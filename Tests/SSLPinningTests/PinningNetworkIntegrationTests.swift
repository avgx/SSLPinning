import Foundation
import Testing
@testable import SSLPinning

/// Runs sequentially in one test to avoid parallel `URLSession` races and long default timeouts.
/// Literal-IP to `example.com` (e.g. historic 93.184.216.34) is avoided: CDN edges differ; use a second DNS name on the same leaf instead (`www.example.com`).
@Suite("Network integration", .tags(.network))
struct PinningNetworkIntegrationTests {
    /// example.com leaf as of 2026-04 (rotate when this test fails).
    private static let examplePin = Pin(
        host: "example.com",
        serialNumber: "65:20:58:9E:F1:7E:B5:5C:66:44:33:F2:9F:2E:68:4A",
        sha256: "1A:F6:27:C6:C2:AC:99:2E:3C:91:02:43:8F:46:7C:4C:23:8D:31:12:32:5A:C7:CF:90:03:D7:7F:75:EF:FF:BA",
        sha1: "AE:0E:78:A8:E1:DA:BE:74:93:2D:D8:81:2D:EE:A5:EE:E7:CF:A6:E7"
    )

    private static func configureTimeouts(_ configuration: URLSessionConfiguration, request: TimeInterval = 30) {
        configuration.timeoutIntervalForRequest = request
        configuration.timeoutIntervalForResource = request + 15
    }

    @Test func legacyScenariosInOrder() async throws {
        let examplePin = Self.examplePin

        // 1) example.com + matching pin → body and serial
        do {
            let (session, delegate) = NetworkSession.makeSession(policy: .pinning([examplePin])) {
                Self.configureTimeouts($0)
            }
            defer { session.finishTasksAndInvalidate() }
            let url = URL(string: "https://example.com")!
            let (data, _) = try await session.data(from: url)
            #expect(data.count > 0)
            #expect(delegate.lastPinningError == nil)
            let certs = delegate.evaluator.certificateChainsByHost["example.com"]
            if let certs {
                print("\(certs)")
            }
            #expect(certs?.first?.serialNumber == examplePin.serialNumber)
        }

        // 2) example.com + wrong pin → pinMismatch on delegate
        do {
            let wrong = Pin(host: "example.com", serialNumber: "00", sha256: "00", sha1: "00")
            let (session, delegate) = NetworkSession.makeSession(policy: .pinning([wrong])) {
                Self.configureTimeouts($0)
            }
            defer { session.finishTasksAndInvalidate() }
            let url = URL(string: "https://example.com")!
            await #expect(throws: (any Error).self) {
                _ = try await session.data(from: url)
            }
            #expect({
                guard case .pinMismatch(let host, let expected, _) = delegate.lastPinningError else { return false }
                return host == "example.com" && expected == wrong
            }(), "Expected pinMismatch, got \(String(describing: delegate.lastPinningError))")
        }

        // 3) example.com + pinning([]) → unknownHost with non-empty chain
        do {
            let (session, delegate) = NetworkSession.makeSession(policy: .pinning([])) {
                Self.configureTimeouts($0)
            }
            defer { session.finishTasksAndInvalidate() }
            let url = URL(string: "https://example.com")!
            await #expect(throws: (any Error).self) {
                _ = try await session.data(from: url)
            }
            #expect({
                guard case .unknownHost(let host, let chain) = delegate.lastPinningError else { return false }
                return host == "example.com" && chain.isEmpty == false
            }(), "Expected unknownHost, got \(String(describing: delegate.lastPinningError))")
        }

        // 4) Same leaf, second public name: `www.example.com` typically shares the example.com certificate (SAN).
        do {
            let wwwPin = Pin(
                host: "www.example.com",
                serialNumber: examplePin.serialNumber,
                sha256: examplePin.sha256,
                sha1: examplePin.sha1
            )
            let (session, delegate) = NetworkSession.makeSession(policy: .pinning([examplePin, wwwPin])) {
                Self.configureTimeouts($0)
            }
            defer { session.finishTasksAndInvalidate() }
            let url = URL(string: "https://www.example.com/")!
            let (data, _) = try await session.data(from: url)
            #expect(data.count > 0)
            #expect(delegate.lastPinningError == nil)
            #expect(delegate.evaluator.certificateChainsByHost["www.example.com"]?.first?.serialNumber == examplePin.serialNumber)
        }

        // 5) self-signed.badssl.com + system → TLS error; chain in cache when trust evaluated
        do {
            let url = URL(string: "https://self-signed.badssl.com/")!
            let (session, delegate) = NetworkSession.makeSession(policy: .system) {
                Self.configureTimeouts($0)
            }
            defer { session.finishTasksAndInvalidate() }
            await #expect(throws: (any Error).self) {
                _ = try await session.data(from: url)
            }
            if let certs = delegate.evaluator.certificateChainsByHost["self-signed.badssl.com"] {
                #expect(certs.count == 1)
                #expect(certs.first?.isSelfSigned == true)
                #expect(certs.first?.commonName == "*.badssl.com")
            }
        }
    }

    /// Cloudflare DNS resolver HTTPS by literal IPv4; exercises `CertificateInfo` validity on supported OS versions.
    @Test func cloudflareOneDotOneDotOneByIP() async throws {
        let literal = "1.1.1.1"
        let (session, delegate) = NetworkSession.makeSession(policy: .trustEveryone, suppressHttpRedirects: true) {
            $0.timeoutIntervalForRequest = 20
            $0.timeoutIntervalForResource = 30
        }
        defer { session.finishTasksAndInvalidate() }
        let url = URL(string: "https://\(literal)/")!
        let (data, response) = try await session.data(from: url)
        let status = (response as? HTTPURLResponse)?.statusCode
        // Redirects are suppressed so the body may be empty; TLS and certificate extraction still succeed.
        #expect(status.map { (200 ... 399).contains($0) } == true)
        #expect(data.count >= 0)
        #expect(
            delegate.evaluator.certificateChainsByHost[literal]?.first != nil,
            "Expected certificate chain for \(literal)"
        )
        guard let leaf = delegate.evaluator.certificateChainsByHost[literal]?.first else { return }

        #if os(macOS) && !targetEnvironment(macCatalyst)
        #expect(leaf.notValidBefore != nil)
        #expect(leaf.notValidAfter != nil)
        if let start = leaf.notValidBefore, let end = leaf.notValidAfter {
            #expect(start < Date() && end > Date())
        }
        #else
        if #available(iOS 18.0, tvOS 18.0, watchOS 11.0, macCatalyst 18.0, visionOS 2.0, *) {
            #expect(leaf.notValidBefore != nil, "Validity requires iOS 18+ (and aligned) Security APIs on embedded platforms")
            #expect(leaf.notValidAfter != nil)
            if let start = leaf.notValidBefore, let end = leaf.notValidAfter {
                #expect(start < Date() && end > Date())
            }
        }
        #endif

        let pinName = Pin(host: literal, serialNumber: leaf.serialNumber, sha256: leaf.sha256, sha1: leaf.sha1)
        let (pinSession, pinDelegate) = NetworkSession.makeSession(policy: .pinning([pinName]), suppressHttpRedirects: true) {
            $0.timeoutIntervalForRequest = 20
            $0.timeoutIntervalForResource = 30
        }
        defer { pinSession.finishTasksAndInvalidate() }
        let (pinData, pinResponse) = try await pinSession.data(from: url)
        #expect(pinDelegate.lastPinningError == nil)
        let pinStatus = (pinResponse as? HTTPURLResponse)?.statusCode
        #expect(pinStatus.map { (200 ... 399).contains($0) } == true)
        #expect(pinData.count >= 0)
    }
}
