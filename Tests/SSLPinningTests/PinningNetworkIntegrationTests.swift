import Foundation
import Testing
@testable import SSLPinning

/// Runs sequentially in one test to avoid parallel `URLSession` races and long default timeouts.
/// Literal-IP to `example.com` (e.g. historic 93.184.216.34) is avoided: CDN edges differ; use a second DNS name on the same leaf instead (`www.example.com`).
@Suite("Network integration", .tags(.network))
struct PinningNetworkIntegrationTests {
    /// example.com leaf as of 2026-06 (rotate when this test fails).
    private static let examplePin = Fingerprint(
        host: "example.com",
        serialNumber: "1aa73fea257be3334b9a29552e6f878e",
        sha256: "beab14cf39678fda0ef1606eedb818c2298ba2cc7a00886e7dc2d2410f24cd35",
        sha1: "e7f60d1afecdffdf164b7479386bbe67cdd8e51e"
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
            #expect(certs?.first?.serialNumber == examplePin.serialNumber)
        }

        // 2) example.com + wrong pin → fingerprintMismatch on delegate
        do {
            let wrong = Fingerprint(host: "example.com", serialNumber: "00", sha256: "00", sha1: "00")
            let (session, delegate) = NetworkSession.makeSession(policy: .pinning([wrong])) {
                Self.configureTimeouts($0)
            }
            defer { session.finishTasksAndInvalidate() }
            let url = URL(string: "https://example.com")!
            await #expect(throws: (any Error).self) {
                _ = try await session.data(from: url)
            }
            #expect({
                guard case .fingerprintMismatch(let host, let expected, _) = delegate.lastPinningError else { return false }
                return host == "example.com" && expected == wrong
            }(), "Expected fingerprintMismatch, got \(String(describing: delegate.lastPinningError))")
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
            let wwwPin = Fingerprint(
                host: "www.example.com",
                serialNumber: examplePin.serialNumber!,
                sha256: examplePin.sha256,
                sha1: examplePin.sha1!
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

    /// Maps a failing `URLSession` TLS error into ``SSLPinningError/systemTrustFailed`` and throws it (for apps that surface one error type).
    @Test func selfSignedBadSSL_throwMappedSystemTrustFailed() async throws {
        await #expect(throws: SSLPinningError.self) {
            try await Self.throwMappedSelfSignedBadSSL()
        }
    }

    /// Performs one request, maps the URL error to ``SSLPinningError``, asserts on ``URLError.Code``, then rethrows for `#expect(throws:)`.
    private static func throwMappedSelfSignedBadSSL() async throws {
        let url = URL(string: "https://self-signed.badssl.com/")!
        let (session, delegate) = NetworkSession.makeSession(policy: .system) {
            Self.configureTimeouts($0)
        }
        defer { session.finishTasksAndInvalidate() }

        let ssl: SSLPinningError
        do {
            _ = try await session.data(from: url)
            Issue.record("Expected TLS failure from self-signed.badssl.com")
            throw URLError(.unknown)
        } catch let probeError {
            guard let mapped = SSLPinningError.systemTrustFailureIfPresent(in: probeError) else {
                Issue.record("Expected an SSL certificate URL error, got \(probeError)")
                throw probeError
            }
            ssl = mapped
        }

        guard case .systemTrustFailed(let urlError) = ssl else {
            Issue.record("Expected systemTrustFailed, got \(ssl)")
            throw ssl
        }

        let acceptableCodes: [URLError.Code] = [
            .serverCertificateUntrusted,
            .secureConnectionFailed,
            .serverCertificateHasUnknownRoot
        ]
        #expect(acceptableCodes.contains(urlError.code))

        #expect((ssl.errorDescription ?? "").isEmpty == false)
        #expect((ssl.failureReason ?? "").isEmpty == false)
        #expect((ssl.recoverySuggestion ?? "").isEmpty == false)
        #expect(ssl.failureReason?.contains(urlError.localizedDescription) == true)

        #expect(!delegate.evaluator.certificateChainsByHost.isEmpty)
        #expect(!delegate.evaluator.trustStatusByHost.isEmpty)

        throw ssl
    }

    /// Cloudflare DNS resolver HTTPS by literal IPv4; exercises `CertificateInfo` validity from X509 parsing.
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
        #expect(status.map { (200 ... 399).contains($0) } == true)
        #expect(data.count >= 0)
        #expect(
            delegate.evaluator.certificateChainsByHost[literal]?.first != nil,
            "Expected certificate chain for \(literal)"
        )
        guard let leaf = delegate.evaluator.certificateChainsByHost[literal]?.first else { return }

        let validity = leaf.validityRange
        #expect(validity.notBefore < Date() && validity.notAfter > Date())

        let pinName = Fingerprint(host: literal, certificate: leaf)
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
