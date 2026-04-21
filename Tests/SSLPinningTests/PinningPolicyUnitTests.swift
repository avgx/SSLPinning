import Foundation
import Testing
@testable import SSLPinning

@Suite("Pinning policy")
struct PinningPolicyUnitTests {
    private let sample = CertificateInfo(
        commonName: "leaf",
        subjectSummary: "leaf",
        serialNumber: "01",
        sha256: "AA",
        sha1: "BB",
        isSelfSigned: false
    )

    @Test func noPinForHost_returnsHostNotInPinList() {
        let pins = [Pin(host: "other.example", serialNumber: "1", sha256: "2", sha1: "3")]
        let decision = makePinningDecision(
            pins: pins,
            host: "example.com",
            chainContainsPin: { _ in true },
            presentedChain: [sample]
        )
        #expect(decision == .hostNotInPinList(presentedChain: [sample]))
    }

    @Test func pinForHost_chainMatches_returnsCertificateMatchesPin() {
        let pin = Pin(host: "example.com", serialNumber: "1", sha256: "2", sha1: "3")
        let decision = makePinningDecision(
            pins: [pin],
            host: "example.com",
            chainContainsPin: { _ in true },
            presentedChain: [sample]
        )
        #expect(decision == .certificateMatchesPin)
    }

    @Test func pinForHost_chainDoesNotMatch_returnsCertificateMismatch() {
        let pin = Pin(host: "example.com", serialNumber: "1", sha256: "2", sha1: "3")
        let decision = makePinningDecision(
            pins: [pin],
            host: "example.com",
            chainContainsPin: { _ in false },
            presentedChain: [sample]
        )
        #expect(decision == .certificateMismatch(expected: pin, presentedChain: [sample]))
    }

    @Test func sslPinningError_localizedFieldsAreNonEmpty() {
        let pin = Pin(host: "h", serialNumber: "s", sha256: "256", sha1: "1")
        let cases: [SSLPinningError] = [
            .invalidServerTrust(host: "h"),
            .pinMismatch(host: "h", expected: pin, presentedChain: [sample]),
            .unknownHost(host: "h", presentedChain: [sample]),
            .systemTrustFailed(underlying: URLError(.serverCertificateUntrusted)),
        ]
        for err in cases {
            #expect(err.errorDescription?.isEmpty == false)
            #expect(err.failureReason?.isEmpty == false)
            #expect(err.recoverySuggestion?.isEmpty == false)
        }
    }

    @Test func localization_catalog_russian_pinMismatch_containsFingerprintWording() throws {
        let value = try Self.ruStringUnitValue(
            catalogKey: "sslpinning.pin_mismatch.error_description"
        )
        #expect(value.contains("отпечат"))
        #expect(Self.containsCyrillic(value))
        let formatted = String(format: value, locale: Locale(identifier: "ru"), "api.example.org")
        #expect(Self.containsCyrillic(formatted))
    }

    @Test func localization_catalog_russian_systemTrust_containsTLSWording() throws {
        let value = try Self.ruStringUnitValue(
            catalogKey: "sslpinning.system_trust_failed.error_description"
        )
        #expect(value.isEmpty == false)
        #expect(Self.containsCyrillic(value))
        #expect(value.contains("TLS"))
    }

    /// TODO: `Bundle.localizedString` / `String(localized:)` against raw `Localizable.xcstrings` in `swift test` often returns the key; re-enable when runtime resolution is fixed (e.g. Xcode-compiled catalog or SPM follow-up).
    @Test(.disabled("Runtime xcstrings resolution from bundle in swift test — revisit later"))
    func localization_runtime_russian_pinMismatch_withPreferredLanguagesOverride() throws {
        let defaults = UserDefaults.standard
        let key = "AppleLanguages"
        let previous = defaults.object(forKey: key)
        defaults.set(["ru"], forKey: key)
        defer {
            if let previous {
                defaults.set(previous, forKey: key)
            } else {
                defaults.removeObject(forKey: key)
            }
        }

        let bundle = SSLPinningLocalizationBundle.bundle
        let template = bundle.localizedString(
            forKey: "sslpinning.pin_mismatch.error_description",
            value: nil,
            table: "Localizable"
        )
        #expect(template != "sslpinning.pin_mismatch.error_description")
        let formatted = String(format: template, locale: Locale(identifier: "ru"), "api.example.org")
        #expect(formatted.contains("отпечат"))
        #expect(Self.containsCyrillic(formatted))
    }

    private static func ruStringUnitValue(catalogKey: String) throws -> String {
        let url = try #require(
            SSLPinningLocalizationBundle.bundle.url(forResource: "Localizable", withExtension: "xcstrings"),
            "Localizable.xcstrings missing from SSLPinning resource bundle"
        )
        let data = try Data(contentsOf: url)
        let root = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        let strings = try #require(root["strings"] as? [String: Any])
        let entry = try #require(strings[catalogKey] as? [String: Any])
        let locs = try #require(entry["localizations"] as? [String: Any])
        let ru = try #require(locs["ru"] as? [String: Any])
        let unit = try #require(ru["stringUnit"] as? [String: Any])
        return try #require(unit["value"] as? String)
    }

    private static func containsCyrillic(_ string: String) -> Bool {
        string.unicodeScalars.contains { scalar in
            (0x0400 ... 0x04FF).contains(Int(scalar.value))
        }
    }
}
