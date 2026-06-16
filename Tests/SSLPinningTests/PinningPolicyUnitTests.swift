import Foundation
import Testing
@testable import SSLPinning

@Suite("Pinning policy")
struct PinningPolicyUnitTests {
    private let sample = CertificateInfo(
        commonName: "leaf",
        subjectName: "CN=leaf",
        issuer: "CN=Test",
        serialNumber: "01",
        sha256: "aa",
        sha1: "bb",
        spki: "cc",
        isSelfSigned: false,
        validityRange: CertificateValidityRange(
            notBefore: Date(timeIntervalSince1970: 0),
            notAfter: Date(timeIntervalSince1970: 1_000_000_000)
        )
    )

    @Test func noPinForHost_returnsHostNotInPinList() {
        let pins = [Fingerprint(host: "other.example", serialNumber: "1", sha256: "2", sha1: "3")]
        let decision = makePinningDecision(
            pins: pins,
            challengeHost: "example.com",
            chainMatches: { _ in true },
            presentedChain: [sample]
        )
        #expect(decision == .hostNotInPinList(presentedChain: [sample]))
    }

    @Test func pinForHost_chainMatches_returnsMatch() {
        let pin = Fingerprint(host: "example.com", serialNumber: "1", sha256: "2", sha1: "3")
        let decision = makePinningDecision(
            pins: [pin],
            challengeHost: "example.com",
            chainMatches: { _ in true },
            presentedChain: [sample]
        )
        #expect(decision == .match)
    }

    @Test func pinForHost_chainDoesNotMatch_returnsMismatch() {
        let pin = Fingerprint(host: "example.com", serialNumber: "1", sha256: "2", sha1: "3")
        let decision = makePinningDecision(
            pins: [pin],
            challengeHost: "example.com",
            chainMatches: { _ in false },
            presentedChain: [sample]
        )
        #expect(decision == .mismatch(expected: pin, presentedChain: [sample]))
    }

    @Test func hostMatchIsCaseInsensitive() {
        let pin = Fingerprint(host: "Example.COM", serialNumber: "1", sha256: "2", sha1: "3")
        let decision = makePinningDecision(
            pins: [pin],
            challengeHost: "example.com",
            chainMatches: { _ in true },
            presentedChain: [sample]
        )
        #expect(decision == .match)
    }

    @Test func multiplePinsForSameHost_anyMatchSucceeds() {
        let pin1 = Fingerprint(host: "example.com", serialNumber: "1", sha256: "2", sha1: "3")
        let pin2 = Fingerprint(host: "example.com", serialNumber: "9", sha256: "8", sha1: "7")
        let decision = makePinningDecision(
            pins: [pin1, pin2],
            challengeHost: "example.com",
            chainMatches: { $0 == pin2 },
            presentedChain: [sample]
        )
        #expect(decision == .match)
    }

    @Test func sslPinningError_localizedFieldsAreNonEmpty() {
        let pin = Fingerprint(host: "h", serialNumber: "s", sha256: "256", sha1: "1")
        let cases: [SSLPinningError] = [
            .invalidServerTrust(host: "h"),
            .fingerprintMismatch(host: "h", expected: pin, presentedChain: [sample]),
            .unknownHost(host: "h", presentedChain: [sample]),
            .systemTrustFailed(underlying: URLError(.serverCertificateUntrusted)),
        ]
        for err in cases {
            #expect(err.errorDescription?.isEmpty == false)
            #expect(err.failureReason?.isEmpty == false)
            #expect(err.recoverySuggestion?.isEmpty == false)
        }
    }    
}
