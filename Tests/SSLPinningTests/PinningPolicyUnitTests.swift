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

    @Test func sslPinningError_descriptionsAreNonEmpty() {
        let pin = Pin(host: "h", serialNumber: "s", sha256: "256", sha1: "1")
        let cases: [SSLPinningError] = [
            .invalidServerTrust(host: "h"),
            .pinMismatch(host: "h", expected: pin, presentedChain: [sample]),
            .unknownHost(host: "h", presentedChain: [sample]),
        ]
        for err in cases {
            #expect(err.errorDescription?.isEmpty == false)
        }
    }
}
