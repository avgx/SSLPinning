import Foundation

/// Result of comparing the server chain to the configured pin list for the challenge host (no `SecTrust`).
internal enum PinningDecision: Equatable, Sendable {
    case certificateMatchesPin
    case certificateMismatch(expected: Pin, presentedChain: [CertificateInfo])
    case hostNotInPinList(presentedChain: [CertificateInfo])
}

internal func makePinningDecision(
    pins: [Pin],
    host: String,
    chainContainsPin: (Pin) -> Bool,
    presentedChain: [CertificateInfo]
) -> PinningDecision {
    guard let pin = pins.first(where: { $0.host == host }) else {
        return .hostNotInPinList(presentedChain: presentedChain)
    }
    if chainContainsPin(pin) {
        return .certificateMatchesPin
    }
    return .certificateMismatch(expected: pin, presentedChain: presentedChain)
}
