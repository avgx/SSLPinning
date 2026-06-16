import Foundation

/// Result of comparing the server chain to the configured pin list for the challenge host (no `SecTrust`).
internal enum PinningDecision: Equatable, Sendable {
    case match
    case mismatch(expected: Fingerprint, presentedChain: [CertificateInfo])
    case hostNotInPinList(presentedChain: [CertificateInfo])
}

internal func makePinningDecision(
    pins: [Fingerprint],
    challengeHost: String,
    chainMatches: (Fingerprint) -> Bool,
    presentedChain: [CertificateInfo]
) -> PinningDecision {
    let hostPins = pins.filter {
        $0.host.caseInsensitiveCompare(challengeHost) == .orderedSame
    }

    guard let firstPin = hostPins.first else {
        return .hostNotInPinList(presentedChain: presentedChain)
    }

    if hostPins.contains(where: chainMatches) {
        return .match
    }

    return .mismatch(expected: firstPin, presentedChain: presentedChain)
}
