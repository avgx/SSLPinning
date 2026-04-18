import Foundation
import Security

/// Evaluates server-trust authentication challenges and records certificate chains per host (for inspection / pinning).
public final class ServerTrustEvaluator: @unchecked Sendable {
    private let policy: ServerTrustPolicy

    /// Host → certificate chain from the last server-trust challenge for that host (sendable snapshots for UI).
    public private(set) var certificateChainsByHost: [String: [CertificateInfo]] = [:]

    public init(policy: ServerTrustPolicy) {
        self.policy = policy
    }

    public func evaluate(_ challenge: URLAuthenticationChallenge) -> TrustChallengeResult {
        let protectionSpace = challenge.protectionSpace
        let method = protectionSpace.authenticationMethod
        let host = protectionSpace.host
        // Let URLSession handle non–server-trust challenges (e.g. default); do not cancel the connection.
        guard method == NSURLAuthenticationMethodServerTrust else {
            return TrustChallengeResult(disposition: .performDefaultHandling, credential: nil)
        }
        guard let serverTrust = protectionSpace.serverTrust else {
            return TrustChallengeResult(
                disposition: .cancelAuthenticationChallenge,
                credential: nil,
                pinningError: .invalidServerTrust(host: host)
            )
        }

        let trust = Trust(trust: serverTrust)
        let certificates = trust.certificates
        guard !certificates.isEmpty else {
            return TrustChallengeResult(
                disposition: .cancelAuthenticationChallenge,
                credential: nil,
                pinningError: .invalidServerTrust(host: host)
            )
        }

        let presented = certificates.map(CertificateInfo.init(certificate:))
        certificateChainsByHost[host] = presented

        switch policy {
        case .system:
            return TrustChallengeResult(disposition: .performDefaultHandling, credential: nil)
        case .trustEveryone:
            return TrustChallengeResult(disposition: .useCredential, credential: URLCredential(trust: serverTrust))
        case .pinning(let pins):
            switch makePinningDecision(
                pins: pins,
                host: host,
                chainContainsPin: { trust.contains($0) },
                presentedChain: presented
            ) {
            case .certificateMatchesPin:
                return TrustChallengeResult(disposition: .useCredential, credential: URLCredential(trust: serverTrust))
            case .certificateMismatch(let pin, let chain):
                return TrustChallengeResult(
                    disposition: .cancelAuthenticationChallenge,
                    credential: nil,
                    pinningError: .pinMismatch(host: host, expected: pin, presentedChain: chain)
                )
            case .hostNotInPinList(let chain):
                return TrustChallengeResult(
                    disposition: .cancelAuthenticationChallenge,
                    credential: nil,
                    pinningError: .unknownHost(host: host, presentedChain: chain)
                )
            }
        }
    }
}
