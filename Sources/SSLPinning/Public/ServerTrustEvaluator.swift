import Foundation
import Security

/// Evaluates server-trust authentication challenges and records certificate chains per host (for inspection / pinning).
public final class ServerTrustEvaluator: @unchecked Sendable {
    private let policy: ServerTrustPolicy

    /// Host → certificate chain from the last server-trust challenge for that host (sendable snapshots for UI).
    public private(set) var certificateChainsByHost: [String: [CertificateInfo]] = [:]
    /// Host → trust status
    public private(set) var trustStatusByHost: [String: SystemTrustStatus] = [:]

    public init(policy: ServerTrustPolicy) {
        self.policy = policy
    }

    public func evaluate(_ challenge: URLAuthenticationChallenge) -> TrustChallengeResult {
        let protectionSpace = challenge.protectionSpace
        let method = protectionSpace.authenticationMethod
        let host = protectionSpace.host
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

        trustStatusByHost[host] = trust.evaluateSystemTrust()

        switch policy {
        case .system:
            certificateChainsByHost[host] = snapshotCertificates(certificates)
            return TrustChallengeResult(disposition: .performDefaultHandling, credential: nil)
        case .trustEveryone:
            certificateChainsByHost[host] = snapshotCertificates(certificates)
            return TrustChallengeResult(disposition: .useCredential, credential: URLCredential(trust: serverTrust))
        case .pinning(let pins):
            let presented: [CertificateInfo]
            do {
                presented = try snapshotCertificatesStrict(certificates)
            } catch {
                return TrustChallengeResult(
                    disposition: .cancelAuthenticationChallenge,
                    credential: nil,
                    pinningError: .invalidServerTrust(host: host)
                )
            }
            certificateChainsByHost[host] = presented
            return evaluatePinning(
                pins: pins,
                requireSPKIOnly: false,
                host: host,
                trust: trust,
                serverTrust: serverTrust,
                presented: presented
            )
        case .pinningSpki(let pins):
            let presented: [CertificateInfo]
            do {
                presented = try snapshotCertificatesStrict(certificates)
            } catch {
                return TrustChallengeResult(
                    disposition: .cancelAuthenticationChallenge,
                    credential: nil,
                    pinningError: .invalidServerTrust(host: host)
                )
            }
            certificateChainsByHost[host] = presented
            return evaluatePinning(
                pins: pins,
                requireSPKIOnly: true,
                host: host,
                trust: trust,
                serverTrust: serverTrust,
                presented: presented
            )
        }
    }

    private func snapshotCertificates(_ certificates: [Certificate]) -> [CertificateInfo] {
        certificates.compactMap { try? CertificateInfo(certificate: $0) }
    }

    private func snapshotCertificatesStrict(_ certificates: [Certificate]) throws -> [CertificateInfo] {
        try certificates.map { try CertificateInfo(certificate: $0) }
    }

    private func evaluatePinning(
        pins: [Fingerprint],
        requireSPKIOnly: Bool,
        host: String,
        trust: Trust,
        serverTrust: SecTrust,
        presented: [CertificateInfo]
    ) -> TrustChallengeResult {
        let applicablePins = pins.filter { requireSPKIOnly ? $0.isSPKIOnly : !$0.isSPKIOnly }
        switch makePinningDecision(
            pins: applicablePins,
            challengeHost: host,
            chainMatches: { trust.contains(expected: $0) },
            presentedChain: presented
        ) {
        case .match:
            return TrustChallengeResult(
                disposition: .useCredential,
                credential: URLCredential(trust: serverTrust)
            )
        case .mismatch(let expected, let chain):
            return TrustChallengeResult(
                disposition: .cancelAuthenticationChallenge,
                credential: nil,
                pinningError: .fingerprintMismatch(host: host, expected: expected, presentedChain: chain)
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
