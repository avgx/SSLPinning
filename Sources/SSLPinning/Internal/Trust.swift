import Foundation
import Security

/// Module-internal view of `SecTrust` for building certificate chains and pin checks.
struct Trust {
    let trust: SecTrust

    init(trust: SecTrust) {
        self.trust = trust
    }

    var certificates: [Certificate] {
        let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate]
        return chain?.map { Certificate(cert: $0) } ?? []
    }

    var isSelfSigned: Bool? {
        certificates.count == 1 && (certificates.first?.isSelfSigned ?? false)
    }

    func contains(_ pin: Fingerprint) -> Bool {
        certificates.contains(where: { $0 == pin })
    }
}
