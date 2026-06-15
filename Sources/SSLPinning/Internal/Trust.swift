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
    
    func evaluateSystemTrust() -> SystemTrustStatus {
        var error: CFError?

        let trusted = SecTrustEvaluateWithError(trust, &error)

        let evaluatedChain = (SecTrustCopyCertificateChain(trust) as? [SecCertificate]) ?? []

        let root = evaluatedChain.last.map {
            CertificateInfo(certificate: Certificate(cert: $0))
        }

        let leaf = evaluatedChain.first.map {
            CertificateInfo(certificate: Certificate(cert: $0))
        }

        return SystemTrustStatus(
            isTrusted: trusted,
            errorDescription: error?.localizedDescription,
            leaf: leaf,
            root: root
        )
    }
}
