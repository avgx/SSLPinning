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

    func contains(expected: Fingerprint) -> Bool {
        certificates.contains { certificate in
            if expected.isSPKIOnly {
                guard let hash = try? certificate.spki else { return false }
                return hash == expected.sha256
            }
            guard let serial = expected.serialNumber, let sha1 = expected.sha1 else { return false }
            return certificate.serialNumber == serial
                && certificate.sha256 == expected.sha256
                && certificate.sha1 == sha1
        }
    }

    func evaluateSystemTrust() -> SystemTrustStatus {
        var error: CFError?

        let trusted = SecTrustEvaluateWithError(trust, &error)

        let evaluatedChain = (SecTrustCopyCertificateChain(trust) as? [SecCertificate]) ?? []

        let root = evaluatedChain.last.flatMap { cert in
            try? CertificateInfo(certificate: Certificate(cert: cert))
        }

        let leaf = evaluatedChain.first.flatMap { cert in
            try? CertificateInfo(certificate: Certificate(cert: cert))
        }

        return SystemTrustStatus(
            isTrusted: trusted,
            errorDescription: error?.localizedDescription,
            leaf: leaf,
            root: root
        )
    }
}
