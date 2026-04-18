import Foundation

extension SecCertificate {
    var isSelfSigned: Bool? {
        guard
            let subject = SecCertificateCopyNormalizedSubjectSequence(self),
            let issuer = SecCertificateCopyNormalizedIssuerSequence(self)
        else {
            return nil
        }
        return subject == issuer
    }

    var data: Data {
        SecCertificateCopyData(self) as Data
    }
}
