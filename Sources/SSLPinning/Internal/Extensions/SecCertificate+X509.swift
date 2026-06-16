import Foundation
import Security
import X509

extension SecCertificate {
    func x509Certificate() throws -> X509.Certificate {
        try X509.Certificate(derEncoded: Array(SecCertificateCopyData(self) as Data))
    }
}
