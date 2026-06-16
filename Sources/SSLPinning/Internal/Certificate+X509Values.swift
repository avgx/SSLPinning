import Foundation
import X509

extension Certificate {
    var validityRange: (notBefore: Date, notAfter: Date) {
        get throws {
            let x509 = try cert.x509Certificate()
            return (x509.notValidBefore, x509.notValidAfter)
        }
    }

    var issuer: String {
        get throws {
            try cert.x509Certificate().issuer.description
        }
    }
}
