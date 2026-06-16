import CryptoKit
import Foundation
import Security
import SwiftASN1
import X509

extension SecCertificate {
    func spkiHash(from x509: X509.Certificate? = nil) throws -> Data {
        Data(SHA256.hash(data: try spkiDER(from: x509)))
    }

    func spkiDER(from x509: X509.Certificate? = nil) throws -> Data {
        let certificate = try x509 ?? x509Certificate()
        var serializer = DER.Serializer()
        try serializer.serialize(certificate.publicKey)
        return Data(serializer.serializedBytes)
    }
}
