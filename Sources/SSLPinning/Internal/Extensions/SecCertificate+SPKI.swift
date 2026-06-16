import CryptoKit
import Foundation
import Security
import SwiftASN1
import X509

extension SecCertificate {
    func spkiHash(from x509: X509.Certificate? = nil) throws -> Data {
        let certificate = try x509 ?? x509Certificate()
        var serializer = DER.Serializer()
        try serializer.serialize(certificate.publicKey)
        let spkiDER = serializer.serializedBytes
        return Data(SHA256.hash(data: Data(spkiDER)))
    }

    func spkiDER(from x509: X509.Certificate? = nil) throws -> Data {
        let certificate = try x509 ?? x509Certificate()
        var serializer = DER.Serializer()
        try serializer.serialize(certificate.publicKey)
        return Data(serializer.serializedBytes)
    }
}
