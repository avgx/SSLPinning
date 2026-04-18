import Foundation

/// Represent a single certificate.
public struct Certificate: Fingerprint, @unchecked Sendable {
    let cert: SecCertificate
    public init(cert: SecCertificate) {
        self.cert = cert
    }
    
    public var commonName: String? {
        var name: CFString?
        SecCertificateCopyCommonName(cert, &name)
        return name as String?
    }
    
    public var isSelfSigned: Bool? {
        cert.isSelfSigned
    }
    
    public var emailAddresses: [String]? {
        var emails: CFArray?
        SecCertificateCopyEmailAddresses(cert, &emails)
        return emails as? [String]
    }
    
    public var serialNumber: String {
        ((SecCertificateCopySerialNumberData(cert, nil) as Data?) ?? Data()).hex(separator: ":")
    }
    
    public var subjectSummary: String? {
        SecCertificateCopySubjectSummary(cert) as String?
    }
    
    public var data: Data {
        SecCertificateCopyData(cert) as Data
    }
    
    public var sha256: String {
        data.sha256().hex(separator: ":")
    }
    
    public var sha1: String {
        data.sha1().hex(separator: ":")
    }
    
    public var pem: String {
        let lines = cert.data.base64EncodedString().split(by: 64)
        let prefix = "-----BEGIN CERTIFICATE-----"
        let suffix = "-----END CERTIFICATE-----"
        return ([prefix] + lines + [suffix]).joined(separator: "\n")
    }
}
