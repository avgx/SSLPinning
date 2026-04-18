import Foundation
import Security

/// Single certificate from a `SecTrust` chain; module-internal wrapper around `SecCertificate`.
struct Certificate: Fingerprint, @unchecked Sendable {
    let cert: SecCertificate

    init(cert: SecCertificate) {
        self.cert = cert
    }

    var commonName: String? {
        var name: CFString?
        SecCertificateCopyCommonName(cert, &name)
        return name as String?
    }

    var isSelfSigned: Bool? {
        cert.isSelfSigned
    }

    var emailAddresses: [String]? {
        var emails: CFArray?
        SecCertificateCopyEmailAddresses(cert, &emails)
        return emails as? [String]
    }

    var serialNumber: String {
        ((SecCertificateCopySerialNumberData(cert, nil) as Data?) ?? Data()).hex(separator: ":")
    }

    var subjectSummary: String? {
        SecCertificateCopySubjectSummary(cert) as String?
    }

    var data: Data {
        SecCertificateCopyData(cert) as Data
    }

    var sha256: String {
        data.sha256().hex(separator: ":")
    }

    var sha1: String {
        data.sha1().hex(separator: ":")
    }

    var pem: String {
        let lines = cert.data.base64EncodedString().split(by: 64)
        let prefix = "-----BEGIN CERTIFICATE-----"
        let suffix = "-----END CERTIFICATE-----"
        return ([prefix] + lines + [suffix]).joined(separator: "\n")
    }
}
