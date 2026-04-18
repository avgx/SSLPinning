import Foundation

/// Fingerprint fields used to match a live certificate against a configured `Pin`.
public protocol Fingerprint {
    var serialNumber: String { get }
    var sha256: String { get }
    var sha1: String { get }
}

public func == (lhs: any Fingerprint, rhs: any Fingerprint) -> Bool {
    lhs.serialNumber == rhs.serialNumber
        && lhs.sha256 == rhs.sha256
        && lhs.sha1 == rhs.sha1
}

/// Sendable snapshot of a server certificate for UI and errors (no `SecCertificate` reference).
public struct CertificateInfo: Sendable, Equatable, Hashable, Fingerprint {
    public let commonName: String?
    public let subjectSummary: String?
    public let serialNumber: String
    public let sha256: String
    public let sha1: String
    public let isSelfSigned: Bool?
    public let notValidBefore: Date?
    public let notValidAfter: Date?
    /// Distinguished-name style issuer string when the platform provides it.
    public let issuer: String?
    /// DNS names and IP literals from the Subject Alternative Name extension (may be empty).
    public let subjectAlternativeNames: [String]

    public init(
        commonName: String?,
        subjectSummary: String?,
        serialNumber: String,
        sha256: String,
        sha1: String,
        isSelfSigned: Bool? = nil,
        notValidBefore: Date? = nil,
        notValidAfter: Date? = nil,
        issuer: String? = nil,
        subjectAlternativeNames: [String] = []
    ) {
        self.commonName = commonName
        self.subjectSummary = subjectSummary
        self.serialNumber = serialNumber
        self.sha256 = sha256
        self.sha1 = sha1
        self.isSelfSigned = isSelfSigned
        self.notValidBefore = notValidBefore
        self.notValidAfter = notValidAfter
        self.issuer = issuer
        self.subjectAlternativeNames = subjectAlternativeNames
    }

    init(certificate: Certificate) {
        let validity = certificate.validityRange
        self.init(
            commonName: certificate.commonName,
            subjectSummary: certificate.subjectSummary,
            serialNumber: certificate.serialNumber,
            sha256: certificate.sha256,
            sha1: certificate.sha1,
            isSelfSigned: certificate.isSelfSigned,
            notValidBefore: validity.notBefore,
            notValidAfter: validity.notAfter,
            issuer: certificate.issuer,
            subjectAlternativeNames: certificate.subjectAlternativeNames
        )
    }
}
