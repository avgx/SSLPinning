import Foundation

/// Configured pin persisted in policy or user defaults.
///
/// Certificate pinning: set ``serialNumber`` and ``sha1``. SPKI pinning: leave them `nil` and use ``init(host:spkiSHA256:)``.
public struct Fingerprint: Codable, Equatable, Sendable {
    /// Challenge hostname this pin applies to (matched case-insensitively).
    public let host: String
    /// SHA-256 digest as lowercase hexadecimal (64 characters, no separators; not Base64).
    ///
    /// Certificate mode: hash of the certificate DER. SPKI mode: hash of the SubjectPublicKeyInfo DER.
    public let sha256: String
    /// Serial number as lowercase hexadecimal (no separators), or `nil` for SPKI-only pins.
    public let serialNumber: String?
    /// SHA-1 digest as lowercase hexadecimal (40 characters, no separators; not Base64), or `nil` for SPKI-only pins.
    public let sha1: String?

    /// `true` when this pin matches by SPKI hash only (``serialNumber`` and ``sha1`` are `nil`).
    public var isSPKIOnly: Bool { serialNumber == nil && sha1 == nil }

    /// Creates a certificate fingerprint pin (full certificate DER hashes).
    public init(host: String, serialNumber: String, sha256: String, sha1: String) {
        self.host = host
        self.sha256 = sha256
        self.serialNumber = serialNumber
        self.sha1 = sha1
    }

    /// Creates an SPKI pin (`sha256` is the SHA-256 hash of the SubjectPublicKeyInfo DER).
    public init(host: String, spkiSHA256: String) {
        self.host = host
        self.sha256 = spkiSHA256
        self.serialNumber = nil
        self.sha1 = nil
    }

    /// Builds a certificate pin from a live ``CertificateInfo`` snapshot.
    public init(host: String, certificate: CertificateInfo) {
        self.init(
            host: host,
            serialNumber: certificate.serialNumber,
            sha256: certificate.sha256,
            sha1: certificate.sha1
        )
    }

    /// Builds an SPKI pin from a live ``CertificateInfo`` snapshot.
    public init(host: String, spkiFrom certificate: CertificateInfo) {
        self.init(host: host, spkiSHA256: certificate.spki)
    }
}

/// Not-before / not-after validity window parsed from the certificate.
public struct CertificateValidityRange: Sendable, Equatable, Hashable {
    /// Start of validity (inclusive).
    public let notBefore: Date
    /// End of validity (exclusive per RFC 5280).
    public let notAfter: Date

    public init(notBefore: Date, notAfter: Date) {
        self.notBefore = notBefore
        self.notAfter = notAfter
    }
}

/// Sendable snapshot of a server certificate for UI and errors (no `SecCertificate` reference).
public struct CertificateInfo: Sendable, Equatable, Hashable, CustomStringConvertible {
    /// Common name from `SecCertificateCopyCommonName`; empty when absent.
    public let commonName: String
    /// Subject distinguished name string from the certificate.
    public let subjectName: String
    /// Issuer distinguished name string from the certificate.
    public let issuer: String
    /// Serial number as lowercase hexadecimal (no separators).
    public let serialNumber: String
    /// SHA-256 of certificate DER: lowercase hexadecimal, 64 characters, no separators (not Base64).
    public let sha256: String
    /// SHA-1 of certificate DER: lowercase hexadecimal, 40 characters, no separators (not Base64).
    public let sha1: String
    /// SHA-256 of SubjectPublicKeyInfo DER: lowercase hexadecimal, 64 characters, no separators (not Base64).
    public let spki: String
    public let isSelfSigned: Bool?
    /// Parsed validity window from the certificate.
    public let validityRange: CertificateValidityRange
    /// PEM-encoded certificate (Base64 body between BEGIN/END lines; not a hash).
    public let pem: String?

    public init(
        commonName: String,
        subjectName: String,
        issuer: String,
        serialNumber: String,
        sha256: String,
        sha1: String,
        spki: String,
        isSelfSigned: Bool? = nil,
        validityRange: CertificateValidityRange,
        pem: String? = nil
    ) {
        self.commonName = commonName
        self.subjectName = subjectName
        self.issuer = issuer
        self.serialNumber = serialNumber
        self.sha256 = sha256
        self.sha1 = sha1
        self.spki = spki
        self.isSelfSigned = isSelfSigned
        self.validityRange = validityRange
        self.pem = pem
    }

    init(certificate: Certificate) throws {
        let x509 = try certificate.cert.x509Certificate()
        let validity = try certificate.validityRange
        self.init(
            commonName: certificate.commonName ?? "",
            subjectName: x509.subject.description,
            issuer: x509.issuer.description,
            serialNumber: certificate.serialNumber,
            sha256: certificate.sha256,
            sha1: certificate.sha1,
            spki: try certificate.spki,
            isSelfSigned: certificate.isSelfSigned,
            validityRange: CertificateValidityRange(
                notBefore: validity.notBefore,
                notAfter: validity.notAfter
            ),
            pem: certificate.pem
        )
    }

    /// Multi-line, YAML-shaped text safe to paste into logs, monospace UI, or a YAML viewer.
    public var description: String {
        let iso = ISO8601DateFormatter()
        iso.formatOptions = [.withInternetDateTime, .withFractionalSeconds]

        func escapeForYamlDoubleQuoted(_ s: String) -> String {
            s.replacingOccurrences(of: "\\", with: "\\\\")
                .replacingOccurrences(of: "\"", with: "\\\"")
        }

        func yamlDoubleQuoted(_ s: String) -> String {
            "\"\(escapeForYamlDoubleQuoted(s))\""
        }

        func yamlBoolOrNull(_ b: Bool?) -> String {
            guard let b else { return "null" }
            return b ? "true" : "false"
        }

        var lines: [String] = []
        lines.append("commonName: \(yamlDoubleQuoted(commonName))")
        lines.append("subjectName: \(yamlDoubleQuoted(subjectName))")
        lines.append("issuer: \(yamlDoubleQuoted(issuer))")
        lines.append("serialNumber: \(yamlDoubleQuoted(serialNumber))")
        lines.append("sha256: \(yamlDoubleQuoted(sha256))")
        lines.append("sha1: \(yamlDoubleQuoted(sha1))")
        lines.append("spki: \(yamlDoubleQuoted(spki))")
        lines.append("isSelfSigned: \(yamlBoolOrNull(isSelfSigned))")
        lines.append("validityRange:")
        lines.append("  notBefore: \(yamlDoubleQuoted(iso.string(from: validityRange.notBefore)))")
        lines.append("  notAfter: \(yamlDoubleQuoted(iso.string(from: validityRange.notAfter)))")
        return lines.joined(separator: "\n")
    }
}
