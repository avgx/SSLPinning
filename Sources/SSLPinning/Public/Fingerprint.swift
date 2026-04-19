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
public struct CertificateInfo: Sendable, Equatable, Hashable, Fingerprint, CustomStringConvertible {
    public let commonName: String?
    public let subjectSummary: String?
    public let serialNumber: String
    public let sha256: String
    public let sha1: String
    public let isSelfSigned: Bool?
    public let notValidBefore: Date?
    public let notValidAfter: Date?

    public init(
        commonName: String?,
        subjectSummary: String?,
        serialNumber: String,
        sha256: String,
        sha1: String,
        isSelfSigned: Bool? = nil,
        notValidBefore: Date? = nil,
        notValidAfter: Date? = nil
    ) {
        self.commonName = commonName
        self.subjectSummary = subjectSummary
        self.serialNumber = serialNumber
        self.sha256 = sha256
        self.sha1 = sha1
        self.isSelfSigned = isSelfSigned
        self.notValidBefore = notValidBefore
        self.notValidAfter = notValidAfter
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
            notValidAfter: validity.notAfter
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

        func yamlStringOrNull(_ s: String?) -> String {
            guard let s else { return "null" }
            return yamlDoubleQuoted(s)
        }

        func yamlDateOrNull(_ d: Date?) -> String {
            guard let d else { return "null" }
            return yamlDoubleQuoted(iso.string(from: d))
        }

        func yamlBoolOrNull(_ b: Bool?) -> String {
            guard let b else { return "null" }
            return b ? "true" : "false"
        }

        var lines: [String] = []
        lines.append("commonName: \(yamlStringOrNull(commonName))")
        lines.append("subjectSummary: \(yamlStringOrNull(subjectSummary))")
        lines.append("serialNumber: \(yamlDoubleQuoted(serialNumber))")
        lines.append("sha256: \(yamlDoubleQuoted(sha256))")
        lines.append("sha1: \(yamlDoubleQuoted(sha1))")
        lines.append("isSelfSigned: \(yamlBoolOrNull(isSelfSigned))")
        lines.append("notValidBefore: \(yamlDateOrNull(notValidBefore))")
        lines.append("notValidAfter: \(yamlDateOrNull(notValidAfter))")
        return lines.joined(separator: "\n")
    }
}
