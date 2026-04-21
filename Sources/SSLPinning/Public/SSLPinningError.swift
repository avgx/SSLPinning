import Foundation

public enum SSLPinningError: Error, Sendable, Equatable {
    /// Server trust challenge was malformed or empty.
    case invalidServerTrust(host: String)
    /// A pin exists for this host but the chain does not match it.
    case pinMismatch(host: String, expected: Pin, presentedChain: [CertificateInfo])
    /// Pinning is enabled but there is no pin for this host; UI may add one and retry.
    case unknownHost(host: String, presentedChain: [CertificateInfo])
    /// System `URLSession` / TLS stack rejected the connection (certificate or handshake).
    case systemTrustFailed(underlying: URLError)
}

extension SSLPinningError {
    /// If `error` is a URL-session TLS/certificate failure, wraps it as ``systemTrustFailed``; otherwise `nil`.
    public static func systemTrustFailureIfPresent(in error: Error) -> SSLPinningError? {
        guard error.isSSLCertificateURLError else { return nil }
        return .systemTrustFailed(underlying: URLError(_nsError: error as NSError))
    }
}

extension SSLPinningError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .invalidServerTrust(let host):
            SSLPinningL10n.format("invalid_server_trust.error_description", host)
        case .pinMismatch(let host, _, _):
            SSLPinningL10n.format("pin_mismatch.error_description", host)
        case .unknownHost(let host, _):
            SSLPinningL10n.format("unknown_host.error_description", host)
        case .systemTrustFailed:
            SSLPinningL10n.str("system_trust_failed.error_description")
        }
    }

    public var failureReason: String? {
        switch self {
        case .invalidServerTrust:
            return SSLPinningL10n.str("invalid_server_trust.failure_reason")
        case .pinMismatch(_, let expected, let chain):
            let presented = chain.first?.sha256 ?? "?"
            return SSLPinningL10n.format(
                "pin_mismatch.failure_reason",
                expected.serialNumber,
                expected.sha256,
                presented
            )
        case .unknownHost(_, let chain):
            let fp = chain.first?.sha256 ?? "?"
            return SSLPinningL10n.format("unknown_host.failure_reason", fp)
        case .systemTrustFailed(let underlying):
            let codeLabel = SSLPinningL10n.urlErrorSummary(for: underlying.code)
            let header = SSLPinningL10n.format("system_trust_failed.failure_reason_header", codeLabel)
            return "\(header)\n\n\(underlying.localizedDescription)"
        }
    }

    public var recoverySuggestion: String? {
        switch self {
        case .invalidServerTrust:
            SSLPinningL10n.str("invalid_server_trust.recovery_suggestion")
        case .pinMismatch:
            SSLPinningL10n.str("pin_mismatch.recovery_suggestion")
        case .unknownHost:
            SSLPinningL10n.str("unknown_host.recovery_suggestion")
        case .systemTrustFailed:
            SSLPinningL10n.str("system_trust_failed.recovery_suggestion")
        }
    }
}

// MARK: - URL error classification (moved from URLSessionCertificateTrustFailure)

extension NSError {
    /// `NSURLError` codes commonly associated with TLS or server certificate problems.
    public static var sslCertificateURLErrorCodes: [Int] {
        [
            NSURLErrorSecureConnectionFailed,
            NSURLErrorServerCertificateUntrusted,
            NSURLErrorServerCertificateHasBadDate,
            NSURLErrorServerCertificateNotYetValid,
            NSURLErrorServerCertificateHasUnknownRoot,
            NSURLErrorClientCertificateRejected,
            NSURLErrorClientCertificateRequired
        ]
    }
}

extension Error {
    /// Returns `true` when this error’s code is one of ``NSError/sslCertificateURLErrorCodes``.
    public var isSSLCertificateURLError: Bool {
        let ns = self as NSError
        return NSError.sslCertificateURLErrorCodes.contains(ns.code)
    }
}

// MARK: - Localization

private enum SSLPinningL10n {
    private static let table = "Localizable"

    static func str(_ key: String) -> String {
        String(localized: String.LocalizationValue(key), table: table, bundle: .module, locale: .current)
    }

    static func format(_ key: String, _ arguments: CVarArg...) -> String {
        let format = str(key)
        return String(format: format, locale: .current, arguments: arguments)
    }

    static func urlErrorSummary(for code: URLError.Code) -> String {
        let key: String
        switch code {
        case .secureConnectionFailed:
            key = "url_error.secure_connection_failed"
        case .serverCertificateUntrusted:
            key = "url_error.server_certificate_untrusted"
        case .serverCertificateHasBadDate:
            key = "url_error.server_certificate_bad_date"
        case .serverCertificateNotYetValid:
            key = "url_error.server_certificate_not_yet_valid"
        case .serverCertificateHasUnknownRoot:
            key = "url_error.server_certificate_unknown_root"
        case .clientCertificateRejected:
            key = "url_error.client_certificate_rejected"
        case .clientCertificateRequired:
            key = "url_error.client_certificate_required"
        default:
            key = "url_error.generic_tls"
        }
        return str(key)
    }
}
