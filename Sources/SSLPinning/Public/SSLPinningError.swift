import Foundation

public enum SSLPinningError: Error, Sendable, Equatable {
    /// Server trust challenge was malformed or empty.
    case invalidServerTrust(host: String)
    /// A pin exists for this host but the chain does not match it.
    case fingerprintMismatch(host: String, expected: Fingerprint, presentedChain: [CertificateInfo])
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
            SSLPinningLocalization.format("sslpinning.invalid_server_trust.error_description", host)
        case .fingerprintMismatch(let host, _, _):
            SSLPinningLocalization.format("sslpinning.fingerprint_mismatch.error_description", host)
        case .unknownHost(let host, _):
            SSLPinningLocalization.format("sslpinning.unknown_host.error_description", host)
        case .systemTrustFailed:
            SSLPinningLocalization.string("sslpinning.system_trust_failed.error_description")
        }
    }

    public var failureReason: String? {
        switch self {
        case .invalidServerTrust:
            return SSLPinningLocalization.string("sslpinning.invalid_server_trust.failure_reason")
        case .fingerprintMismatch(_, let expected, let chain):
            if expected.isSPKIOnly {
                let presented = chain.first?.spki ?? "?"
                return SSLPinningLocalization.format(
                    "sslpinning.fingerprint_mismatch_spki.failure_reason",
                    expected.sha256,
                    presented
                )
            }
            let presented = chain.first?.sha256 ?? "?"
            let serial = expected.serialNumber ?? "?"
            return SSLPinningLocalization.format(
                "sslpinning.fingerprint_mismatch.failure_reason",
                serial,
                expected.sha256,
                presented
            )
        case .unknownHost(_, let chain):
            let fp = chain.first?.sha256 ?? "?"
            return SSLPinningLocalization.format("sslpinning.unknown_host.failure_reason", fp)
        case .systemTrustFailed(let underlying):
            let codeLabel = urlErrorSummary(for: underlying.code)
            let header = SSLPinningLocalization.format(
                "sslpinning.system_trust_failed.failure_reason_header",
                codeLabel
            )
            return "\(header)\n\n\(underlying.localizedDescription)"
        }
    }

    public var recoverySuggestion: String? {
        switch self {
        case .invalidServerTrust:
            SSLPinningLocalization.string("sslpinning.invalid_server_trust.recovery_suggestion")
        case .fingerprintMismatch:
            SSLPinningLocalization.string("sslpinning.fingerprint_mismatch.recovery_suggestion")
        case .unknownHost:
            SSLPinningLocalization.string("sslpinning.unknown_host.recovery_suggestion")
        case .systemTrustFailed:
            SSLPinningLocalization.string("sslpinning.system_trust_failed.recovery_suggestion")
        }
    }

    private func urlErrorSummary(for code: URLError.Code) -> String {
        let key: String
        switch code {
        case .secureConnectionFailed:
            key = "sslpinning.url_error.secure_connection_failed"
        case .serverCertificateUntrusted:
            key = "sslpinning.url_error.server_certificate_untrusted"
        case .serverCertificateHasBadDate:
            key = "sslpinning.url_error.server_certificate_bad_date"
        case .serverCertificateNotYetValid:
            key = "sslpinning.url_error.server_certificate_not_yet_valid"
        case .serverCertificateHasUnknownRoot:
            key = "sslpinning.url_error.server_certificate_unknown_root"
        case .clientCertificateRejected:
            key = "sslpinning.url_error.client_certificate_rejected"
        case .clientCertificateRequired:
            key = "sslpinning.url_error.client_certificate_required"
        default:
            key = "sslpinning.url_error.generic_tls"
        }
        return SSLPinningLocalization.string(key)
    }
}

// MARK: - URL error classification

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
