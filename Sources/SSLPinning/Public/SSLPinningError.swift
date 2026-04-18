import Foundation

public enum SSLPinningError: Error, Sendable, Equatable {
    /// Server trust challenge was malformed or empty.
    case invalidServerTrust(host: String)
    /// A pin exists for this host but the chain does not match it.
    case pinMismatch(host: String, expected: Pin, presentedChain: [CertificateInfo])
    /// Pinning is enabled but there is no pin for this host; UI may add one and retry.
    case unknownHost(host: String, presentedChain: [CertificateInfo])
}

extension SSLPinningError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .invalidServerTrust(let host):
            return "Invalid or empty server trust for \(host)."
        case .pinMismatch(let host, _, let chain):
            let fp = chain.first?.sha256 ?? "?"
            return "Certificate pin mismatch for \(host) (presented SHA-256: \(fp))."
        case .unknownHost(let host, let chain):
            let fp = chain.first?.sha256 ?? "?"
            return "No pin configured for \(host); server presented SHA-256: \(fp)."
        }
    }
}
