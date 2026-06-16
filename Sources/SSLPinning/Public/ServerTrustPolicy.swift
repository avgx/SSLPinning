import Foundation

/// How `ServerTrustEvaluator` should respond to server TLS authentication challenges.
public enum ServerTrustPolicy: Codable, Equatable, Sendable {
    /// Use the system trust store; no app-level pinning.
    case system
    /// Accept any server certificate (insecure; debugging only).
    case trustEveryone
    /// Allow only hosts whose certificate matches a configured ``Fingerprint``.
    case pinning([Fingerprint])
    /// Allow only hosts whose SPKI hash matches a configured ``Fingerprint`` (SPKI-only pins).
    case pinningSpki([Fingerprint])

    private enum CodingKeys: String, CodingKey {
        case type
        case pins
    }

    private enum PolicyType: String, Codable {
        case system
        case trustEveryone
        case pinning
        case pinningSpki
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)

        switch self {
        case .system:
            try container.encode(PolicyType.system, forKey: .type)

        case .trustEveryone:
            try container.encode(PolicyType.trustEveryone, forKey: .type)

        case .pinning(let pins):
            try container.encode(PolicyType.pinning, forKey: .type)
            try container.encode(pins, forKey: .pins)
        case .pinningSpki(let pins):
            try container.encode(PolicyType.pinningSpki, forKey: .type)
            try container.encode(pins, forKey: .pins)
        }
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let type = try container.decode(PolicyType.self, forKey: .type)

        switch type {
        case .system:
            self = .system

        case .trustEveryone:
            self = .trustEveryone

        case .pinning:
            let pins = try container.decode([Fingerprint].self, forKey: .pins)
            self = .pinning(pins)
        case .pinningSpki:
            let pins = try container.decode([Fingerprint].self, forKey: .pins)
            self = .pinningSpki(pins)
        }
    }
}

extension ServerTrustPolicy {
    /// Stable localization key for this policy case.
    public var localizationKey: String {
        switch self {
        case .system:
            "sslpinning.policy.system.description"
        case .trustEveryone:
            "sslpinning.policy.trust_everyone.description"
        case .pinning:
            "sslpinning.policy.pinning.description"
        case .pinningSpki:
            "sslpinning.policy.pinning_spki.description"
        }
    }

    /// Short functional description for settings or picker UI (localized).
    public func localizedDescription(locale: Locale = .current) -> String {
        SSLPinningLocalization.string(localizationKey, locale: locale)
    }
}
