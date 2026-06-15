import Foundation

/// How `ServerTrustEvaluator` should respond to server TLS authentication challenges.
public enum ServerTrustPolicy: Codable, Equatable, Sendable {
    case system
    case trustEveryone
    case pinning([Pin])
    
    private enum CodingKeys: String, CodingKey {
        case type
        case pins
    }
    
    private enum PolicyType: String, Codable {
        case system
        case trustEveryone
        case pinning
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
            let pins = try container.decode([Pin].self, forKey: .pins)
            self = .pinning(pins)
        }
    }
}
