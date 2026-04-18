import Foundation

/// How `ServerTrustEvaluator` should respond to server TLS authentication challenges.
public enum ServerTrustPolicy: Sendable {
    case system
    case trustEveryone
    case pinning([Pin])
}
