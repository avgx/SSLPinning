import Foundation

public enum SSL: Sendable {
    case system
    case trustEveryone
    case pinning([Pin])
}
