import Foundation

public struct Pin: Codable, Fingerprint, Equatable, Sendable {
    public let host: String
    public let serialNumber: String
    public let sha256: String
    public let sha1: String

    public init(host: String, serialNumber: String, sha256: String, sha1: String) {
        self.host = host
        self.serialNumber = serialNumber
        self.sha256 = sha256
        self.sha1 = sha1
    }
}
