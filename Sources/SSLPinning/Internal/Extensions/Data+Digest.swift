import CommonCrypto
import Foundation

extension Data {
    func sha256() -> Data {
        let data: Data = self
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        _ = data.withUnsafeBytes { CC_SHA256($0.baseAddress, CC_LONG($0.count), &hash) }
        return Data(hash)
    }

    func sha1() -> Data {
        let data: Data = self
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        _ = data.withUnsafeBytes { CC_SHA1($0.baseAddress, CC_LONG($0.count), &hash) }
        return Data(hash)
    }

    func hex(separator: String = "") -> String {
        let data: Data = self
        return data.map { String(format: "%02X", $0) }.joined(separator: separator)
    }
}
