import Foundation

public struct Trust {
    let trust: SecTrust
    public init(trust: SecTrust) {
        self.trust = trust
    }
    
    public var certificates: [Certificate] {
        let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate]
        return chain?.map { Certificate(cert: $0) } ?? []
    }
    
    public var isSelfSigned: Bool? {
        certificates.count == 1 && (certificates.first?.isSelfSigned ?? false)
    }
    
    public func contains(_ pin: Fingerprint) -> Bool {
        certificates.contains(where: { $0 == pin })
    }
}
