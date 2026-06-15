import Foundation

public struct SystemTrustStatus: Sendable, Equatable {
    /// Is certificate chain "Trusted by system"
    public let isTrusted: Bool

    /// Security.framework diagnostic.
    public let errorDescription: String?

    /// Leaf certificate of evaluated chain.
    public let leaf: CertificateInfo?

    /// Root certificate of evaluated chain.
    public let root: CertificateInfo?

    /// True if leaf certificate is self-signed.
    public var isSelfSignedLeaf: Bool {
        leaf?.isSelfSigned ?? false
    }

    init(
        isTrusted: Bool,
        errorDescription: String?,
        leaf: CertificateInfo?,
        root: CertificateInfo?
    ) {
        self.isTrusted = isTrusted
        self.errorDescription = errorDescription
        self.leaf = leaf
        self.root = root
    }
}
