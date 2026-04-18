import Foundation

public struct TrustChallengeResult: Sendable {
    public let disposition: URLSession.AuthChallengeDisposition
    public let credential: URLCredential?
    /// Set when pinning cancels the challenge so the app can surface a typed error after the task fails.
    public let pinningError: SSLPinningError?

    public init(
        disposition: URLSession.AuthChallengeDisposition,
        credential: URLCredential?,
        pinningError: SSLPinningError? = nil
    ) {
        self.disposition = disposition
        self.credential = credential
        self.pinningError = pinningError
    }
}
