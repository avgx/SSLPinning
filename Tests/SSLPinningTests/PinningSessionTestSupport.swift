import Foundation
import Testing
@testable import SSLPinning

extension Tag {
    @Tag static var network: Tag
}

/// Retained by `URLSession` while requests run; captures the last pinning error from TLS evaluation.
final class PinningSessionDelegate: NSObject, URLSessionDelegate, URLSessionTaskDelegate, @unchecked Sendable {
    let evaluator: ServerTrustEvaluator
    private let lock = NSLock()
    private var _lastPinningError: SSLPinningError?

    /// When true, HTTP redirects are not followed (`completionHandler(nil)`), so the TLS host matches the original URL (e.g. literal `1.1.1.1`).
    var suppressHttpRedirects = false

    var lastPinningError: SSLPinningError? {
        lock.withLock { _lastPinningError }
    }

    init(policy: ServerTrustPolicy) {
        self.evaluator = ServerTrustEvaluator(policy: policy)
        super.init()
    }

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        let result = evaluator.evaluate(challenge)
        lock.withLock { _lastPinningError = result.pinningError }
        completionHandler(result.disposition, result.credential)
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        if suppressHttpRedirects {
            completionHandler(nil)
        } else {
            completionHandler(newRequest)
        }
    }
}

enum NetworkSession {
    static func makeSession(
        policy: ServerTrustPolicy,
        suppressHttpRedirects: Bool = false,
        configure: (URLSessionConfiguration) -> Void = { _ in }
    ) -> (URLSession, PinningSessionDelegate) {
        let delegate = PinningSessionDelegate(policy: policy)
        delegate.suppressHttpRedirects = suppressHttpRedirects
        let configuration = URLSessionConfiguration.ephemeral
        configure(configuration)
        let session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
        return (session, delegate)
    }
}
