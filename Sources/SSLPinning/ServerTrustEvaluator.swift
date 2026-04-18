import Foundation
import Security

/// Evaluates server-trust authentication challenges and records certificate chains per host (for inspection / pinning).
public final class ServerTrustEvaluator: @unchecked Sendable {
    private let ssl: SSL

    /// host → certificate chain observed on last challenge for that host
    public private(set) var sslCache: [String: [Certificate]] = [:]

    public init(ssl: SSL) {
        self.ssl = ssl
    }

    public func evaluate(_ challenge: URLAuthenticationChallenge) async -> (URLSession.AuthChallengeDisposition, URLCredential?) {
        let protectionSpace = challenge.protectionSpace
        let method = protectionSpace.authenticationMethod
        let host = protectionSpace.host
        guard method == NSURLAuthenticationMethodServerTrust else {
            return (.cancelAuthenticationChallenge, nil)
        }
        guard let serverTrust = protectionSpace.serverTrust else {
            return (.cancelAuthenticationChallenge, nil)
        }
        guard SecTrustGetCertificateCount(serverTrust) > 0 else {
            return (.cancelAuthenticationChallenge, nil)
        }

        let trust = Trust(trust: serverTrust)
        sslCache[host] = trust.certificates

        switch ssl {
        case .system:
            return (.performDefaultHandling, nil)
        case .pinning(let pins):
            if let pin = pins.first(where: { $0.host == host }) {
                if trust.contains(pin) {
                    return (.useCredential, URLCredential(trust: serverTrust))
                } else {
                    return (.performDefaultHandling, nil)
                }
            }
        case .trustEveryone:
            return (.useCredential, URLCredential(trust: serverTrust))
        }

        return (.performDefaultHandling, nil)
    }
}
