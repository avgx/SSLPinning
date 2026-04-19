# SSLPinning

Small helpers for `URLAuthenticationMethodServerTrust` in a `URLSession` delegate, optional certificate pinning, and typed [`SSLPinningError`](Sources/SSLPinning/Public/SSLPinningError.swift) when pinning cancels a challenge.

**Platforms:** macOS 12+, iOS 15+ (uses `SecTrustCopyCertificateChain`).

**Layout:** [`Public/`](Sources/SSLPinning/Public/) is the API surface; [`Internal/`](Sources/SSLPinning/Internal/) holds implementation helpers (same `SSLPinning` module).

### `CertificateInfo` and validity (iOS-first)

Pinning only needs fingerprints; [`CertificateInfo`](Sources/SSLPinning/Public/Fingerprint.swift) adds optional metadata for UI and logging.

| Field | iOS / iPadOS / Catalyst | Native macOS |
|--------|-------------------------|--------------|
| `commonName`, `subjectSummary`, serial, digests | From `Security` APIs on all platforms | Same |
| `notValidBefore` / `notValidAfter` | `SecCertificateCopyNotValidBeforeDate` / `…AfterDate` on **iOS 18+** (nil below) | Same APIs on **macOS 15+**; macOS 13–14 uses [`SecCertificateCopyValues`](https://developer.apple.com/documentation/security/seccertificatecopyvalues(_:_:_:)) only to read validity from the returned plist |

## Usage

`URLSession` must use a delegate that handles server-trust challenges. Call [`ServerTrustEvaluator.evaluate(_:)`](Sources/SSLPinning/Public/ServerTrustEvaluator.swift), then pass the returned [`TrustChallengeResult`](Sources/SSLPinning/Public/TrustChallengeResult.swift) to the completion handler. The evaluator is synchronous so you can call it directly from the delegate (no nested `Task` required).

When `pinningError` is non-nil, the disposition is usually `.cancelAuthenticationChallenge`; the task will fail with a URL error. Treat `pinningError` as the structured reason (e.g. show UI and optionally append a new [`Pin`](Sources/SSLPinning/Public/Pin.swift) and retry).

Challenges whose `authenticationMethod` is not server trust are answered with `.performDefaultHandling` so unrelated auth flows are not cancelled by mistake.

### Delegate

```swift
final class TLSDelegate: NSObject, URLSessionDelegate {
    private let evaluator: ServerTrustEvaluator

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
        completionHandler(result.disposition, result.credential)
    }
}
```

In a real app, keep one `ServerTrustEvaluator` per policy (or per session) so [`certificateChainsByHost`](Sources/SSLPinning/Public/ServerTrustEvaluator.swift) stays meaningful.

### SwiftUI flow (pinning, unknown host)

1. Load the root URL with `ServerTrustPolicy.pinning(existingPins)`.
2. If the request throws, inspect the delegate’s last `TrustChallengeResult.pinningError` (or capture `result.pinningError` in the delegate and assign to your `@Observable` model before calling `completionHandler`).
3. For [`unknownHost(host:presentedChain:)`](Sources/SSLPinning/Public/SSLPinningError.swift), show an alert with e.g. `presentedChain.first?.sha256` and build a new `Pin(host:serialNumber:sha256:sha1:)` from that [`CertificateInfo`](Sources/SSLPinning/Public/Fingerprint.swift) if the user chooses to trust this server for your app.
4. Retry the same URL with `ServerTrustPolicy.pinning(existingPins + [newPin])`. No “wait inside the delegate”: the user action happens after the failed task, then a new task starts.

For [`pinMismatch`](Sources/SSLPinning/Public/SSLPinningError.swift), do not retry until the configured pin or server certificate is corrected; continuing would defeat pinning.

### Filtered tests (network)

Integration tests are tagged `.network`. Run unit-only suite (no outbound network):

```bash
swift test --filter PinningPolicy
```

Run network integration (outbound HTTPS; update the example.com pin in [`PinningNetworkIntegrationTests.swift`](Tests/SSLPinningTests/PinningNetworkIntegrationTests.swift) if the leaf rotates):

```bash
swift test --filter legacyScenariosInOrder
```
