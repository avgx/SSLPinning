import Foundation
import Testing
@testable import SSLPinning

@Suite("ServerTrustPolicy")
struct ServerTrustPolicyTests {
    @Test
    func testEquatable_system() {
        #expect(ServerTrustPolicy.system == .system)
        #expect(ServerTrustPolicy.system != .trustEveryone)
    }

    @Test
    func testEquatable_trustEveryone() {
        #expect(ServerTrustPolicy.trustEveryone == .trustEveryone)
        #expect(ServerTrustPolicy.trustEveryone != .system)
    }

    @Test
    func testEquatable_pinning() {
        let p1 = Fingerprint(host: "a.com", serialNumber: "1", sha256: "x", sha1: "y")
        let p2 = Fingerprint(host: "a.com", serialNumber: "1", sha256: "x", sha1: "y")
        let p3 = Fingerprint(host: "b.com", serialNumber: "2", sha256: "x2", sha1: "y2")

        #expect(ServerTrustPolicy.pinning([p1]) == .pinning([p2]))
        #expect(ServerTrustPolicy.pinning([p1]) != .pinning([p3]))
    }

    @Test
    func testCodable_system_roundTrip() throws {
        try roundTrip(.system)
    }

    @Test
    func testCodable_trustEveryone_roundTrip() throws {
        try roundTrip(.trustEveryone)
    }

    @Test
    func testCodable_pinning_roundTrip() throws {
        let pins = [
            Fingerprint(host: "a.com", serialNumber: "1", sha256: "s256", sha1: "s1"),
            Fingerprint(host: "b.com", serialNumber: "2", sha256: "s256b", sha1: "s1b")
        ]

        try roundTrip(.pinning(pins))
    }

    @Test
    func testCodable_pinningSpki_roundTrip() throws {
        let pins = [
            Fingerprint(host: "a.com", spkiSHA256: "abc"),
            Fingerprint(host: "b.com", spkiSHA256: "def")
        ]

        try roundTrip(.pinningSpki(pins))
    }

    @Test
    func testLocalizationKeys_nonEmpty() {
        #expect(ServerTrustPolicy.system.localizationKey.isEmpty == false)
        #expect(ServerTrustPolicy.pinning([]).localizationKey.isEmpty == false)
        #expect(ServerTrustPolicy.pinningSpki([]).localizationKey.isEmpty == false)
    }

    private func roundTrip(_ value: ServerTrustPolicy) throws {
        let encoder = JSONEncoder()
        let decoder = JSONDecoder()

        let data = try encoder.encode(value)
        let decoded = try decoder.decode(ServerTrustPolicy.self, from: data)

        #expect(decoded == value)
    }

    @Test
    func testJSON_contract_pinning() throws {
        let policy: ServerTrustPolicy = .pinning([
            Fingerprint(host: "a.com", serialNumber: "1", sha256: "x", sha1: "y")
        ])

        let data = try JSONEncoder().encode(policy)

        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]

        #expect(json?["type"] as? String == "pinning")
        #expect((json?["pins"] as? [[String: Any]])?.count == 1)
    }
}
