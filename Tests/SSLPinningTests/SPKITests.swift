import Foundation
import Security
import Testing
@testable import SSLPinning

struct SPKITests {

    /// openssl s_client -connect beta.axxonnet.com:443 -showcerts </dev/null
    let leafCertificate = """
-----BEGIN CERTIFICATE-----
MIIE/DCCA+SgAwIBAgISBaictqFvUG0Wr7ECxL8Poe+wMA0GCSqGSIb3DQEBCwUA
MDMxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQwwCgYDVQQD
EwNSMTMwHhcNMjYwNTAxMTUwMDQ0WhcNMjYwNzMwMTUwMDQzWjAcMRowGAYDVQQD
ExFiZXRhLmF4eG9ubmV0LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAMUSz+k8Wv8hVGVdZNFEYHvcOwUmC5iVmhVBQHsXEnYLeVqyTS+WcChkBivD
K0q00ofq5jNVWAplEWhZRdXKy0MfweyAceFCNy3HMsXu06fAxv823S9UMtof4hFF
+WrZ2aObk5DDhBvV7b0j2s8BwwnBrm5Ae9xGP1uNDeUDE3nhpmpjCUG61z9Voitu
nGbR9e/re4hpq4ukUSmiJWQILmJgYy6jnis48Y3CuK4F7kw7nsa1emUIuLTw1TNU
1heIJ7MzwQ+xKiYDqlxT1Zo2uAzxbJPHQqJQTQp2VhC1dBp2+CFdjqaFYPZ5Vzjz
Gn5zNM5O0HTiqIekN9YSCCZqlw0CAwEAAaOCAh8wggIbMA4GA1UdDwEB/wQEAwIF
oDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBRy
o7Z0RMei2ZDp+XIABsHSFNmv7TAfBgNVHSMEGDAWgBTnq58PLDOgU9NeT3jIsoQO
O9aSMzAzBggrBgEFBQcBAQQnMCUwIwYIKwYBBQUHMAKGF2h0dHA6Ly9yMTMuaS5s
ZW5jci5vcmcvMBwGA1UdEQQVMBOCEWJldGEuYXh4b25uZXQuY29tMBMGA1UdIAQM
MAowCAYGZ4EMAQIBMC4GA1UdHwQnMCUwI6AhoB+GHWh0dHA6Ly9yMTMuYy5sZW5j
ci5vcmcvNDkuY3JsMIIBDAYKKwYBBAHWeQIEAgSB/QSB+gD4AHYA2AlVO5RPev/I
FhlvlE+Fq7D4/F6HVSYPFdEucrtFSxQAAAGd5EP9DAAABAMARzBFAiBPXytxUTBm
gxVyNR+LpOeZ50wnfR3kcSSv22NqoXZdygIhAOOR+o5S6zmxi2GIAA5ZLYzhqzXW
4G+wtZvKUMSw4AB6AH4AqCbL4wrGNRJGUz/gZfFPGdluGQgTxB3ZbXkAsxI8VScA
AAGd5EP+QgAIAAAFAAkek8cEAwBHMEUCIQDaZ/lRm36esfODeZJmND7ZmAv8QG6a
YXU3/BfO6oqQPAIgX4suIk0y5r9Hr4SKfXuhpA9/HryQ7KItgKKCL0UJnSMwDQYJ
KoZIhvcNAQELBQADggEBAEhgrnR8XUvjrHfyQcdZjDMtRmfjC1c3I11LAOcYUy79
qCharh1WGN89jt4DPqbTh+3juf/zLr2vE8JTdTR2EHK5QBn9uEhQLMyhA6Ev5d6S
Cvo3dhT75rGY9o0C+BU/gaDsbWBxrjFGUzqydfvgTSzVgqH+f/XJ6jveBMk/lYGX
xkJfFD6jiVSJ3T7c4r59MZYow0VpxtK+QLVi1kl1gjSHQG1koYNiZfYupS7cJ5N3
tgoAlemofTjf0YZiX6LWVkpibMyhAiTzGIkMkV8Eh8xLDPkLpF9jFrd3/x8hE4ya
/09KdlBcB7wAaljOtCN8aRHjpLYmNpNwPmbv3VWJH6c=
-----END CERTIFICATE-----    
"""

    let leaf2Certificate = """
-----BEGIN CERTIFICATE-----
MIIDsDCCAzagAwIBAgISBv49t2Z0Exmus+tBOyqL+RcEMAoGCCqGSM49BAMDMDIx
CzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQDEwJF
ODAeFw0yNjA1MDUyMzMyMjRaFw0yNjA4MDMyMzMyMjNaMBkxFzAVBgNVBAMMDiou
YXh4b25uZXQuY29tMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEGfMgQcCB5LSDpGZu
HciTtgpDr+eqywaqj5ChKxZPZVTJRwbbo1tkVpHfCRfPUL6LuKN8VQ5eUYE1jrDE
+B/DrcYVPBDE/FvUEKJMfw/V1ORVPYQuH8QaJrP0xqqHWBW2o4ICJjCCAiIwDgYD
VR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAw
HQYDVR0OBBYEFIkD2W1k/WpaGdHFO7yhFfgWIfncMB8GA1UdIwQYMBaAFI8NE6L2
Ln7RUGwzGDhdWY4jcpHKMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcwAoYWaHR0
cDovL2U4LmkubGVuY3Iub3JnLzAnBgNVHREEIDAegg4qLmF4eG9ubmV0LmNvbYIM
YXh4b25uZXQuY29tMBMGA1UdIAQMMAowCAYGZ4EMAQIBMCwGA1UdHwQlMCMwIaAf
oB2GG2h0dHA6Ly9lOC5jLmxlbmNyLm9yZy81LmNybDCCAQsGCisGAQQB1nkCBAIE
gfwEgfkA9wB2AMijxH/Hs625NWsBP2p6Em3jOk5DpcZG+ZetOXWZHc+aAAABnfqx
3+UAAAQDAEcwRQIhAKJSZBo/bivX/EH7Jszb+4EAnLEx+ZjhW3OJ438mZ6omAiAY
8VIAExNu4RiddTy0xe0dWGuvOpAmh1GsPZzgezk8FwB9ABqLnWsP/r+BtHk5xtIx
CobW0QLU8EbiGCyd419eJiXvAAABnfqx4O0ACAAABQAPZBYVBAMARjBEAiA65buR
PxKe43GkK1r9n+wjjLppGX9gLSKZGWBfKRrKSwIgTWuc7kArL6cQpiqxpgQ+EQrR
W9IIAAPoxhCPCfc1OHQwCgYIKoZIzj0EAwMDaAAwZQIxAPuNwAGmPZUpE3MLvm3O
0iS88Z7S9snUTspdCIvqfhTS1Gisb5ROqos7LpZes0AD3wIweJJl+v8xpYflqOoE
VFkmpetVcBm7L3t+T6AdGF1Sym5NtUaxf+2WIxPb3aYinYzb
-----END CERTIFICATE-----    
"""

    var leaf: SecCertificate {
        let der = try! pemToDER(leafCertificate)
        return SecCertificateCreateWithData(nil, der as CFData)!
    }

    var leaf2: SecCertificate {
        let der = try! pemToDER(leaf2Certificate)
        return SecCertificateCreateWithData(nil, der as CFData)!
    }

    func pemToDER(_ pem: String) throws -> Data {
        let base64 = pem
            .replacingOccurrences(of: "-----BEGIN CERTIFICATE-----", with: "")
            .replacingOccurrences(of: "-----END CERTIFICATE-----", with: "")
            .components(separatedBy: .whitespacesAndNewlines)
            .joined()

        guard let der = Data(base64Encoded: base64) else {
            throw NSError()
        }

        return der
    }

    @Test
    func spkiHashIsDeterministic() throws {
        let hash1 = try leaf.spkiHash()
        let hash2 = try leaf.spkiHash()
        #expect(hash1 == hash2)
    }

    @Test
    func differentCertificatesProduceDifferentSPKIHashes() throws {
        let hash1 = try leaf.spkiHash()
        let hash2 = try leaf2.spkiHash()
        #expect(hash1 != hash2)
    }

    /// openssl x509 -in leaf.pem -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256
    @Test
    func spkiHashMatchesOpenSSL() throws {
        let hash = try leaf.spkiHash()
        let hex = hash.hex()
        #expect(hex == "a0475b3bbd84993e8707a359ae0176ed1726638126acf032bdcf7263b8e68740")

        let spkiDER = try leaf.spkiDER()
        #expect(spkiDER.count == 294)
    }
}
