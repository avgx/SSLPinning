import Foundation
import Security

extension Certificate {
    /// Validity bounds from a single `SecCertificateCopyValues` pass (nil if the plist omits them).
    var validityRange: (notBefore: Date?, notAfter: Date?) {
        Self.validityNotBeforeNotAfter(certificate: cert)
    }

    /// One-line issuer from the certificate when `SecCertificateCopyValues` exposes it.
    var issuer: String? {
        if let s = Self.propertyString(certificate: cert, oid: kSecOIDX509V1IssuerNameStd) {
            return s
        }
        if let s = Self.propertyString(certificate: cert, oid: kSecOIDX509V1IssuerNameLDAP) {
            return s
        }
        if let s = Self.propertyString(certificate: cert, oid: kSecOIDX509V1IssuerName) {
            return s
        }
        return SecCertificateCopyLongDescription(nil, cert, nil) as String?
    }

    /// DNS names and IP literals from the Subject Alternative Name extension (empty if absent).
    var subjectAlternativeNames: [String] {
        Self.subjectAlternativeNames(from: cert)
    }

    // MARK: - SecCertificateCopyValues

    private static func innerDictionary(root: NSDictionary, oid: CFString) -> NSDictionary? {
        if let inner = root.object(forKey: oid) as? NSDictionary {
            return inner
        }
        for key in root.allKeys {
            guard CFGetTypeID(key as AnyObject) == CFStringGetTypeID() else { continue }
            let keyCF = unsafeBitCast(key as AnyObject, to: CFString.self)
            if CFStringCompare(keyCF, oid, []) == .compareEqualTo {
                return root.object(forKey: key) as? NSDictionary
            }
        }
        return nil
    }

    private static func propertyValue(certificate: SecCertificate, oid: CFString) -> Any? {
        guard let plist = SecCertificateCopyValues(certificate, nil, nil) else {
            return nil
        }
        let root = plist as NSDictionary
        guard let inner = innerDictionary(root: root, oid: oid) else {
            return nil
        }
        return inner.object(forKey: kSecPropertyKeyValue)
    }

    private static func effectivePayload(inner: NSDictionary?) -> Any? {
        guard let inner else { return nil }
        return inner.object(forKey: kSecPropertyKeyValue) ?? inner
    }

    private static func validityNotBeforeNotAfter(certificate: SecCertificate) -> (Date?, Date?) {
        guard let plist = SecCertificateCopyValues(certificate, nil, nil) else {
            return (nil, nil)
        }
        let root = plist as NSDictionary
        let beforePayload = effectivePayload(inner: innerDictionary(root: root, oid: kSecOIDX509V1ValidityNotBefore))
        let afterPayload = effectivePayload(inner: innerDictionary(root: root, oid: kSecOIDX509V1ValidityNotAfter))
        var before = firstDate(in: beforePayload)
        var after = firstDate(in: afterPayload)
        if before == nil {
            before = dateMatchingLabel(in: root, labelContains: "Not Valid Before")
                ?? dateMatchingLabel(in: root, labelContains: "Not Before")
        }
        if after == nil {
            after = dateMatchingLabel(in: root, labelContains: "Not Valid After")
                ?? dateMatchingLabel(in: root, labelContains: "Not After")
        }
        return (before, after)
    }

    private static func plistLabel(from dict: NSDictionary) -> String? {
        if let s = dict.object(forKey: kSecPropertyKeyLabel) as? String { return s }
        if let s = dict.object(forKey: kSecPropertyKeyLocalizedLabel) as? String { return s }
        if let s = dict.object(forKey: kSecPropertyKeyLabel) as? NSString { return s as String }
        if let s = dict.object(forKey: kSecPropertyKeyLocalizedLabel) as? NSString { return s as String }
        return nil
    }

    private static func dateMatchingLabel(in value: Any?, labelContains: String) -> Date? {
        guard let value else { return nil }
        switch value {
        case let dict as NSDictionary:
            if let lab = plistLabel(from: dict), lab.range(of: labelContains, options: .caseInsensitive) != nil {
                if let v = dict.object(forKey: kSecPropertyKeyValue), let d = firstDate(in: v) {
                    return d
                }
            }
            let keyEnumerator = dict.keyEnumerator()
            while let k = keyEnumerator.nextObject() {
                if let v = dict.object(forKey: k), let d = dateMatchingLabel(in: v, labelContains: labelContains) {
                    return d
                }
            }
        case let arr as NSArray:
            for idx in 0 ..< arr.count {
                if let d = dateMatchingLabel(in: arr.object(at: idx), labelContains: labelContains) {
                    return d
                }
            }
        case let arr as [Any]:
            for el in arr {
                if let d = dateMatchingLabel(in: el, labelContains: labelContains) {
                    return d
                }
            }
        default:
            break
        }
        return nil
    }

    private static func propertyString(certificate: SecCertificate, oid: CFString) -> String? {
        guard let value = propertyValue(certificate: certificate, oid: oid) else { return nil }
        if let s = value as? String { return s }
        if let s = value as? NSString { return s as String }
        if let d = firstDate(in: value) {
            return ISO8601DateFormatter().string(from: d)
        }
        return nil
    }

    private static func firstDate(in value: Any?) -> Date? {
        guard let value else { return nil }
        if let d = value as? Date { return d }
        if let d = value as? NSDate { return d as Date }
        // `SecCertificateCopyValues` encodes X.509 validity as CFAbsoluteTime (`NSNumber` seconds since 2001-01-01).
        if let n = value as? NSNumber {
            return Date(timeIntervalSinceReferenceDate: n.doubleValue)
        }
        if let s = value as? String, let d = isoOrRfc3339Date(from: s) { return d }
        if let s = value as? NSString, let d = isoOrRfc3339Date(from: s as String) { return d }
        switch value {
        case let arr as [Any]:
            for el in arr {
                if let d = firstDate(in: el) { return d }
            }
        case let arr as NSArray:
            for idx in 0 ..< arr.count {
                if let d = firstDate(in: arr.object(at: idx)) { return d }
            }
        case let dict as NSDictionary:
            if let v = dict.object(forKey: kSecPropertyKeyValue), let d = firstDate(in: v) { return d }
            let keyEnumerator = dict.keyEnumerator()
            while let k = keyEnumerator.nextObject() {
                if let v = dict.object(forKey: k), let d = firstDate(in: v) { return d }
            }
        case let dict as [AnyHashable: Any]:
            for (_, v) in dict {
                if let d = firstDate(in: v) { return d }
            }
        default:
            break
        }
        return nil
    }

    private static func isoOrRfc3339Date(from string: String) -> Date? {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let d = f.date(from: string) { return d }
        f.formatOptions = [.withInternetDateTime]
        if let d = f.date(from: string) { return d }
        let df = DateFormatter()
        df.locale = Locale(identifier: "en_US_POSIX")
        df.timeZone = TimeZone(secondsFromGMT: 0)
        let patterns = [
            "MMM d HH:mm:ss yyyy zzz",
            "MMM  d HH:mm:ss yyyy zzz",
            "yyyy-MM-dd HH:mm:ss zzz",
            "yyyy-MM-dd HH:mm:ss Z",
        ]
        for pattern in patterns {
            df.dateFormat = pattern
            if let d = df.date(from: string) { return d }
        }
        return asn1UTCorGeneralizedTime(from: string)
    }

    /// ASN.1 UTCTime / GeneralizedTime as plain strings (e.g. `250101000000Z`, `20250418120000Z`).
    private static func asn1UTCorGeneralizedTime(from string: String) -> Date? {
        let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let last = trimmed.last, last == "Z" || last == "z" else { return nil }
        let core = trimmed.dropLast()
        guard core.allSatisfy(\.isNumber) else { return nil }
        let df = DateFormatter()
        df.locale = Locale(identifier: "en_US_POSIX")
        df.timeZone = TimeZone(secondsFromGMT: 0)
        switch core.count {
        case 14:
            df.dateFormat = "yyyyMMddHHmmss"
        case 12:
            df.dateFormat = "yyMMddHHmmss"
        case 10:
            df.dateFormat = "yyMMddHHmm"
        default:
            return nil
        }
        return df.date(from: String(core))
    }

    private static func subjectAlternativeNames(from certificate: SecCertificate) -> [String] {
        guard let value = propertyValue(certificate: certificate, oid: kSecOIDSubjectAltName) else {
            return []
        }
        var names: Set<String> = []
        collectSANStrings(from: value, into: &names)
        return names.sorted()
    }

    private static func collectSANStrings(from value: Any, into out: inout Set<String>) {
        switch value {
        case let s as String:
            let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
            if t.isEmpty == false { out.insert(t) }
        case let s as NSString:
            collectSANStrings(from: s as String, into: &out)
        case let arr as [Any]:
            for el in arr { collectSANStrings(from: el, into: &out) }
        case let arr as NSArray:
            for idx in 0 ..< arr.count {
                collectSANStrings(from: arr.object(at: idx), into: &out)
            }
        case let dict as NSDictionary:
            if let v = dict.object(forKey: kSecPropertyKeyValue) {
                collectSANStrings(from: v, into: &out)
            } else {
                let keyEnumerator = dict.keyEnumerator()
                while let k = keyEnumerator.nextObject() {
                    if let v = dict.object(forKey: k) {
                        collectSANStrings(from: v, into: &out)
                    }
                }
            }
        case let dict as [AnyHashable: Any]:
            for (_, v) in dict {
                collectSANStrings(from: v, into: &out)
            }
        default:
            break
        }
    }
}
