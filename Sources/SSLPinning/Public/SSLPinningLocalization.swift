import Foundation

/// Localized user-facing strings from ``Localizable.xcstrings``.
public enum SSLPinningLocalization {
    private static let table = "Localizable"
    private static let englishLocale = Locale(identifier: "en")

    /// Resource bundle that contains ``Localizable.xcstrings``.
    public static var bundle: Bundle { .module }

    /// Resolves `key` for `locale`. Falls back to English when the catalog has no translation.
    public static func string(_ key: String, locale: Locale = .current) -> String {
        resolve(key: key, locale: locale)
    }

    /// Formats a localized string for `locale`. Falls back to English when the catalog has no translation.
    public static func format(_ key: String, locale: Locale = .current, _ arguments: CVarArg...) -> String {
        let template = resolve(key: key, locale: locale)
        return String(format: template, locale: locale, arguments: arguments)
    }

    private static func resolve(key: String, locale: Locale) -> String {
        let localized = String(
            localized: String.LocalizationValue(key),
            table: table,
            bundle: bundle,
            locale: locale
        )
        if !localized.isEmpty, localized != key {
            return localized
        }
        if locale.identifier.hasPrefix("en") {
            return localized.isEmpty ? key : localized
        }
        let englishValue = String(
            localized: String.LocalizationValue(key),
            table: table,
            bundle: bundle,
            locale: englishLocale
        )
        if !englishValue.isEmpty, englishValue != key {
            return englishValue
        }
        return localized.isEmpty ? key : localized
    }
}
