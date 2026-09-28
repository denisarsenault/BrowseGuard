import Foundation

/// Reads a URL that a build setting supplies through `Info.plist`.
///
/// Both the blocklist feed and the Chrome Web Store listing are configured this
/// way, and both must be HTTPS for the same reason: one is an instruction set
/// the app acts on, the other is a link the app opens on the user's behalf, and
/// neither should be rewritable by anyone on the network path.
///
/// An unset, empty, or unexpanded value means "not configured" rather than
/// "broken" — a fresh checkout has no feed and no published listing, and should
/// simply not offer them.
public enum ConfiguredURL {

    public static func https(from raw: String?) -> URL? {
        guard let raw else { return nil }
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty,
              !trimmed.hasPrefix("$("),          // build setting never substituted
              let url = URL(string: trimmed),
              url.scheme?.lowercased() == "https"
        else { return nil }
        return url
    }

    public static func https(infoKey: String, in bundle: Bundle = .main) -> URL? {
        https(from: bundle.object(forInfoDictionaryKey: infoKey) as? String)
    }
}
