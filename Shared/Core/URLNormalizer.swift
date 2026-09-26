import Foundation

/// Canonicalizes hosts before they reach the matcher or the heuristics.
///
/// Every lookup path in the app funnels through here so that `WWW.Example.COM.`
/// and `example.com` cannot disagree about whether a site is allowlisted.
public enum URLNormalizer {

    /// Lowercased, trailing-dot-stripped, `www.`-stripped registrable host.
    ///
    /// Returns `nil` for anything that is not a network URL with a host:
    /// `about:blank`, `data:`, `file:`, and IP-literal-free garbage.
    public static func canonicalHost(of url: URL) -> String? {
        guard let scheme = url.scheme?.lowercased(),
              scheme == "http" || scheme == "https" || scheme == "ws" || scheme == "wss",
              let host = url.host(percentEncoded: false)
        else { return nil }
        return canonicalHost(of: host)
    }

    /// Normalizes a bare host string. Accepts what a user might type into the
    /// allowlist field, including a full URL pasted by mistake.
    public static func canonicalHost(of raw: String) -> String? {
        var host = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !host.isEmpty else { return nil }

        // Tolerate a pasted URL.
        if host.contains("://"), let parsed = URL(string: host)?.host(percentEncoded: false) {
            host = parsed.lowercased()
        } else if let slash = host.firstIndex(of: "/") {
            host = String(host[host.startIndex..<slash])
        }

        // Strip credentials and port.
        if let at = host.lastIndex(of: "@") {
            host = String(host[host.index(after: at)...])
        }
        if !host.hasPrefix("["), let colon = host.lastIndex(of: ":") {
            host = String(host[host.startIndex..<colon])
        }

        while host.hasSuffix(".") { host.removeLast() }
        if host.hasPrefix("www.") { host.removeFirst(4) }

        guard !host.isEmpty, host.allSatisfy(isAllowedHostScalar) else { return nil }
        return host
    }

    private static func isAllowedHostScalar(_ character: Character) -> Bool {
        character.isLetter || character.isNumber || character == "." || character == "-"
            || character == "_" || character == ":" || character == "[" || character == "]"
    }

    /// The labels of a host, most specific first: `a.b.example.com` becomes
    /// `["a.b.example.com", "b.example.com", "example.com", "com"]`.
    ///
    /// Used for suffix matching so a rule on `example.com` also covers
    /// `tracker.example.com`.
    public static func suffixChain(for host: String) -> [String] {
        let labels = host.split(separator: ".", omittingEmptySubsequences: true)
        guard labels.count > 1 else { return [host] }
        return (0..<labels.count).map { labels[$0...].joined(separator: ".") }
    }

    /// True when the host is a raw IPv4/IPv6 literal rather than a name.
    public static func isIPLiteral(_ host: String) -> Bool {
        if host.hasPrefix("[") { return true }
        let parts = host.split(separator: ".")
        guard parts.count == 4 else { return host.contains(":") }
        return parts.allSatisfy { part in
            guard let value = Int(part), (0...255).contains(value) else { return false }
            return true
        }
    }

    /// Decodes an IDN `xn--` host to Unicode for homograph inspection.
    /// Returns `nil` when the host has no punycode labels.
    public static func decodedIDN(_ host: String) -> String? {
        guard host.contains("xn--") else { return nil }
        // `URL` round-trips IDNA for us; the naive path is enough for display.
        guard let url = URL(string: "http://\(host)/"),
              let decoded = url.host(percentEncoded: false)?.removingPercentEncoding
        else { return nil }
        return decoded == host ? nil : decoded
    }
}
