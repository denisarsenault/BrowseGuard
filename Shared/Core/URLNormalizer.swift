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
    /// Returns `nil` when the host has no punycode labels, or none decode.
    ///
    /// Punycode is decoded here rather than handed to `URL`, because Apple's
    /// `URL.host` gives the *encoded* form back — so the previous version of
    /// this function always found `decoded == host` and returned `nil`, which
    /// silently disabled the homograph heuristic entirely. A cross-check
    /// against the JavaScript port is what exposed it.
    public static func decodedIDN(_ host: String) -> String? {
        guard host.contains("xn--") else { return nil }
        var changed = false
        let labels = host.split(separator: ".", omittingEmptySubsequences: false).map { label -> String in
            guard label.lowercased().hasPrefix("xn--"),
                  let decoded = punycodeDecode(String(label.dropFirst(4)))
            else { return String(label) }
            changed = true
            return decoded
        }
        return changed ? labels.joined(separator: ".") : nil
    }

    /// RFC 3492 punycode decoding of a single label (without the `xn--`).
    /// Returns `nil` for input that is not valid punycode.
    static func punycodeDecode(_ input: String) -> String? {
        let base = 36, tmin = 1, tmax = 26, skew = 38, damp = 700
        let initialBias = 72, initialN = 128

        func adapt(_ delta: Int, _ numPoints: Int, _ firstTime: Bool) -> Int {
            var delta = firstTime ? delta / damp : delta / 2
            delta += delta / numPoints
            var k = 0
            while delta > ((base - tmin) * tmax) / 2 {
                delta /= base - tmin
                k += base
            }
            return k + (base - tmin + 1) * delta / (delta + skew)
        }

        func digit(_ character: Character) -> Int? {
            guard let ascii = character.asciiValue else { return nil }
            switch ascii {
            case 0x41...0x5A: return Int(ascii - 0x41)          // A-Z
            case 0x61...0x7A: return Int(ascii - 0x61)          // a-z
            case 0x30...0x39: return Int(ascii - 0x30) + 26     // 0-9
            default: return nil
            }
        }

        var output: [Unicode.Scalar] = []
        var encoded = Substring(input)

        // Everything before the last delimiter is literal ASCII.
        if let delimiter = input.lastIndex(of: "-") {
            for character in input[input.startIndex..<delimiter] {
                guard let scalar = character.unicodeScalars.first,
                      character.unicodeScalars.count == 1, scalar.isASCII
                else { return nil }
                output.append(scalar)
            }
            encoded = input[input.index(after: delimiter)...]
        }

        var n = initialN, i = 0, bias = initialBias
        var index = encoded.startIndex

        while index < encoded.endIndex {
            let oldI = i
            var weight = 1, k = base
            while true {
                guard index < encoded.endIndex, let d = digit(encoded[index]) else { return nil }
                index = encoded.index(after: index)
                // Overflow-safe: a label this long is malformed anyway.
                let (product, overflow) = d.multipliedReportingOverflow(by: weight)
                guard !overflow else { return nil }
                i += product
                let t = k <= bias ? tmin : (k >= bias + tmax ? tmax : k - bias)
                if d < t { break }
                weight *= base - t
                k += base
            }

            bias = adapt(i - oldI, output.count + 1, oldI == 0)
            n += i / (output.count + 1)
            i %= output.count + 1
            guard let scalar = Unicode.Scalar(UInt32(n)) else { return nil }
            output.insert(scalar, at: i)
            i += 1
        }

        return output.isEmpty ? nil : String(String.UnicodeScalarView(output))
    }

    /// Non-Latin characters that render like an ASCII letter, mapped to the
    /// letter they imitate.
    ///
    /// Deliberately small. This is not a general Unicode confusables table
    /// (UTS #39) — it covers the Cyrillic and Greek letters that actually turn
    /// up in brand-impersonation domains, which is what the brand check needs.
    private static let confusables: [Character: Character] = [
        // Cyrillic
        "а": "a", "в": "b", "с": "c", "ԁ": "d", "е": "e", "ѕ": "s", "һ": "h",
        "і": "i", "ӏ": "l", "ј": "j", "к": "k", "м": "m", "н": "h", "о": "o",
        "р": "p", "ԛ": "q", "г": "r", "т": "t", "ѵ": "v", "х": "x", "у": "y",
        // Greek
        "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o",
        "ρ": "p", "σ": "o", "τ": "t", "υ": "u", "χ": "x", "γ": "y", "μ": "u",
    ]

    /// Rewrites confusable characters to the ASCII letters they imitate, so a
    /// whole-script lookalike can be compared against a brand name.
    ///
    /// Returns `nil` when nothing was confusable — the caller only cares about
    /// labels that are pretending to be something else.
    public static func confusableSkeleton(_ label: String) -> String? {
        var changed = false
        let mapped = label.map { character -> Character in
            guard let ascii = confusables[Character(character.lowercased())] else { return character }
            changed = true
            return ascii
        }
        return changed ? String(mapped) : nil
    }

    /// True when a decoded host mixes ASCII letters with non-ASCII letters in
    /// the same label — the shape of a homograph attack (`аpple.com`, with a
    /// Cyrillic `а`).
    ///
    /// A label written entirely in one non-Latin script is an ordinary
    /// international domain and is deliberately not flagged here; the
    /// whole-script lookalike case is caught by `confusableSkeleton` instead.
    public static func mixesScripts(_ decodedHost: String) -> Bool {
        for label in decodedHost.split(separator: ".") {
            var hasASCIILetter = false, hasNonASCIILetter = false
            for character in label where character.isLetter {
                if character.isASCII { hasASCIILetter = true } else { hasNonASCIILetter = true }
            }
            if hasASCIILetter && hasNonASCIILetter { return true }
        }
        return false
    }
}
