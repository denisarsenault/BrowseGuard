import Foundation

/// A single heuristic observation about a host.
public struct HeuristicSignal: Sendable, Hashable, Codable {
    public let rule: String
    public let explanation: String
    /// 0...1. Summed and clamped to produce the host's overall risk.
    public let weight: Double
}

/// Catches hosts that are not on any list yet.
///
/// This is the part that gives BrowseGuard coverage on zero-day phishing:
/// blocklists are always behind, but a domain registered yesterday that reads
/// `app1e-icloud-verify.tk` is detectable from its shape alone.
///
/// Every rule here is cheap and allocation-light because it runs on the
/// navigation path, once per top-level load.
public struct HeuristicScanner: Sendable {

    /// Brands that phishing kits impersonate most often. Typosquat distance is
    /// measured against these.
    public let protectedBrands: [String]

    /// TLDs with a historically poor abuse ratio and near-zero legitimate use
    /// in the traffic this app sees.
    public let highRiskTLDs: Set<String>

    /// Score at or above which a host is treated as a block, not a warning.
    public let blockThreshold: Double

    public init(
        protectedBrands: [String] = HeuristicScanner.defaultBrands,
        highRiskTLDs: Set<String> = HeuristicScanner.defaultHighRiskTLDs,
        blockThreshold: Double = 0.75
    ) {
        self.protectedBrands = protectedBrands
        self.highRiskTLDs = highRiskTLDs
        self.blockThreshold = blockThreshold
    }

    public static let defaultBrands: [String] = [
        "apple", "icloud", "paypal", "amazon", "microsoft", "office365",
        "google", "gmail", "facebook", "instagram", "netflix", "chase",
        "wellsfargo", "bankofamerica", "coinbase", "binance", "dropbox",
        "linkedin", "whatsapp", "steamcommunity", "roblox", "usps", "fedex",
    ]

    public static let defaultHighRiskTLDs: Set<String> = [
        "tk", "ml", "ga", "cf", "gq", "top", "xyz", "work", "click", "link",
        "zip", "mov", "country", "kim", "loan", "download", "review", "rest",
    ]

    /// Runs every rule and returns the signals that fired.
    public func signals(for host: String) -> [HeuristicSignal] {
        guard !URLNormalizer.isIPLiteral(host) else {
            return [HeuristicSignal(
                rule: "ip-literal",
                explanation: "The address is a raw IP with no domain name.",
                weight: 0.35
            )]
        }

        var signals: [HeuristicSignal] = []
        let labels = host.split(separator: ".").map(String.init)
        guard labels.count >= 2 else { return signals }

        let tld = labels[labels.count - 1]
        let registrable = labels[labels.count - 2]

        if highRiskTLDs.contains(tld) {
            signals.append(HeuristicSignal(
                rule: "high-risk-tld",
                explanation: "`.\(tld)` domains are abused far more often than they are used legitimately.",
                weight: 0.3
            ))
        }

        if let decoded = URLNormalizer.decodedIDN(host), decoded != host {
            signals.append(HeuristicSignal(
                rule: "idn-homograph",
                explanation: "The name uses non-Latin characters that render like \"\(decoded)\".",
                weight: 0.45
            ))
        }

        if labels.count >= 5 {
            signals.append(HeuristicSignal(
                rule: "deep-subdomain",
                explanation: "\(labels.count) levels of subdomain — a common way to hide the real domain.",
                weight: 0.2
            ))
        }

        // Brand name in a subdomain but not in the registrable domain:
        // `apple.com.secure-login.ru` is the canonical phishing shape.
        let prefixLabels = labels.dropLast(2).joined(separator: ".")
        if let brand = protectedBrands.first(where: { prefixLabels.contains($0) }),
           !registrable.contains(brand) {
            signals.append(HeuristicSignal(
                rule: "brand-in-subdomain",
                explanation: "\"\(brand)\" appears in the subdomain but the real domain is \"\(registrable).\(tld)\".",
                weight: 0.55
            ))
        }

        // Typosquat: near-miss of a protected brand in the registrable label.
        let core = registrable.replacingOccurrences(of: "-", with: "")
        for brand in protectedBrands where core != brand {
            let distance = Self.damerauLevenshtein(core, brand)
            guard distance > 0, distance <= Self.allowedDistance(for: brand) else { continue }
            signals.append(HeuristicSignal(
                rule: "typosquat",
                explanation: "\"\(registrable)\" is \(distance) character\(distance == 1 ? "" : "s") away from \"\(brand)\".",
                weight: distance == 1 ? 0.6 : 0.4
            ))
            break
        }

        let digits = registrable.filter(\.isNumber).count
        let hyphens = registrable.filter { $0 == "-" }.count
        if registrable.count >= 12, hyphens >= 3 {
            signals.append(HeuristicSignal(
                rule: "hyphen-stuffing",
                explanation: "The domain is padded with \(hyphens) hyphens to look like a phrase.",
                weight: 0.25
            ))
        }
        if digits >= 4, Double(digits) / Double(max(registrable.count, 1)) > 0.3 {
            signals.append(HeuristicSignal(
                rule: "digit-stuffing",
                explanation: "The domain is mostly digits, typical of auto-generated hosts.",
                weight: 0.25
            ))
        }

        if registrable.count >= 12, Self.shannonEntropy(registrable) > 3.6 {
            signals.append(HeuristicSignal(
                rule: "high-entropy",
                explanation: "The name looks machine-generated rather than chosen.",
                weight: 0.3
            ))
        }

        for token in Self.scamTokens where registrable.contains(token) {
            signals.append(HeuristicSignal(
                rule: "scam-token",
                explanation: "Contains \"\(token)\", a word phishing kits lean on.",
                weight: 0.2
            ))
            break
        }

        return signals
    }

    /// Clamped sum of the signals that fired.
    public func risk(for host: String) -> Double {
        min(1.0, signals(for: host).reduce(0) { $0 + $1.weight })
    }

    private static let scamTokens = [
        "verify", "secure", "account", "update", "signin", "login", "wallet",
        "recovery", "support", "billing", "unlock", "confirm", "suspended",
    ]

    /// Short brands need a tighter radius or every four-letter word matches.
    private static func allowedDistance(for brand: String) -> Int {
        switch brand.count {
        case ..<6: 1
        case ..<10: 2
        default: 2
        }
    }

    static func shannonEntropy(_ string: String) -> Double {
        guard !string.isEmpty else { return 0 }
        var counts: [Character: Int] = [:]
        for character in string { counts[character, default: 0] += 1 }
        let total = Double(string.count)
        return counts.values.reduce(0.0) { entropy, count in
            let probability = Double(count) / total
            return entropy - probability * log2(probability)
        }
    }

    /// Optimal string alignment distance — handles the transposition case
    /// (`gogole` vs `google`) that plain Levenshtein scores as 2.
    static func damerauLevenshtein(_ lhs: String, _ rhs: String) -> Int {
        let a = Array(lhs), b = Array(rhs)
        if a.isEmpty { return b.count }
        if b.isEmpty { return a.count }

        var previous = Array(0...b.count)
        var current = [Int](repeating: 0, count: b.count + 1)
        var beforePrevious = [Int](repeating: 0, count: b.count + 1)

        for i in 1...a.count {
            current[0] = i
            for j in 1...b.count {
                let cost = a[i - 1] == b[j - 1] ? 0 : 1
                current[j] = min(
                    previous[j] + 1,          // deletion
                    current[j - 1] + 1,       // insertion
                    previous[j - 1] + cost    // substitution
                )
                if i > 1, j > 1, a[i - 1] == b[j - 2], a[i - 2] == b[j - 1] {
                    current[j] = min(current[j], beforePrevious[j - 2] + cost)
                }
            }
            beforePrevious = previous
            previous = current
            current = [Int](repeating: 0, count: b.count + 1)
        }
        return previous[b.count]
    }
}
