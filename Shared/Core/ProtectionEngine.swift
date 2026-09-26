import Foundation

/// The single place a block/allow decision is made.
///
/// Immutable and `Sendable` so the app, the content blocker, and the web
/// extension handler all evaluate a host the same way with no shared state
/// and no locking. Build one from a snapshot, ask it questions, throw it away.
public struct ProtectionEngine: Sendable {

    public let settings: ProtectionSettings
    public let catalog: BlocklistCatalog
    public let allowlist: Allowlist
    public let userBlocklist: UserBlocklist
    public let scanner: HeuristicScanner

    public init(
        settings: ProtectionSettings,
        catalog: BlocklistCatalog,
        allowlist: Allowlist,
        userBlocklist: UserBlocklist = .empty,
        scanner: HeuristicScanner? = nil
    ) {
        self.settings = settings
        self.catalog = catalog
        self.allowlist = allowlist
        self.userBlocklist = userBlocklist
        self.scanner = scanner ?? HeuristicScanner(
            blockThreshold: settings.heuristicSensitivity.blockThreshold
        )
    }

    /// Builds an engine from whatever is currently in the App Group.
    /// This is the entry point the extensions use.
    public static func current() -> ProtectionEngine {
        ProtectionEngine(
            settings: SharedStore.settings(),
            catalog: SharedStore.catalog(),
            allowlist: SharedStore.allowlist(),
            userBlocklist: SharedStore.userBlocklist()
        )
    }

    public func evaluate(url: URL, at date: Date = .now) -> Verdict {
        guard let host = URLNormalizer.canonicalHost(of: url) else {
            return Verdict(host: url.absoluteString, decision: .allow)
        }
        return evaluate(host: host, at: date)
    }

    public func evaluate(host rawHost: String, at date: Date = .now) -> Verdict {
        guard let host = URLNormalizer.canonicalHost(of: rawHost) else {
            return .allow(rawHost)
        }

        guard settings.isProtectionEnabled else { return .allow(host) }

        // The user's own block list is checked before the allowlist. Both are
        // the user's instructions, so the tie-break is which one is the more
        // specific, more recent intent — and deliberately blocking a site you
        // once allowed should take effect without having to hunt down the old
        // allowlist entry first.
        if let blocked = userBlocklist.contains(host: host) {
            return Verdict(
                host: host,
                decision: .block,
                category: .userBlocked,
                severity: .low,
                confidence: 1.0,
                source: blocked.note?.isEmpty == false ? blocked.note : "Your block list"
            )
        }

        // The allowlist wins over everything else, including critical categories.
        // That is a deliberate product decision: the user is the last word,
        // but the bypass is time-boxed and the event is still logged.
        if let item = allowlist.contains(host: host, at: date) {
            return Verdict(
                host: host,
                decision: .allowlisted,
                category: item.bypassedCategory,
                source: item.isTemporary ? "Temporary bypass" : "Allowlist"
            )
        }

        if let entry = catalog.match(host: host) {
            guard settings.isEnabled(entry.category) else { return .allow(host) }
            return Verdict(
                host: host,
                decision: .block,
                category: entry.category,
                severity: entry.category.severity,
                confidence: 1.0,
                source: entry.source
            )
        }

        guard settings.heuristicsEnabled else { return .allow(host) }
        return heuristicVerdict(for: host)
    }

    private func heuristicVerdict(for host: String) -> Verdict {
        // Heuristics are a phishing/scam detector, so they are gated on that
        // category rather than on the master heuristics switch alone.
        guard settings.isEnabled(.scam) else { return .allow(host) }

        let signals = scanner.signals(for: host)
        guard !signals.isEmpty else { return .allow(host) }

        let risk = min(1.0, signals.reduce(0) { $0 + $1.weight })
        let sensitivity = settings.heuristicSensitivity

        if risk >= sensitivity.blockThreshold {
            return Verdict(
                host: host,
                decision: .block,
                category: .scam,
                severity: .high,
                confidence: risk,
                signals: signals,
                source: "Heuristics"
            )
        }
        if risk >= sensitivity.warnThreshold {
            return Verdict(
                host: host,
                decision: .warn,
                category: .scam,
                severity: .medium,
                confidence: risk,
                signals: signals,
                source: "Heuristics"
            )
        }
        return .allow(host)
    }

    /// The interstitial is always shown for security-critical blocks even when
    /// the user turned it off — silently swallowing a malware navigation would
    /// leave them wondering why the page is blank.
    public func shouldPresentInterstitial(for verdict: Verdict) -> Bool {
        guard verdict.isBlocking else { return false }
        if let category = verdict.category, category.isSecurityCritical { return true }
        return settings.showsInterstitial
    }
}
