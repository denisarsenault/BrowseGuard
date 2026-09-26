import Foundation

/// Turns the catalog into Safari content-blocker JSON.
///
/// Safari's rule format is declarative and evaluated inside WebKit, which is
/// why the content blocker is the fast path: it stops ad, tracker, and miner
/// requests before they are made, with no round trip to our code. The heavier
/// heuristic work happens in the web extension for the top-level navigation
/// only.
public enum ContentRuleCompiler {

    /// WebKit documents a 150,000-rule ceiling, but that number is misleading:
    /// every `url-filter` is compiled into one shared DFA, and the cost grows
    /// far faster than the rule count. In practice Safari spent over a minute
    /// on a 42,000-rule list and then refused it outright with
    /// `SFErrorLoadingInterrupted`, leaving the blocker with no rules at all —
    /// worse than shipping fewer.
    ///
    /// This budget is set where Safari compiles quickly and reliably. Treat it
    /// as a real limit, not a formality.
    public static let ruleLimit = 25_000

    /// Categories that belong in Safari's content blocker.
    ///
    /// The split follows the threat model rather than just size:
    ///
    /// - Ads, trackers, miners, and PUP portals are **sub-resource** threats.
    ///   They arrive as requests made from inside a page you meant to visit,
    ///   so WebKit is the only thing that can stop them before they are sent.
    ///   Their lists are also small.
    /// - Phishing is a **navigation** threat: you follow a link to a fake login
    ///   page. The web extension catches that at `onBeforeNavigate` by asking
    ///   `ProtectionEngine`, which holds the full 40,000-host list and answers
    ///   with a dictionary lookup costing nothing.
    ///
    /// So phishing is deliberately excluded here. It is not unprotected — it is
    /// protected by the path that can actually carry a list that size.
    public static let contentBlockerCategories: Set<ThreatCategory> = [
        .advertising, .tracking, .clickbait, .cryptojacking, .pup, .malware, .userBlocked,
    ]

    public struct Rule: Codable, Sendable {
        public struct Trigger: Codable, Sendable {
            public var urlFilter: String
            public var ifDomain: [String]?
            public var unlessDomain: [String]?
            public var resourceType: [String]?
            public var loadType: [String]?

            enum CodingKeys: String, CodingKey {
                case urlFilter = "url-filter"
                case ifDomain = "if-domain"
                case unlessDomain = "unless-domain"
                case resourceType = "resource-type"
                case loadType = "load-type"
            }
        }

        public struct Action: Codable, Sendable {
            public var type: String
            public var selector: String?
        }

        public var trigger: Trigger
        public var action: Action
    }

    /// Compiles the enabled portion of the catalog.
    ///
    /// - Parameters:
    ///   - catalog: every loaded feed.
    ///   - settings: decides which categories contribute rules.
    ///   - allowlist: becomes `ignore-previous-rules` entries so a user's
    ///     allowlisted host is exempt inside WebKit too, not just in our code.
    public static func compile(
        catalog: BlocklistCatalog,
        settings: ProtectionSettings,
        allowlist: Allowlist,
        userBlocklist: UserBlocklist = .empty
    ) -> [Rule] {
        guard settings.isProtectionEnabled else { return [] }

        let active = catalog.allEntries
            .filter { settings.isEnabled($0.category) }
            .filter { contentBlockerCategories.contains($0.category) }
            .sorted { lhs, rhs in
                // Keep the most dangerous rules when we have to truncate.
                if lhs.category.severity != rhs.category.severity {
                    return lhs.category.severity > rhs.category.severity
                }
                return lhs.host < rhs.host
            }

        let allowlistHosts = allowlist.activeItems.map(\.host)
        let budget = ruleLimit - max(allowlistHosts.count, 1) - Self.cosmeticRules.count
        var rules: [Rule] = []
        rules.reserveCapacity(min(active.count, budget) + allowlistHosts.count + 1)

        for entry in active.prefix(budget) {
            rules.append(blockRule(for: entry))
        }

        if settings.isEnabled(.advertising) || settings.isEnabled(.clickbait) {
            rules.append(contentsOf: cosmeticRules)
        }

        // `ignore-previous-rules` only undoes rules above it, so the allowlist
        // exemption goes after everything it is meant to exempt.
        if !allowlistHosts.isEmpty {
            rules.append(Rule(
                trigger: .init(
                    urlFilter: ".*",
                    ifDomain: allowlistHosts.map { "*\($0)" },
                    unlessDomain: nil,
                    resourceType: nil,
                    loadType: nil
                ),
                action: .init(type: "ignore-previous-rules", selector: nil)
            ))
        }

        // …and the user's own blocks go after *that*, so they survive it. Same
        // precedence the engine applies, which matters: if WebKit and the
        // engine disagreed, a site would be blocked on one path and allowed on
        // the other depending on how it was loaded.
        for host in userBlocklist.hosts {
            rules.append(blockRule(for: BlocklistEntry(host: host, category: .userBlocked)))
        }

        return rules
    }

    private static func blockRule(for entry: BlocklistEntry) -> Rule {
        // `^https?://([^/]+\.)?host` anchors the match at the host portion so
        // `evil.com` does not match `notevil.com.example.org/path`.
        let escaped = NSRegularExpression.escapedPattern(for: entry.host)
        return Rule(
            trigger: .init(
                urlFilter: "^https?://([^/]+\\.)?\(escaped)[:/]",
                ifDomain: nil,
                unlessDomain: nil,
                resourceType: nil,
                loadType: nil
            ),
            action: .init(type: "block", selector: nil)
        )
    }

    /// Hides the containers left behind after the network request is blocked,
    /// so the page does not keep a blank rectangle where the ad was.
    private static let cosmeticRules: [Rule] = [
        ".ad-slot", ".adsbygoogle", "[id^=\"div-gpt-ad\"]",
        ".taboola", ".OUTBRAIN", ".trc_related_container",
    ].map { selector in
        Rule(
            trigger: .init(
                urlFilter: ".*",
                ifDomain: nil,
                unlessDomain: nil,
                resourceType: nil,
                loadType: nil
            ),
            action: .init(type: "css-display-none", selector: selector)
        )
    }

    /// Compiles and writes the rule file the extensions serve from the App
    /// Group. Returns the number of rules written.
    @discardableResult
    public static func writeCompiledRules(
        catalog: BlocklistCatalog,
        settings: ProtectionSettings,
        allowlist: Allowlist,
        userBlocklist: UserBlocklist = .empty
    ) -> Int {
        let rules = compile(
            catalog: catalog,
            settings: settings,
            allowlist: allowlist,
            userBlocklist: userBlocklist
        )
        // An empty array is valid JSON but WebKit rejects an empty rule list,
        // so protection-off writes one harmless no-op rule instead.
        let payload = rules.isEmpty ? [noOpRule] : rules
        SharedStore.write(payload, to: .compiledRules)
        return rules.count
    }

    /// Matches nothing; keeps the extension loadable while protection is off.
    private static let noOpRule = Rule(
        trigger: .init(
            urlFilter: "^https?://browseguard\\.invalid/never-matches",
            ifDomain: nil,
            unlessDomain: nil,
            resourceType: nil,
            loadType: nil
        ),
        action: .init(type: "block", selector: nil)
    )
}
