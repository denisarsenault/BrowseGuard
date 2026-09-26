import Foundation

/// What BrowseGuard decided about a navigation.
public struct Verdict: Sendable, Codable, Hashable {

    public enum Decision: String, Sendable, Codable {
        /// Nothing known or suspected. Let it through silently.
        case allow
        /// Blocked outright; the user sees the interstitial.
        case block
        /// Suspicious but not certain. The user sees the interstitial with
        /// softer copy and a clearly-offered "continue" action.
        case warn
        /// The user (or an enterprise policy) allowlisted this host.
        case allowlisted
    }

    public let host: String
    public let decision: Decision
    public let category: ThreatCategory?
    public let severity: ThreatSeverity
    /// 0...1 confidence. 1.0 for an exact blocklist hit.
    public let confidence: Double
    /// Populated when the verdict came from the heuristic scanner.
    public let signals: [HeuristicSignal]
    /// Feed name for a list hit, or `"Heuristics"`.
    public let source: String?

    public init(
        host: String,
        decision: Decision,
        category: ThreatCategory? = nil,
        severity: ThreatSeverity = .low,
        confidence: Double = 0,
        signals: [HeuristicSignal] = [],
        source: String? = nil
    ) {
        self.host = host
        self.decision = decision
        self.category = category
        self.severity = severity
        self.confidence = confidence
        self.signals = signals
        self.source = source
    }

    public static func allow(_ host: String) -> Verdict {
        Verdict(host: host, decision: .allow)
    }

    public var isBlocking: Bool {
        decision == .block || decision == .warn
    }

    /// Headline for the interstitial.
    public var headline: String {
        switch decision {
        case .block:
            switch category {
            case .malware: "This site distributes malware"
            case .scam: "This site is a known scam"
            case .cryptojacking: "This site mines cryptocurrency"
            case .pup: "This site pushes unwanted software"
            // No threat language here — the user blocked this on purpose, and
            // implying it is dangerous would be a lie.
            case .userBlocked: "You blocked this site"
            case .advertising, .tracking, .clickbait: "Blocked by BrowseGuard"
            case nil: "Blocked by BrowseGuard"
            }
        case .warn: "This site looks suspicious"
        case .allow, .allowlisted: "Allowed"
        }
    }

    /// Body copy for the interstitial: the list source, or the heuristic
    /// signals written out so the user can judge for themselves.
    public var explanation: String {
        switch decision {
        case .block where category == .userBlocked:
            "\(host) is on your own block list. Nothing suggests it is dangerous — you chose to block it."
        case .block where !signals.isEmpty, .warn:
            signals.map(\.explanation).joined(separator: " ")
        case .block:
            "\(host) is on the \(source ?? "BrowseGuard") \(category?.title.lowercased() ?? "threat") list."
        case .allow:
            "No threats detected."
        case .allowlisted:
            "You added \(host) to your allowlist."
        }
    }
}
