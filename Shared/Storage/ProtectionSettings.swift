import Foundation

/// User-facing configuration, shared with the extensions through the App Group.
public struct ProtectionSettings: Codable, Sendable, Equatable {

    /// Master switch. When off, the content blockers serve an empty rule set
    /// and the web extension stops evaluating navigations.
    public var isProtectionEnabled: Bool

    /// Per-category enablement.
    public var enabledCategories: Set<ThreatCategory>

    /// Run the heuristic scanner on hosts that are not on any list.
    public var heuristicsEnabled: Bool

    /// Risk at or above which an unlisted host is blocked instead of warned.
    /// Exposed as Low/Balanced/Strict in the UI.
    public var heuristicSensitivity: Sensitivity

    /// Show the interstitial. When off, blocks are silent and only appear in
    /// the activity log — useful for ads and trackers, dangerous for malware,
    /// so the UI keeps the interstitial for critical categories regardless.
    public var showsInterstitial: Bool

    /// Keep a local record of what was blocked.
    public var logsActivity: Bool

    /// Mirror settings, allowlist, and counters through iCloud.
    public var syncsViaICloud: Bool

    /// How long a per-site "continue anyway" lasts before it lapses.
    public var temporaryBypassDuration: TimeInterval

    /// Automatically refresh blocklists.
    public var autoUpdatesEnabled: Bool

    public enum Sensitivity: String, Codable, Sendable, CaseIterable, Identifiable {
        case relaxed, balanced, strict

        public var id: String { rawValue }

        public var title: String {
            switch self {
            case .relaxed: "Relaxed"
            case .balanced: "Balanced"
            case .strict: "Strict"
            }
        }

        public var detail: String {
            switch self {
            case .relaxed: "Only block when the evidence is overwhelming. Fewest false positives."
            case .balanced: "Block clear typosquats and homographs. Warn on the rest."
            case .strict: "Block anything that trips two or more heuristics."
            }
        }

        /// Fed to `HeuristicScanner.blockThreshold`.
        public var blockThreshold: Double {
            switch self {
            case .relaxed: 0.9
            case .balanced: 0.75
            case .strict: 0.5
            }
        }

        /// Below this, nothing is surfaced at all.
        public var warnThreshold: Double {
            switch self {
            case .relaxed: 0.6
            case .balanced: 0.45
            case .strict: 0.3
            }
        }
    }

    public init(
        isProtectionEnabled: Bool = true,
        enabledCategories: Set<ThreatCategory> = Set(ThreatCategory.allCases),
        heuristicsEnabled: Bool = true,
        heuristicSensitivity: Sensitivity = .balanced,
        showsInterstitial: Bool = true,
        logsActivity: Bool = true,
        syncsViaICloud: Bool = true,
        temporaryBypassDuration: TimeInterval = 60 * 60,
        autoUpdatesEnabled: Bool = true
    ) {
        self.isProtectionEnabled = isProtectionEnabled
        self.enabledCategories = enabledCategories
        self.heuristicsEnabled = heuristicsEnabled
        self.heuristicSensitivity = heuristicSensitivity
        self.showsInterstitial = showsInterstitial
        self.logsActivity = logsActivity
        self.syncsViaICloud = syncsViaICloud
        self.temporaryBypassDuration = temporaryBypassDuration
        self.autoUpdatesEnabled = autoUpdatesEnabled
    }

    public static let `default` = ProtectionSettings()

    public func isEnabled(_ category: ThreatCategory) -> Bool {
        isProtectionEnabled && enabledCategories.contains(category)
    }

    // Decoding tolerates settings written by an older build: any key that is
    // missing falls back to its default rather than failing the whole read.
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let fallback = ProtectionSettings()
        isProtectionEnabled = try container.decodeIfPresent(Bool.self, forKey: .isProtectionEnabled) ?? fallback.isProtectionEnabled
        enabledCategories = try container.decodeIfPresent(Set<ThreatCategory>.self, forKey: .enabledCategories) ?? fallback.enabledCategories
        heuristicsEnabled = try container.decodeIfPresent(Bool.self, forKey: .heuristicsEnabled) ?? fallback.heuristicsEnabled
        heuristicSensitivity = try container.decodeIfPresent(Sensitivity.self, forKey: .heuristicSensitivity) ?? fallback.heuristicSensitivity
        showsInterstitial = try container.decodeIfPresent(Bool.self, forKey: .showsInterstitial) ?? fallback.showsInterstitial
        logsActivity = try container.decodeIfPresent(Bool.self, forKey: .logsActivity) ?? fallback.logsActivity
        syncsViaICloud = try container.decodeIfPresent(Bool.self, forKey: .syncsViaICloud) ?? fallback.syncsViaICloud
        temporaryBypassDuration = try container.decodeIfPresent(TimeInterval.self, forKey: .temporaryBypassDuration) ?? fallback.temporaryBypassDuration
        autoUpdatesEnabled = try container.decodeIfPresent(Bool.self, forKey: .autoUpdatesEnabled) ?? fallback.autoUpdatesEnabled
    }
}
