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

    /// The schema this file was written with. Persisted so a later build
    /// can tell which categories are genuinely new. See
    /// `currentSchemaVersion`.
    public private(set) var schemaVersion: Int

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
        autoUpdatesEnabled: Bool = true,
        schemaVersion: Int = ProtectionSettings.currentSchemaVersion
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
        self.schemaVersion = schemaVersion
    }

    public static let `default` = ProtectionSettings()

    public func isEnabled(_ category: ThreatCategory) -> Bool {
        guard isProtectionEnabled else { return false }
        // Categories the user cannot switch off are never looked up in
        // `enabledCategories`. Reading them from it meant that settings saved
        // before such a category existed reported it disabled forever — which
        // is how "Blocked by You" came to render greyed out while happily
        // blocking eight sites.
        guard ThreatCategory.toggleable.contains(category) else { return true }
        return enabledCategories.contains(category)
    }

    // MARK: - Schema

    /// Bumped whenever a category is added, so existing installs can tell
    /// "the user switched this off" apart from "this did not exist yet".
    /// Without it a new protection silently stays off for everyone who already
    /// had the app — the worst possible default for a security feature.
    public static let currentSchemaVersion = 2

    /// The schema version each category first shipped in. A category whose
    /// entry here is newer than the version a settings file was written with
    /// was never a choice its owner made, so it defaults on.
    ///
    /// Add a line here whenever you add a case to `ThreatCategory`, and bump
    /// `currentSchemaVersion` to match.
    static let categoryIntroducedIn: [ThreatCategory: Int] = [
        .malware: 1, .scam: 1, .advertising: 1, .tracking: 1,
        .clickbait: 1, .cryptojacking: 1, .pup: 1,
        .userBlocked: 2,
    ]

    // Decoding tolerates settings written by an older build: any key that is
    // missing falls back to its default rather than failing the whole read.
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let fallback = ProtectionSettings()
        isProtectionEnabled = try container.decodeIfPresent(Bool.self, forKey: .isProtectionEnabled) ?? fallback.isProtectionEnabled

        // Absent means "written before versioning", which is schema 1.
        let writtenWith = try container.decodeIfPresent(Int.self, forKey: .schemaVersion) ?? 1

        // Decoded as raw strings rather than as `ThreatCategory` so that a
        // category this build does not know about — a file written by a newer
        // version, or one since removed — is skipped instead of throwing and
        // taking every other setting down with it.
        if let raw = try container.decodeIfPresent([String].self, forKey: .enabledCategories) {
            enabledCategories = Set(raw.compactMap(ThreatCategory.init(rawValue:)))
        } else {
            enabledCategories = fallback.enabledCategories
        }

        // Anything introduced after the version this file was written with was
        // never switched off by anyone — it did not exist. Turn it on.
        for category in ThreatCategory.allCases
        where (Self.categoryIntroducedIn[category] ?? 1) > writtenWith {
            enabledCategories.insert(category)
        }
        schemaVersion = Self.currentSchemaVersion

        heuristicsEnabled = try container.decodeIfPresent(Bool.self, forKey: .heuristicsEnabled) ?? fallback.heuristicsEnabled
        heuristicSensitivity = try container.decodeIfPresent(Sensitivity.self, forKey: .heuristicSensitivity) ?? fallback.heuristicSensitivity
        showsInterstitial = try container.decodeIfPresent(Bool.self, forKey: .showsInterstitial) ?? fallback.showsInterstitial
        logsActivity = try container.decodeIfPresent(Bool.self, forKey: .logsActivity) ?? fallback.logsActivity
        syncsViaICloud = try container.decodeIfPresent(Bool.self, forKey: .syncsViaICloud) ?? fallback.syncsViaICloud
        temporaryBypassDuration = try container.decodeIfPresent(TimeInterval.self, forKey: .temporaryBypassDuration) ?? fallback.temporaryBypassDuration
        autoUpdatesEnabled = try container.decodeIfPresent(Bool.self, forKey: .autoUpdatesEnabled) ?? fallback.autoUpdatesEnabled
    }
}
