import Foundation

/// The protection categories BrowseGuard can enforce.
///
/// These mirror the toggles a user sees in the UI. Every blocklist entry and
/// every heuristic finding is attributed to exactly one category so the user
/// can turn off a class of blocking without losing the rest.
public enum ThreatCategory: String, CaseIterable, Codable, Sendable, Identifiable {
    /// Known malware distribution, exploit kits, and C2 hosts.
    case malware
    /// Phishing, tech-support scams, fake stores, and fraud.
    case scam
    /// Advertising networks and ad serving.
    case advertising
    /// Analytics, fingerprinting, and cross-site tracking.
    case tracking
    /// Clickbait, chumboxes, and content-recommendation farms.
    case clickbait
    /// In-browser cryptocurrency miners.
    case cryptojacking
    /// Potentially unwanted programs and bundleware download portals.
    case pup
    /// Not a threat at all — a site the user chose to block themselves.
    /// Carried as a category so user blocks log and count like everything else.
    case userBlocked

    public var id: String { rawValue }

    /// Categories the user switches on and off in "What to Block".
    ///
    /// `userBlocked` is excluded: a switch that turns off the list you built
    /// yourself would be confusing, and removing an entry is the clear way to
    /// undo one.
    public static var toggleable: [ThreatCategory] {
        allCases.filter { $0 != .userBlocked }
    }

    public var title: String {
        switch self {
        case .malware: "Malware"
        case .scam: "Scams & Phishing"
        case .advertising: "Ads"
        case .tracking: "Trackers"
        case .clickbait: "Clickbait"
        case .cryptojacking: "Cryptojacking"
        case .pup: "Unwanted Programs"
        case .userBlocked: "Blocked by You"
        }
    }

    public var detail: String {
        switch self {
        case .malware: "Sites that deliver viruses, trojans, and exploit kits."
        case .scam: "Fake login pages, tech-support fraud, and phishing."
        case .advertising: "Ad networks and the requests that serve banners."
        case .tracking: "Analytics and fingerprinting scripts that follow you."
        case .clickbait: "Chumbox widgets and low-quality content farms."
        case .cryptojacking: "Scripts that mine cryptocurrency using your device."
        case .pup: "Bundleware and download portals that push junk software."
        case .userBlocked: "Sites you added to your own block list."
        }
    }

    public var symbolName: String {
        switch self {
        case .malware: "ladybug.fill"
        case .scam: "exclamationmark.shield.fill"
        case .advertising: "rectangle.on.rectangle.slash.fill"
        case .tracking: "eye.slash.fill"
        case .clickbait: "hand.tap.fill"
        case .cryptojacking: "cpu.fill"
        case .pup: "arrow.down.app.fill"
        case .userBlocked: "hand.raised.slash.fill"
        }
    }

    /// Categories that block active harm. These stay on unless the user very
    /// deliberately turns them off, and the UI warns when they do.
    public var isSecurityCritical: Bool {
        switch self {
        case .malware, .scam, .cryptojacking: true
        case .advertising, .tracking, .clickbait, .pup, .userBlocked: false
        }
    }

    /// Severity drives block-page copy and how loudly the event is surfaced.
    public var severity: ThreatSeverity {
        switch self {
        case .malware: .critical
        case .scam, .cryptojacking: .high
        case .pup: .medium
        case .advertising, .tracking, .clickbait, .userBlocked: .low
        }
    }
}

public enum ThreatSeverity: Int, Codable, Sendable, Comparable {
    case low = 0, medium = 1, high = 2, critical = 3

    public static func < (lhs: ThreatSeverity, rhs: ThreatSeverity) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    public var title: String {
        switch self {
        case .low: "Low"
        case .medium: "Medium"
        case .high: "High"
        case .critical: "Critical"
        }
    }
}
