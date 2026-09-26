import Foundation

/// One entry in the activity log.
///
/// Records only the host — never the full URL, query string, or page title.
/// That is both a privacy decision and what keeps the log small enough to sync.
public struct BlockEvent: Codable, Sendable, Hashable, Identifiable {
    public let id: UUID
    public let host: String
    public let category: ThreatCategory
    public let decision: Verdict.Decision
    public let severity: ThreatSeverity
    public let timestamp: Date
    public let source: String?
    /// True when the user pressed "Continue anyway" on this block.
    public var wasBypassed: Bool

    public init(
        id: UUID = UUID(),
        host: String,
        category: ThreatCategory,
        decision: Verdict.Decision,
        severity: ThreatSeverity,
        timestamp: Date = .now,
        source: String? = nil,
        wasBypassed: Bool = false
    ) {
        self.id = id
        self.host = host
        self.category = category
        self.decision = decision
        self.severity = severity
        self.timestamp = timestamp
        self.source = source
        self.wasBypassed = wasBypassed
    }

    public init?(verdict: Verdict, at timestamp: Date = .now) {
        guard verdict.isBlocking, let category = verdict.category else { return nil }
        self.init(
            host: verdict.host,
            category: category,
            decision: verdict.decision,
            severity: verdict.severity,
            timestamp: timestamp,
            source: verdict.source
        )
    }
}

/// Rolled-up counters for the dashboard, cheap to compute and cheap to sync.
public struct ActivitySummary: Codable, Sendable, Equatable {
    public var totalBlocked: Int
    public var byCategory: [ThreatCategory: Int]
    public var lastBlockedAt: Date?
    public var criticalBlockedToday: Int

    public init(
        totalBlocked: Int = 0,
        byCategory: [ThreatCategory: Int] = [:],
        lastBlockedAt: Date? = nil,
        criticalBlockedToday: Int = 0
    ) {
        self.totalBlocked = totalBlocked
        self.byCategory = byCategory
        self.lastBlockedAt = lastBlockedAt
        self.criticalBlockedToday = criticalBlockedToday
    }

    public static func summarize(_ events: [BlockEvent], calendar: Calendar = .current) -> ActivitySummary {
        var summary = ActivitySummary()
        summary.totalBlocked = events.count
        for event in events {
            summary.byCategory[event.category, default: 0] += 1
            if summary.lastBlockedAt.map({ event.timestamp > $0 }) ?? true {
                summary.lastBlockedAt = event.timestamp
            }
            if event.severity >= .high, calendar.isDateInToday(event.timestamp) {
                summary.criticalBlockedToday += 1
            }
        }
        return summary
    }
}
