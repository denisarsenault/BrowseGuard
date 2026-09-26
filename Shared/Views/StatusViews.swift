import SwiftUI

/// The big "you are protected" banner at the top of every platform's home.
public struct ProtectionStatusCard: View {
    let isEnabled: Bool
    let isFullyArmed: Bool
    let summary: ActivitySummary
    let ruleCount: Int
    let isApplying: Bool

    public init(
        isEnabled: Bool,
        isFullyArmed: Bool,
        summary: ActivitySummary,
        ruleCount: Int,
        isApplying: Bool = false
    ) {
        self.isEnabled = isEnabled
        self.isFullyArmed = isFullyArmed
        self.summary = summary
        self.ruleCount = ruleCount
        self.isApplying = isApplying
    }

    private var tint: Color {
        if !isEnabled { return Theme.disabled }
        return isFullyArmed ? Theme.safe : .orange
    }

    private var title: String {
        if !isEnabled { return "Protection is off" }
        return isFullyArmed ? "You're protected" : "Finish setup in Safari"
    }

    private var subtitle: String {
        if !isEnabled { return "Turn BrowseGuard on to start filtering." }
        if !isFullyArmed { return "BrowseGuard is ready, but Safari hasn't been given permission yet." }
        // Before the first compile finishes there is genuinely no count to
        // show. Saying so beats "0 rules active", which reads as "you are not
        // protected" when the truth is "not counted yet".
        if isApplying && ruleCount == 0 { return "Compiling rules…" }
        let rules = "\(ruleCount.formatted()) rules active"
        // Rules are already live in the App Group; Safari is catching up.
        if isApplying { return "\(rules) · Safari is applying them…" }
        return "\(rules) · \(summary.totalBlocked.formatted()) blocked all time"
    }

    public var body: some View {
        HStack(spacing: Theme.cardPadding) {
            Image(systemName: isEnabled && isFullyArmed ? "checkmark.shield.fill" : "exclamationmark.shield.fill")
                .font(.system(size: 44))
                .foregroundStyle(tint)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 4) {
                Text(title).font(.headline)
                Text(subtitle)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
        .cardBackground()
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(title). \(subtitle)")
    }
}

/// One number in the stats grid.
public struct StatTile: View {
    let value: Int
    let label: String
    let symbolName: String
    let tint: Color

    public init(value: Int, label: String, symbolName: String, tint: Color) {
        self.value = value
        self.label = label
        self.symbolName = symbolName
        self.tint = tint
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Image(systemName: symbolName)
                .font(.title3)
                .foregroundStyle(tint)
                .accessibilityHidden(true)
            Text(value.formatted())
                .font(.title2.weight(.semibold))
                .monospacedDigit()
                .contentTransition(.numericText())
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(2, reservesSpace: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .cardBackground()
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(value.formatted()) \(label)")
    }
}

/// Per-category totals, sized for whatever platform it lands on.
public struct CategoryStatsGrid: View {
    let summary: ActivitySummary
    let enabledCategories: Set<ThreatCategory>

    public init(summary: ActivitySummary, enabledCategories: Set<ThreatCategory>) {
        self.summary = summary
        self.enabledCategories = enabledCategories
    }

    public var body: some View {
        LazyVGrid(
            columns: [GridItem(.adaptive(minimum: Theme.gridMinimum), spacing: 12)],
            spacing: 12
        ) {
            ForEach(ThreatCategory.allCases) { category in
                StatTile(
                    value: summary.byCategory[category] ?? 0,
                    label: category.title,
                    symbolName: category.symbolName,
                    tint: enabledCategories.contains(category)
                        ? Theme.color(for: category)
                        : Theme.disabled
                )
                .opacity(enabledCategories.contains(category) ? 1 : 0.5)
            }
        }
    }
}
