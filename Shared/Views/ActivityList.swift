import SwiftUI

/// A single row in the activity log.
public struct BlockEventRow: View {
    let event: BlockEvent

    public init(event: BlockEvent) {
        self.event = event
    }

    public var body: some View {
        HStack(spacing: 12) {
            Image(systemName: event.category.symbolName)
                .foregroundStyle(Theme.color(for: event.severity))
                .frame(width: 28)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 2) {
                Text(event.host)
                    .font(.body)
                    .lineLimit(1)
                    .truncationMode(.middle)
                HStack(spacing: 6) {
                    Text(event.category.title)
                    if let source = event.source {
                        Text("·")
                        Text(source)
                    }
                    if event.wasBypassed {
                        Text("·")
                        Text("You continued anyway")
                            .foregroundStyle(.orange)
                    }
                }
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)
            }

            Spacer(minLength: 8)

            Text(event.timestamp, format: .relative(presentation: .numeric, unitsStyle: .narrow))
                .font(.caption)
                .foregroundStyle(.tertiary)
                .monospacedDigit()
        }
        .padding(.vertical, 4)
        .accessibilityElement(children: .combine)
        .accessibilityLabel(
            "\(event.host), \(event.category.title), \(event.timestamp.formatted(date: .abbreviated, time: .shortened))"
        )
    }
}

/// The shared activity log body. Each platform wraps it in its own container.
public struct ActivityListView: View {
    let events: [BlockEvent]
    let limit: Int?

    public init(events: [BlockEvent], limit: Int? = nil) {
        self.events = events
        self.limit = limit
    }

    private var visible: [BlockEvent] {
        let sorted = events.sorted { $0.timestamp > $1.timestamp }
        guard let limit else { return sorted }
        return Array(sorted.prefix(limit))
    }

    public var body: some View {
        if visible.isEmpty {
            ContentUnavailableView(
                "Nothing blocked yet",
                systemImage: "checkmark.shield",
                description: Text("Sites BrowseGuard stops will show up here.")
            )
        } else {
            ForEach(visible) { event in
                BlockEventRow(event: event)
            }
        }
    }
}
