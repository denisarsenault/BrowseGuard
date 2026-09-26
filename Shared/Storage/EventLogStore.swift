import Foundation

/// The activity log, capped so it never grows without bound.
///
/// Writes go through `NSFileCoordinator` because the web extension handler and
/// the host app can both append at the same time — the extension runs in its
/// own process and has no idea the app is open.
public enum EventLogStore {

    /// Roughly a month of heavy browsing. Beyond this the oldest events drop.
    public static let capacity = 5_000

    public static func load() -> [BlockEvent] {
        SharedStore.read([BlockEvent].self, from: .events) ?? []
    }

    /// Appends one event and trims to `capacity`. Returns the new log.
    @discardableResult
    public static func append(_ event: BlockEvent) -> [BlockEvent] {
        mutate { events in
            events.append(event)
            if events.count > capacity {
                events.removeFirst(events.count - capacity)
            }
        }
    }

    /// Marks the most recent event for `host` as bypassed, so the UI can show
    /// "you continued past this" rather than a second, duplicate entry.
    @discardableResult
    public static func markBypassed(host: String) -> [BlockEvent] {
        mutate { events in
            guard let index = events.lastIndex(where: { $0.host == host }) else { return }
            events[index].wasBypassed = true
        }
    }

    @discardableResult
    public static func clear() -> [BlockEvent] {
        SharedStore.write([BlockEvent](), to: .events)
        return []
    }

    /// Read-modify-write under a file coordinator so concurrent appends from
    /// the app and the extension do not clobber each other.
    private static func mutate(_ body: (inout [BlockEvent]) -> Void) -> [BlockEvent] {
        guard let url = AppGroup.File.events.url else {
            var events = load()
            body(&events)
            return events
        }

        var result: [BlockEvent] = []
        var coordinationError: NSError?
        NSFileCoordinator().coordinate(
            writingItemAt: url,
            options: .forMerging,
            error: &coordinationError
        ) { _ in
            var events = load()
            body(&events)
            SharedStore.write(events, to: .events)
            result = events
        }

        if let coordinationError {
            SharedStore.log.error(
                "Event log coordination failed: \(coordinationError.localizedDescription, privacy: .public)"
            )
            var events = load()
            body(&events)
            SharedStore.write(events, to: .events)
            return events
        }
        return result
    }
}
