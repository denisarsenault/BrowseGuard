import Foundation

/// Collapses a burst of requests into one run, and never lets two runs overlap.
///
/// Recompiling the content blocker costs a second or two of CPU and several
/// megabytes of JSON. Flipping four category switches in a row should pay that
/// once, not four times.
///
/// Two separate guarantees, and both matter:
///
/// - **Coalescing.** A request arriving inside the delay window replaces the
///   one waiting, so only the last one runs.
/// - **Serialization.** A request arriving *after* a run has already started
///   cannot run alongside it. Without this, two compiles would race and the
///   older one could finish last and overwrite the newer rules — leaving the
///   user with settings they had already changed away from.
///
/// `@MainActor` because the state it guards belongs to the UI layer; the
/// expensive work inside the operation is what hops off the main actor.
@MainActor
public final class CoalescingRunner {

    private let delay: Duration
    /// The run that is waiting out the delay. Cancelled when superseded.
    private var pending: Task<Void, Never>?
    /// The most recently started run. New runs chain behind it.
    private var running: Task<Void, Never>?

    public init(delay: Duration) {
        self.delay = delay
    }

    /// Requests a run after the delay. Supersedes any request still waiting.
    public func schedule(_ operation: @escaping @MainActor () async -> Void) {
        let delay = self.delay
        pending?.cancel()
        pending = Task { [weak self] in
            // Only the wait is cancellable. Once the operation starts it runs
            // to completion — abandoning a half-written rule file partway
            // through would be worse than a redundant compile.
            do {
                try await Task.sleep(for: delay)
            } catch {
                return
            }
            guard let self, !Task.isCancelled else { return }
            await self.enqueue(operation)
        }
    }

    /// Runs without waiting — for launch, where there is nothing to coalesce
    /// with and delaying only makes the app look empty for longer. Still
    /// serialized against anything already in flight.
    public func runNow(_ operation: @escaping @MainActor () async -> Void) async {
        pending?.cancel()
        pending = nil
        await enqueue(operation)
    }

    /// True while something is waiting or running.
    public var isBusy: Bool {
        pending != nil || running != nil
    }

    private func enqueue(_ operation: @escaping @MainActor () async -> Void) async {
        let previous = running
        let task = Task { @MainActor in
            // Chaining on the previous run is what preserves ordering.
            await previous?.value
            await operation()
        }
        running = task
        await task.value
        if running == task { running = nil }
    }
}
