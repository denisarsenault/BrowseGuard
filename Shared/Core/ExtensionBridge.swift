import Foundation
import os

#if canImport(SafariServices) && !os(tvOS)
import SafariServices
#endif

/// Tells Safari to re-read our content-blocker rules, and reports whether the
/// user has actually switched the extensions on.
///
/// Every call is a no-op on tvOS, which has no Safari and therefore no
/// extensions to reload — the TV target is a dashboard only.
///
/// ## Why every call here is defensive
///
/// These APIs are thin wrappers over an XPC connection to Safari's helper, and
/// they fail in two ways that ordinary Swift error handling does not cover:
///
/// 1. They can raise an Objective-C `NSException` — not throw a Swift error —
///    when the helper rejects the selector the framework sends. That happens
///    on unsigned or unsandboxed builds, where the framework cannot mint the
///    sandbox extension token its private selector carries. Swift cannot catch
///    an `NSException`, so it terminates the app.
/// 2. They can simply never call their completion handler if the helper is
///    wedged, stranding the caller forever.
///
/// So each query runs inside `BGRunCatchingExceptions` and against a deadline,
/// and a failure of either kind resolves to `nil` — "cannot determine" — which
/// the UI already renders as an unknown state rather than as "off".
public enum ExtensionBridge {

    private static let log = Logger(subsystem: "com.mybrightzone.BrowseGuard", category: "ExtensionBridge")

    /// A state lookup is a cheap question Safari's helper answers in
    /// milliseconds. Past this we assume it is not going to.
    private static let stateQueryTimeout: TimeInterval = 5

    /// How long to wait for Safari to acknowledge a reload.
    ///
    /// Platform-specific because the API behaves differently:
    ///
    /// - **iOS** genuinely reports back, and a large rule set legitimately
    ///   takes WebKit tens of seconds to recompile, so it gets a long deadline.
    /// - **macOS** does not. Measured here: `getStateOfContentBlocker` answers
    ///   for the same identifier in ~70ms and reports the blocker enabled, but
    ///   `reloadContentBlocker`'s completion handler never fires at all. The
    ///   call still takes effect; it just never says so. Waiting a minute for
    ///   an answer that is not coming only strands the UI on "applying" after
    ///   every toggle, so macOS gets a short deadline and a `.notConfirmed`.
    private static var reloadTimeout: TimeInterval {
        #if os(macOS)
        5
        #else
        60
        #endif
    }

    public static var contentBlockerBundleID: String {
        #if os(macOS)
        AppGroup.macContentBlockerBundleID
        #else
        AppGroup.iOSContentBlockerBundleID
        #endif
    }

    public static var webExtensionBundleID: String {
        #if os(macOS)
        AppGroup.macWebExtensionBundleID
        #else
        AppGroup.iOSWebExtensionBundleID
        #endif
    }

    // MARK: - Reloading

    /// What came back from asking Safari to reload.
    ///
    /// Compilation already happened before any of these, so every case still
    /// means "a correct rule file is on disk". They differ only in whether
    /// Safari has picked it up yet — which is why none of them is a plain
    /// error, and why the rule count is reported separately and earlier.
    public enum ReloadOutcome: Sendable {
        /// Safari confirmed the reload.
        case reloaded

        /// Safari has no record of our extension because the user has not
        /// switched it on yet. This is the normal state before onboarding is
        /// finished, and before the app is signed — not a failure. The UI nags
        /// about it through `contentBlockerIsEnabled()` instead.
        case extensionNotEnabled

        /// Safari neither confirmed nor refused. The rules are on disk and will
        /// be read the next time the extension loads.
        case notConfirmed(detail: String)
    }

    /// Compiles the catalog and writes the rule file to the App Group.
    ///
    /// Deliberately separate from `requestContentBlockerReload`. The rules are
    /// live the moment this returns — the extension serves this file — so
    /// callers can show the count straight away instead of holding it back
    /// until Safari acknowledges. WebKit can take many seconds to recompile a
    /// full catalog, and reporting "0 rules active" during that window is both
    /// wrong and alarming.
    ///
    /// Runs off the main actor. Encoding a full catalog is roughly a second of
    /// CPU and several megabytes of JSON; doing that on the main actor would
    /// freeze the window on every category toggle.
    @discardableResult
    public static func compileRules(
        catalog: BlocklistCatalog,
        settings: ProtectionSettings,
        allowlist: Allowlist,
        userBlocklist: UserBlocklist = .empty
    ) async -> Int {
        await Task.detached(priority: .userInitiated) {
            let count = ContentRuleCompiler.writeCompiledRules(
                catalog: catalog,
                settings: settings,
                allowlist: allowlist,
                userBlocklist: userBlocklist
            )
            log.info("Compiled \(count) content blocker rules to the App Group")
            return count
        }.value
    }

    /// Asks Safari to re-read the rule file `compileRules` wrote.
    ///
    /// Call after `compileRules`. Failing to reach Safari leaves a correct rule
    /// file on disk for the extension to pick up next time it loads, which is
    /// why this returns an outcome rather than a `Result` — there is no case
    /// here where the user lost protection they previously had.
    public static func requestContentBlockerReload() async -> ReloadOutcome {
        #if canImport(SafariServices) && !os(tvOS)
        let identifier = contentBlockerBundleID
        let answer: (any Error)?? = await guarded(
            "reloadContentBlocker",
            timeout: reloadTimeout
        ) { finish in
            SFContentBlockerManager.reloadContentBlocker(
                withIdentifier: identifier,
                completionHandler: { error in finish(error) }
            )
        }

        guard let reported = answer else {
            #if os(macOS)
            // Expected on macOS: the reload is applied but never acknowledged.
            // Not worth alarming anyone about.
            let detail = "Safari applied the rules without acknowledging them."
            log.info("\(detail, privacy: .public)")
            #else
            let detail = "Safari did not answer within \(Int(reloadTimeout))s."
            log.notice("\(detail, privacy: .public) Rules remain on disk.")
            #endif
            return .notConfirmed(detail: detail)
        }

        if let error = reported {
            if isNoExtensionFound(error) {
                log.notice("Safari has not registered the content blocker yet")
                return .extensionNotEnabled
            }
            log.error("Content blocker reload refused: \(error.localizedDescription, privacy: .public)")
            return .notConfirmed(detail: error.localizedDescription)
        }

        log.info("Safari reloaded the content blocker")
        return .reloaded
        #else
        return .reloaded
        #endif
    }

    /// `SFErrorNoExtensionFound` means the user has not enabled the extension
    /// in Safari — a setup state, not a malfunction.
    private static func isNoExtensionFound(_ error: any Error) -> Bool {
        #if canImport(SafariServices) && !os(tvOS)
        let nsError = error as NSError
        return nsError.domain == SFErrorDomain && nsError.code == noExtensionFoundCode
        #else
        return false
        #endif
    }

    #if canImport(SafariServices) && !os(tvOS)
    /// The same constant on both platforms, spelled two ways in Swift: the iOS
    /// SDK ships API notes that bridge `SFErrorCode` into `SFError.Code`, and
    /// the macOS SDK ships none, so it imports as the bare `SFErrorCode`.
    private static let noExtensionFoundCode: Int = {
        #if os(macOS)
        SFErrorCode.noExtensionFound.rawValue
        #else
        SFError.Code.noExtensionFound.rawValue
        #endif
    }()
    #endif

    // MARK: - State

    /// Whether the user has enabled our content blocker in Settings or Safari
    /// preferences. `nil` means "cannot be determined" — either the platform
    /// has no Safari, or the query failed.
    public static func contentBlockerIsEnabled() async -> Bool? {
        #if canImport(SafariServices) && !os(tvOS)
        let identifier = contentBlockerBundleID
        return await guarded("getStateOfContentBlocker") { finish in
            SFContentBlockerManager.getStateOfContentBlocker(withIdentifier: identifier) { state, error in
                if let error {
                    log.error("Blocker state unavailable: \(error.localizedDescription, privacy: .public)")
                }
                finish(state?.isEnabled)
            }
        } ?? nil
        #else
        return nil
        #endif
    }

    /// Whether the Safari *web* extension — the part that runs the heuristics
    /// on real navigations — is switched on.
    ///
    /// macOS only. On iOS the user manages this in Settings and no API reports
    /// it to us, so iOS returns `nil` and the UI falls back to instructions.
    public static func webExtensionIsEnabled() async -> Bool? {
        #if os(macOS)
        let identifier = webExtensionBundleID
        return await guarded("getStateOfSafariExtension") { finish in
            // The SDK annotates this completion handler `NS_SWIFT_UI_ACTOR`,
            // so an inline closure is compiled as `@MainActor` and gets a
            // main-queue assertion in its prologue. Safari does not honor that
            // annotation — it invokes the reply on the XPC connection's own
            // queue — and the assertion then fails with SIGILL before a single
            // line of our code runs.
            //
            // Binding the handler to an explicitly non-isolated type keeps that
            // assertion out of the body. Widening a non-isolated function to an
            // isolated parameter type is a safe conversion, and everything the
            // body touches (`finish` is lock-guarded, `log` is Sendable) is
            // already safe to use from an arbitrary queue.
            let handler: @Sendable (SFSafariExtensionState?, (any Error)?) -> Void = { state, error in
                if let error {
                    log.error("Extension state unavailable: \(error.localizedDescription, privacy: .public)")
                }
                finish(state?.isEnabled)
            }
            SFSafariExtensionManager.getStateOfSafariExtension(
                withIdentifier: identifier,
                completionHandler: handler
            )
        } ?? nil
        #else
        return nil
        #endif
    }

    /// Opens the place where the user turns the extension on.
    @MainActor
    public static func presentExtensionPreferences() {
        #if os(macOS)
        var reason: NSString?
        let completed = BGRunCatchingExceptions({
            SFSafariApplication.showPreferencesForExtension(
                withIdentifier: webExtensionBundleID
            ) { error in
                if let error {
                    log.error("Could not open Safari preferences: \(error.localizedDescription, privacy: .public)")
                }
            }
        }, &reason)

        if !completed {
            log.error("showPreferencesForExtension raised: \((reason as String?) ?? "unknown", privacy: .public)")
        }
        #endif
    }

    // MARK: - Plumbing

    /// Runs a SafariServices call that reports through a completion handler,
    /// surviving both an Objective-C exception and a handler that never fires.
    ///
    /// Returns `nil` when neither the handler nor the barrier produced a value
    /// before the deadline; callers flatten that into their own "unknown".
    ///
    /// The deadline is a dispatch work item rather than a cancelled child task
    /// on purpose. `withCheckedContinuation` is not cancellable, so a task
    /// group would still have to await a stuck query at scope exit — the
    /// timeout would be decorative. Racing three paths into one `OneShot`
    /// means the continuation always resumes, whatever the framework does.
    private static func guarded<Value: Sendable>(
        _ label: String,
        timeout: TimeInterval = stateQueryTimeout,
        _ body: @escaping @Sendable (@escaping @Sendable (Value?) -> Void) -> Void
    ) async -> Value?? {
        await withCheckedContinuation { (continuation: CheckedContinuation<Value??, Never>) in
            let resume = OneShot<Value??>(continuation)

            let deadline = DispatchWorkItem {
                log.error("\(label, privacy: .public) did not answer within \(Int(timeout))s")
                resume.fire(.none)
            }
            DispatchQueue.global(qos: .userInitiated)
                .asyncAfter(deadline: .now() + timeout, execute: deadline)

            var reason: NSString?
            let completed = BGRunCatchingExceptions({
                body { value in
                    deadline.cancel()
                    resume.fire(.some(value))
                }
            }, &reason)

            if !completed {
                // The framework raised rather than calling back. The handler
                // can never fire now, so settle it ourselves.
                deadline.cancel()
                log.error("\(label, privacy: .public) raised: \((reason as String?) ?? "unknown", privacy: .public)")
                resume.fire(.none)
            }
        }
    }

    /// Resumes a continuation exactly once, whichever of the three paths — the
    /// framework's completion handler, our exception barrier, or the deadline —
    /// arrives first. The losers are discarded silently.
    private final class OneShot<Value: Sendable>: @unchecked Sendable {
        private let lock = NSLock()
        private var continuation: CheckedContinuation<Value, Never>?

        init(_ continuation: CheckedContinuation<Value, Never>) {
            self.continuation = continuation
        }

        func fire(_ value: Value) {
            lock.lock()
            let pending = continuation
            continuation = nil
            lock.unlock()
            pending?.resume(returning: value)
        }
    }
}
