import Foundation
import os
#if canImport(UIKit)
import UIKit
#endif

/// Hands Safari the compiled rule file.
///
/// Safari asks for this once when the extension is enabled and again every time
/// `SFContentBlockerManager.reloadContentBlocker` is called. The rules
/// themselves live in the App Group so the host app can recompile them at any
/// time without shipping an app update — the extension bundle only carries a
/// baseline for the case where the app has never run.
///
/// Shared verbatim by the iOS and macOS content blocker targets.
final class ContentBlockerRequestHandler: NSObject, NSExtensionRequestHandling {

    private let log = Logger(subsystem: "com.mybrightzone.BrowseGuard", category: "ContentBlocker")

    func beginRequest(with context: NSExtensionContext) {
        guard let url = ruleFileURL() else {
            log.error("No rule file available; returning an empty response")
            context.completeRequest(returningItems: [], completionHandler: nil)
            return
        }

        // Logged on the success path too, not just on failure. Safari gives no
        // feedback when it is unhappy with what we hand it — the symptom is a
        // reload that simply never returns — so the only way to tell "we served
        // the wrong file" from "Safari never asked" is to say what we served.
        let size = (try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? -1
        log.info("Serving \(url.lastPathComponent, privacy: .public) (\(size) bytes) from \(url.deletingLastPathComponent().path, privacy: .public)")

        guard let attachment = NSItemProvider(contentsOf: url) else {
            log.error("Could not create an item provider for the rule file")
            context.completeRequest(returningItems: [], completionHandler: nil)
            return
        }

        let item = NSExtensionItem()
        item.attachments = [attachment]
        context.completeRequest(returningItems: [item], completionHandler: nil)
        log.info("Handed the rule file to Safari")
    }

    /// Prefers the App Group copy the app compiled; falls back to the baseline
    /// inside the extension bundle.
    ///
    /// The size check matters: WebKit rejects the *whole* list if the JSON is
    /// truncated, which silently disables the blocker. An interrupted write
    /// would otherwise leave the user unprotected with no visible symptom.
    /// Above this we refuse the shared file and serve the bundled baseline.
    ///
    /// iOS gives a content blocker extension a much smaller memory allowance
    /// than the app, and handing Safari an oversized rule set gets this process
    /// killed — after which the user has *no* blocking at all. A stale or
    /// over-large compile is better degraded than fatal, so the smaller
    /// baseline wins over a file this process may not survive delivering.
    ///
    /// The app's own compiler budgets well under this; exceeding it means the
    /// container still holds a rule set from an older build.
    private static let maximumRuleFileBytes = 2 * 1024 * 1024

    private func ruleFileURL() -> URL? {
        let bundled = Bundle.main.url(forResource: "blockerList", withExtension: "json")

        // A lapsed subscription is enforced here as well as in the app. The rule
        // file on disk is the real one until the app next recompiles, and the app
        // may be closed when the subscription ends, so without this check Safari
        // would keep filtering after the user stopped paying.
        guard let entitlementURL = AppGroup.File.entitlement.url,
              EntitlementRecord.load(from: entitlementURL)?.isActive() == true
        else {
            log.notice("No active subscription; serving the no-op rule set")
            return Bundle.main.url(forResource: "noRules", withExtension: "json")
        }

        guard let shared = AppGroup.File.compiledRules.url,
              let size = try? shared.resourceValues(forKeys: [.fileSizeKey]).fileSize,
              size > 2
        else {
            log.notice("No shared rule list; falling back to the bundled baseline")
            return bundled
        }

        if size > Self.maximumRuleFileBytes {
            log.error("""
                Shared rule list is \(size) bytes, over the \(Self.maximumRuleFileBytes) byte \
                ceiling — serving the bundled baseline instead. Run the app to recompile.
                """)
            return bundled
        }

        return shared
    }
}
