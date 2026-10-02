import Foundation
import SafariServices
import os

/// The native half of the Safari web extension.
///
/// The JavaScript side sees every top-level navigation but has no access to the
/// blocklists, the heuristics, or the user's settings — those live in the App
/// Group, which only native code can read. So the extension asks this handler
/// for a verdict on each navigation and acts on the answer.
///
/// Keeping the decision native is deliberate: the rules never have to be
/// serialized into the browser process, the heuristics cannot be read or
/// tampered with by a page, and the same `ProtectionEngine` that the app shows
/// in its UI is the one that actually decides.
final class SafariWebExtensionHandler: NSObject, NSExtensionRequestHandling {

    private let log = Logger(subsystem: "com.mybrightzone.BrowseGuard", category: "WebExtension")

    /// Message names the JavaScript side may send.
    private enum Action: String {
        case evaluate      // { host } -> verdict
        case report        // { host, category, decision } -> ok
        case bypass        // { host, category } -> allowlist updated
        case block         // { host } -> added to the user block list
        case unblock       // { host } -> removed from it
        case settings      // -> the settings the content script needs
        case ping          // health check used by the popup
    }

    func beginRequest(with context: NSExtensionContext) {
        let response = NSExtensionItem()
        response.userInfo = [SFExtensionMessageKey: handle(message(from: context))]
        context.completeRequest(returningItems: [response], completionHandler: nil)
    }

    private func message(from context: NSExtensionContext) -> [String: Any] {
        guard let item = context.inputItems.first as? NSExtensionItem,
              let payload = item.userInfo?[SFExtensionMessageKey] as? [String: Any]
        else { return [:] }
        return payload
    }

    private func handle(_ message: [String: Any]) -> [String: Any] {
        guard let raw = message["action"] as? String, let action = Action(rawValue: raw) else {
            return ["ok": false, "error": "unknown action"]
        }

        switch action {
        case .ping:
            return ["ok": true, "version": Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") ?? "?"]

        case .settings:
            let settings = SharedStore.settings()
            return [
                "ok": true,
                "enabled": settings.isProtectionEnabled,
                "showsInterstitial": settings.showsInterstitial,
                "logsActivity": settings.logsActivity,
                "bypassDuration": settings.temporaryBypassDuration,
            ]

        case .evaluate:
            guard let host = message["host"] as? String else {
                return ["ok": false, "error": "missing host"]
            }
            let engine = ProtectionEngine.current()
            let verdict = engine.evaluate(host: host)

            // Log here rather than trusting the JS side to report back: a page
            // that navigates away immediately would otherwise never be recorded.
            if verdict.isBlocking, engine.settings.logsActivity, let event = BlockEvent(verdict: verdict) {
                EventLogStore.append(event)
            }

            return [
                "ok": true,
                "decision": verdict.decision.rawValue,
                "host": verdict.host,
                "category": verdict.category?.rawValue ?? "",
                "categoryTitle": verdict.category?.title ?? "",
                "severity": verdict.severity.rawValue,
                "confidence": verdict.confidence,
                "headline": verdict.headline,
                "explanation": verdict.explanation,
                "source": verdict.source ?? "",
                "signals": verdict.signals.map { ["rule": $0.rule, "explanation": $0.explanation] },
                "showInterstitial": engine.shouldPresentInterstitial(for: verdict),
            ]

        case .report:
            guard SharedStore.settings().logsActivity,
                  let host = message["host"] as? String,
                  let categoryRaw = message["category"] as? String,
                  let category = ThreatCategory(rawValue: categoryRaw)
            else { return ["ok": true] }

            EventLogStore.append(BlockEvent(
                host: host,
                category: category,
                decision: .block,
                severity: category.severity,
                source: message["source"] as? String
            ))
            return ["ok": true]

        case .block:
            guard let host = message["host"] as? String else {
                return ["ok": false, "error": "missing host"]
            }
            let list = UserBlocklistStore.add(host: host)
            log.notice("User blocked a host from the extension")
            return ["ok": true, "count": list.items.count]

        case .unblock:
            guard let host = message["host"] as? String else {
                return ["ok": false, "error": "missing host"]
            }
            let list = UserBlocklistStore.remove(host: host)
            return ["ok": true, "count": list.items.count]

        case .bypass:
            guard let host = message["host"] as? String else {
                return ["ok": false, "error": "missing host"]
            }
            let category = (message["category"] as? String).flatMap(ThreatCategory.init(rawValue:))
            let duration = SharedStore.settings().temporaryBypassDuration
            AllowlistStore.addTemporaryBypass(host: host, category: category, duration: duration)
            EventLogStore.markBypassed(host: host)
            log.notice("User bypassed a block for a host")
            return ["ok": true, "expiresIn": duration]
        }
    }
}
