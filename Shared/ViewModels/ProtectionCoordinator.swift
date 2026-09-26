import Foundation
import Observation
import os

/// The app-side owner of all mutable state.
///
/// Everything the UI binds to lives here, and every mutation funnels through a
/// method that persists to the App Group, recompiles the Safari rules, and
/// pushes to iCloud.
///
/// The extensions only ever *read* settings and the catalog. The two things
/// they may write — an event log append and a "continue anyway" bypass — go
/// through file-coordinated stores, because those happen in another process
/// while this object may be live.
@MainActor
@Observable
public final class ProtectionCoordinator {

    public private(set) var settings: ProtectionSettings
    public private(set) var allowlist: Allowlist
    public private(set) var userBlocklist: UserBlocklist
    public private(set) var events: [BlockEvent]
    public private(set) var catalog: BlocklistCatalog

    /// `nil` until the first check completes, or on platforms that cannot tell.
    public private(set) var contentBlockerEnabled: Bool?
    public private(set) var webExtensionEnabled: Bool?

    public private(set) var compiledRuleCount: Int = 0
    /// Whether Safari confirmed it picked up the last rule compilation. False
    /// simply means "not acknowledged" — the rules are still written to the App
    /// Group either way.
    public private(set) var rulesConfirmedBySafari = false
    /// True while Safari is recompiling. A full catalog takes WebKit a while,
    /// and the UI says so rather than looking stalled.
    public private(set) var isApplyingRules = false
    public private(set) var lastUpdateCheck: Date?
    public private(set) var isUpdating = false
    public private(set) var lastError: String?

    private let updater: BlocklistUpdater
    private let log = Logger(subsystem: "com.mybrightzone.BrowseGuard", category: "Coordinator")

    /// Rule compilation is expensive enough that flipping several switches in
    /// a row must not pay for it several times. Long enough to swallow a burst
    /// of toggles, short enough that a single deliberate change still feels
    /// immediate.
    private let ruleApplier = CoalescingRunner(delay: .milliseconds(400))

    public init(updater: BlocklistUpdater = BlocklistUpdater()) {
        self.updater = updater
        self.settings = SharedStore.settings()
        var storedAllowlist = SharedStore.allowlist()
        storedAllowlist.pruneExpired()
        self.allowlist = storedAllowlist
        self.userBlocklist = SharedStore.userBlocklist()
        self.events = EventLogStore.load()
        self.catalog = updater.resolvedCatalog()
    }

    public var summary: ActivitySummary {
        ActivitySummary.summarize(events)
    }

    public var engine: ProtectionEngine {
        ProtectionEngine(
            settings: settings,
            catalog: catalog,
            allowlist: allowlist,
            userBlocklist: userBlocklist
        )
    }

    /// Protection is only really on when the user has also switched the Safari
    /// extension on — the toggle in our app cannot do that for them.
    public var isFullyArmed: Bool {
        settings.isProtectionEnabled && (contentBlockerEnabled ?? true)
    }

    // MARK: - Lifecycle

    public func bootstrap() async {
        AppGroup.prepareContainer()
        log.info("""
            Bootstrap: \(self.catalog.lists.count) feed(s), \
            \(self.catalog.entryCount) hosts, \
            app group \(AppGroup.identifier, privacy: .public)
            """)
        // Re-read the lists the extensions can also write before persisting
        // anything. This object was constructed when the window opened, which
        // may have been hours ago; in the meantime the web extension may have
        // added a "continue anyway" bypass from another process. Writing our
        // stale in-memory copy over it silently loses the user's choice — and
        // the symptom is baffling, because the block page plainly worked.
        allowlist = SharedStore.allowlist()
        allowlist.pruneExpired()
        userBlocklist = SharedStore.userBlocklist()

        // Persist the baseline so the extensions have something to read on a
        // first launch where the user never opens a settings screen.
        SharedStore.write(catalog.lists, to: .catalog)
        SharedStore.write(settings, to: .settings)
        SharedStore.write(allowlist, to: .allowlist)
        SharedStore.write(userBlocklist, to: .userBlocklist)

        if settings.syncsViaICloud {
            CloudSync.shared.onRemoteChange = { [weak self] in
                self?.pullFromCloud()
            }
            CloudSync.shared.start()
            pullFromCloud()
        }

        await refreshExtensionState()
        await ruleApplier.runNow { [weak self] in await self?.applyRules() }

        if settings.autoUpdatesEnabled {
            await checkForUpdates()
        }
    }

    public func refreshExtensionState() async {
        contentBlockerEnabled = await ExtensionBridge.contentBlockerIsEnabled()
        webExtensionEnabled = await ExtensionBridge.webExtensionIsEnabled()
        // Logged as values, not just on error: "no error" and "Safari says it
        // is off" look identical from the outside, and the difference decides
        // whether a hung reload is our bug or an unconfigured extension.
        func describe(_ state: Bool?) -> String {
            switch state {
            case true: "enabled"
            case false: "DISABLED"
            case nil: "unknown"
            }
        }
        log.info("""
            Safari state — content blocker: \(describe(self.contentBlockerEnabled), privacy: .public) \
            (\(ExtensionBridge.contentBlockerBundleID, privacy: .public)), \
            web extension: \(describe(self.webExtensionEnabled), privacy: .public)
            """)
    }

    /// Re-reads everything the extensions can write while we were idle: the
    /// activity log, and any bypass the block page added from its own process.
    public func reloadEvents() {
        events = EventLogStore.load()
        var stored = SharedStore.allowlist()
        stored.pruneExpired()
        if stored != allowlist { allowlist = stored }
        let blocked = SharedStore.userBlocklist()
        if blocked != userBlocklist { userBlocklist = blocked }
    }

    // MARK: - Settings

    public func setProtectionEnabled(_ enabled: Bool) async {
        settings.isProtectionEnabled = enabled
        await persistAndApply()
    }

    public func setCategory(_ category: ThreatCategory, enabled: Bool) async {
        if enabled {
            settings.enabledCategories.insert(category)
        } else {
            settings.enabledCategories.remove(category)
        }
        await persistAndApply()
    }

    public func setHeuristics(enabled: Bool) async {
        settings.heuristicsEnabled = enabled
        await persistAndApply()
    }

    public func setSensitivity(_ sensitivity: ProtectionSettings.Sensitivity) async {
        settings.heuristicSensitivity = sensitivity
        await persistAndApply()
    }

    public func setShowsInterstitial(_ shows: Bool) async {
        settings.showsInterstitial = shows
        await persistAndApply()
    }

    public func setLogsActivity(_ logs: Bool) async {
        settings.logsActivity = logs
        if !logs { events = EventLogStore.clear() }
        await persistAndApply()
    }

    public func setICloudSync(enabled: Bool) async {
        settings.syncsViaICloud = enabled
        if enabled {
            CloudSync.shared.onRemoteChange = { [weak self] in self?.pullFromCloud() }
            CloudSync.shared.start()
        } else {
            CloudSync.shared.stop()
        }
        await persistAndApply()
    }

    public func setAutoUpdates(enabled: Bool) async {
        settings.autoUpdatesEnabled = enabled
        await persistAndApply()
    }

    // MARK: - Allowlist

    public func allow(host rawHost: String, note: String? = nil) async {
        guard let host = URLNormalizer.canonicalHost(of: rawHost) else {
            lastError = "\"\(rawHost)\" is not a valid website address."
            return
        }
        lastError = nil
        allowlist.add(AllowlistItem(host: host, note: note))
        await persistAndApply()
    }

    /// Time-boxed bypass, used by the "Continue anyway" button on the block page.
    public func temporarilyAllow(host rawHost: String, bypassing category: ThreatCategory?) async {
        guard let host = URLNormalizer.canonicalHost(of: rawHost) else { return }
        allowlist.add(AllowlistItem(
            host: host,
            expiresAt: .now.addingTimeInterval(settings.temporaryBypassDuration),
            bypassedCategory: category
        ))
        events = EventLogStore.markBypassed(host: host)
        await persistAndApply()
    }

    // MARK: - Block list

    /// Adds a site to the user's own block list.
    ///
    /// Distinct from the threat feeds: nothing here claims the site is
    /// dangerous, only that this person does not want it loading.
    public func block(host rawHost: String, note: String? = nil) async {
        guard let host = URLNormalizer.canonicalHost(of: rawHost) else {
            lastError = "\"\(rawHost)\" is not a valid website address."
            return
        }
        lastError = nil
        // Blocking something you had previously allowed should just work,
        // rather than silently losing to the stale allowlist entry.
        allowlist.remove(host: host)
        userBlocklist.add(BlockedSite(host: host, note: note))
        await persistAndApply()
    }

    public func unblock(host: String) async {
        userBlocklist.remove(host: host)
        await persistAndApply()
    }

    public func removeFromAllowlist(host: String) async {
        allowlist.remove(host: host)
        await persistAndApply()
    }

    public func clearActivity() {
        events = EventLogStore.clear()
        pushToCloud()
    }

    // MARK: - Updates

    public func checkForUpdates() async {
        guard !isUpdating else { return }
        isUpdating = true
        defer { isUpdating = false }

        do {
            let updated = try await updater.fetchUpdates(current: catalog)
            lastUpdateCheck = .now
            guard !updated.isEmpty else { return }

            var merged = Dictionary(catalog.lists.map { ($0.identifier, $0) }, uniquingKeysWith: { a, _ in a })
            for list in updated { merged[list.identifier] = list }

            catalog = BlocklistCatalog(lists: Array(merged.values))
            SharedStore.write(catalog.lists, to: .catalog)
            await ruleApplier.runNow { [weak self] in await self?.applyRules() }
            log.info("Updated \(updated.count) blocklist feed(s)")
        } catch BlocklistUpdater.UpdateError.noFeedConfigured {
            // Expected in a fresh checkout. The bundled baseline still applies,
            // so this is not surfaced to the user as a failure.
            lastUpdateCheck = .now
        } catch {
            lastError = error.localizedDescription
            log.error("Update failed: \(error.localizedDescription, privacy: .public)")
        }
    }

    // MARK: - Persistence

    private func persistAndApply() async {
        SharedStore.write(settings, to: .settings)
        SharedStore.write(allowlist, to: .allowlist)
        SharedStore.write(userBlocklist, to: .userBlocklist)
        pushToCloud()
        // Reflect the pending work straight away; the compile itself is
        // deferred so four quick toggles cost one recompile, not four.
        isApplyingRules = true
        ruleApplier.schedule { [weak self] in await self?.applyRules() }
    }

    private func applyRules() async {
        // Compile first and publish the count immediately. The rules are live
        // in the App Group the moment this returns — the extension serves that
        // file — so there is no reason to withhold the number until Safari
        // acknowledges. WebKit can spend many seconds recompiling a full
        // catalog, and showing "0 rules active" for that whole window reads as
        // "you are not protected" when the opposite is true.
        isApplyingRules = true
        defer { isApplyingRules = false }

        compiledRuleCount = await ExtensionBridge.compileRules(
            catalog: catalog,
            settings: settings,
            allowlist: allowlist,
            userBlocklist: userBlocklist
        )
        lastError = nil

        let outcome = await ExtensionBridge.requestContentBlockerReload()

        // None of the outcomes is a user-facing error: "Safari hasn't
        // registered the extension" is what the setup prompt is already for,
        // and an unconfirmed reload still has the rules on disk for the next
        // time the extension loads. `lastError` stays reserved for things the
        // user can actually act on.
        rulesConfirmedBySafari = if case .reloaded = outcome { true } else { false }
    }

    private func pushToCloud() {
        guard settings.syncsViaICloud else { return }
        CloudSync.shared.push(
            settings: settings,
            allowlist: allowlist,
            userBlocklist: userBlocklist,
            summary: summary
        )
    }

    private func pullFromCloud() {
        guard settings.syncsViaICloud else { return }
        var changed = false

        if var remote = CloudSync.shared.remoteAllowlist(), remote != allowlist {
            remote.pruneExpired()
            allowlist = remote
            SharedStore.write(allowlist, to: .allowlist)
            changed = true
        }
        if let remote = CloudSync.shared.remoteUserBlocklist(), remote != userBlocklist {
            userBlocklist = remote
            SharedStore.write(userBlocklist, to: .userBlocklist)
            changed = true
        }
        if let remote = CloudSync.shared.remoteSettings(), remote != settings {
            // Sync preferences, not device-local plumbing: whether *this*
            // device syncs at all is not something another device gets to set.
            var merged = remote
            merged.syncsViaICloud = settings.syncsViaICloud
            settings = merged
            SharedStore.write(settings, to: .settings)
            changed = true
        }

        guard changed else { return }
        isApplyingRules = true
        ruleApplier.schedule { [weak self] in await self?.applyRules() }
    }
}
