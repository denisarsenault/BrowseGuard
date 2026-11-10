import SwiftUI

struct MacRootView: View {
    @Environment(ProtectionCoordinator.self) private var coordinator
    @State private var selection: Section? = .overview
    @State private var cleanupPromptReport: DuplicateInstallReport?

    private static let promptedVersionKey = "duplicateCleanupPromptedVersion"

    enum Section: String, Hashable, CaseIterable, Identifiable {
        case overview, activity, sites, categories

        var id: String { rawValue }

        var title: String {
            switch self {
            case .overview: "Overview"
            case .activity: "Activity"
            case .sites: "Sites"
            case .categories: "What to Block"
            }
        }

        var symbolName: String {
            switch self {
            case .overview: "shield.lefthalf.filled"
            case .activity: "list.bullet.rectangle"
            case .sites: "checkmark.seal"
            case .categories: "slider.horizontal.3"
            }
        }
    }

    var body: some View {
        NavigationSplitView {
            List(Section.allCases, selection: $selection) { section in
                Label(section.title, systemImage: section.symbolName)
                    .tag(section)
            }
            .navigationSplitViewColumnWidth(min: 180, ideal: 200, max: 260)
        } detail: {
            switch selection ?? .overview {
            case .overview: MacOverviewView()
            case .activity: MacActivityView()
            case .sites: MacSitesView()
            case .categories: MacCategoriesView()
            }
        }
        .navigationTitle("BrowseGuard")
        .task { evaluateCleanupPrompt() }
        .alert("An old copy of BrowseGuard is still installed",
               isPresented: Binding(get: { cleanupPromptReport != nil },
                                    set: { if !$0 { cleanupPromptReport = nil } }),
               presenting: cleanupPromptReport) { _ in
            Button("Review") { selection = .overview; cleanupPromptReport = nil }
            Button("Later", role: .cancel) { cleanupPromptReport = nil }
        } message: { report in
            let n = report.otherCopies.count
            Text("\(n == 1 ? "Another copy is" : "\(n) other copies are") installed. Safari can load its extension and serve stale rules. Review it in Overview to move it to the Trash.")
        }
    }

    /// Show the cleanup prompt at most once per app version, and only when a
    /// second copy is actually present (the moment an update makes the old one
    /// stale is exactly when this fires).
    private func evaluateCleanupPrompt() {
        let report = DuplicateInstallScanner.scan()
        let defaults = AppGroup.defaults
        guard DuplicateInstallPrompt.shouldPrompt(
            hasDuplicates: report.hasDuplicates,
            currentVersion: Self.currentVersion,
            lastPromptedVersion: defaults.string(forKey: Self.promptedVersionKey)
        ) else { return }

        cleanupPromptReport = report
        defaults.set(Self.currentVersion, forKey: Self.promptedVersionKey)
    }

    private static var currentVersion: String {
        let info = Bundle.main.infoDictionary
        let short = (info?["CFBundleShortVersionString"] as? String) ?? "?"
        let build = (info?["CFBundleVersion"] as? String) ?? "?"
        return "\(short) (\(build))"
    }
}

struct MacOverviewView: View {
    @Environment(ProtectionCoordinator.self) private var coordinator
    @State private var installReport: DuplicateInstallReport?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                if let report = installReport, report.hasDuplicates {
                    DuplicateInstallBanner(report: report) {
                        installReport = DuplicateInstallScanner.scan()
                    }
                }

                ProtectionStatusCard(
                    isEnabled: coordinator.settings.isProtectionEnabled,
                    isFullyArmed: coordinator.isFullyArmed,
                    summary: coordinator.summary,
                    ruleCount: coordinator.compiledRuleCount,
                    isApplying: coordinator.isApplyingRules
                )

                Toggle("BrowseGuard Protection", isOn: Binding(
                    get: { coordinator.settings.isProtectionEnabled },
                    set: { value in Task { await coordinator.setProtectionEnabled(value) } }
                ))
                .toggleStyle(.switch)
                .font(.headline)
                .cardBackground()

                VStack(alignment: .leading, spacing: 10) {
                    Text("Safari").font(.headline)
                    ExtensionStatusRow(
                        title: "Content Blocker",
                        isEnabled: coordinator.contentBlockerEnabled,
                        helpText: "Turn on BrowseGuard Blocker in Safari › Settings › Extensions.",
                        action: { ExtensionBridge.presentExtensionPreferences() }
                    )
                    ExtensionStatusRow(
                        title: "Real-time Protection Extension",
                        isEnabled: coordinator.webExtensionEnabled,
                        helpText: "The extension is what checks each page you open against the heuristics.",
                        action: { ExtensionBridge.presentExtensionPreferences() }
                    )
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .cardBackground()

                ChromeExtensionCard()

                Text("Blocked by category").font(.headline)
                CategoryStatsGrid(
                    summary: coordinator.summary,
                    settings: coordinator.settings
                )

                if !coordinator.events.isEmpty {
                    Text("Recent").font(.headline)
                    VStack(spacing: 0) {
                        ActivityListView(events: coordinator.events, limit: 6)
                    }
                    .cardBackground()
                }
            }
            .padding(20)
        }
        .navigationTitle("Overview")
        .task { await coordinator.refreshExtensionState() }
        .task { installReport = DuplicateInstallScanner.scan() }
    }
}

struct MacActivityView: View {
    @Environment(ProtectionCoordinator.self) private var coordinator

    var body: some View {
        List {
            ActivityListView(events: coordinator.events)
        }
        .navigationTitle("Activity")
        .toolbar {
            ToolbarItem {
                Button("Refresh", systemImage: "arrow.clockwise") {
                    coordinator.reloadEvents()
                }
            }
            ToolbarItem {
                Button("Clear", systemImage: "trash") {
                    coordinator.clearActivity()
                }
                .disabled(coordinator.events.isEmpty)
            }
        }
    }
}

struct MacSitesView: View {
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                VStack(alignment: .leading, spacing: 10) {
                    Text("Check a site").font(.headline)
                    SiteCheckerView()
                }
                Divider()
                VStack(alignment: .leading, spacing: 10) {
                    Text("Blocked by you").font(.headline)
                    BlockedSitesEditor()
                }
                Divider()
                VStack(alignment: .leading, spacing: 10) {
                    Text("Allowlist").font(.headline)
                    AllowlistEditor()
                }
            }
            .padding(20)
            .frame(maxWidth: 720, alignment: .leading)
        }
        .navigationTitle("Sites")
    }
}

struct MacCategoriesView: View {
    @Environment(ProtectionCoordinator.self) private var coordinator

    var body: some View {
        Form {
            CategoryToggleList(settings: coordinator.settings) { category, enabled in
                Task { await coordinator.setCategory(category, enabled: enabled) }
            }
        }
        .formStyle(.grouped)
        .navigationTitle("What to Block")
    }
}

struct MacSettingsView: View {
    @Environment(ProtectionCoordinator.self) private var coordinator

    var body: some View {
        Form {
            Section("Heuristics") {
                Toggle("Detect new threats", isOn: Binding(
                    get: { coordinator.settings.heuristicsEnabled },
                    set: { value in Task { await coordinator.setHeuristics(enabled: value) } }
                ))
                if coordinator.settings.heuristicsEnabled {
                    SensitivityPicker(selection: coordinator.settings.heuristicSensitivity) { level in
                        Task { await coordinator.setSensitivity(level) }
                    }
                }
            }

            Section("Privacy") {
                Toggle("Keep an activity log", isOn: Binding(
                    get: { coordinator.settings.logsActivity },
                    set: { value in Task { await coordinator.setLogsActivity(value) } }
                ))
                Toggle("Sync with iCloud", isOn: Binding(
                    get: { coordinator.settings.syncsViaICloud },
                    set: { value in Task { await coordinator.setICloudSync(enabled: value) } }
                ))
                Toggle("Show a block page", isOn: Binding(
                    get: { coordinator.settings.showsInterstitial },
                    set: { value in Task { await coordinator.setShowsInterstitial(value) } }
                ))
            }

            Section("Blocklists") {
                Toggle("Update automatically", isOn: Binding(
                    get: { coordinator.settings.autoUpdatesEnabled },
                    set: { value in Task { await coordinator.setAutoUpdates(enabled: value) } }
                ))
                LabeledContent("Hosts listed") {
                    Text(coordinator.catalog.entryCount.formatted())
                }
                LabeledContent("Compiled rules") {
                    Text(coordinator.compiledRuleCount.formatted())
                }
                Button("Check for Updates") {
                    Task { await coordinator.checkForUpdates() }
                }
                .disabled(coordinator.isUpdating)
            }
        }
        .formStyle(.grouped)
        .padding()
    }
}
