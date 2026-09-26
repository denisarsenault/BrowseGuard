import SwiftUI

struct RootTabView: View {
    var body: some View {
        TabView {
            NavigationStack { HomeView() }
                .tabItem { Label("Protection", systemImage: "shield.lefthalf.filled") }
            NavigationStack { ActivityView() }
                .tabItem { Label("Activity", systemImage: "list.bullet.rectangle") }
            NavigationStack { SitesView() }
                .tabItem { Label("Sites", systemImage: "checkmark.seal") }
            NavigationStack { SettingsView() }
                .tabItem { Label("Settings", systemImage: "gearshape") }
        }
    }
}

struct HomeView: View {
    @Environment(ProtectionCoordinator.self) private var coordinator

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                ProtectionStatusCard(
                    isEnabled: coordinator.settings.isProtectionEnabled,
                    isFullyArmed: coordinator.isFullyArmed,
                    summary: coordinator.summary,
                    ruleCount: coordinator.compiledRuleCount,
                    isApplying: coordinator.isApplyingRules
                )

                if coordinator.contentBlockerEnabled == false {
                    SetupInstructionsCard()
                }

                Toggle(
                    "BrowseGuard Protection",
                    isOn: Binding(
                        get: { coordinator.settings.isProtectionEnabled },
                        set: { value in Task { await coordinator.setProtectionEnabled(value) } }
                    )
                )
                .font(.headline)
                .cardBackground()

                Text("Blocked by category")
                    .font(.headline)
                    .padding(.top, 4)

                CategoryStatsGrid(
                    summary: coordinator.summary,
                    enabledCategories: coordinator.settings.enabledCategories
                )
            }
            .padding()
        }
        .navigationTitle("BrowseGuard")
        .refreshable {
            coordinator.reloadEvents()
            await coordinator.refreshExtensionState()
        }
    }
}

/// iOS cannot deep-link into the Safari extension settings pane, so the app has
/// to spell the steps out. Getting this wrong is the single biggest reason a
/// content blocker looks "broken" to a user.
struct SetupInstructionsCard: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Turn BrowseGuard on in Safari", systemImage: "exclamationmark.triangle.fill")
                .font(.headline)
                .foregroundStyle(.orange)
            Text("""
                1. Open the Settings app and find Safari
                2. Tap Extensions
                3. Turn on BrowseGuard and BrowseGuard Blocker
                4. Tap BrowseGuard and set permissions to Allow
                """)
            .font(.subheadline)
            .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .cardBackground()
    }
}

struct ActivityView: View {
    @Environment(ProtectionCoordinator.self) private var coordinator

    var body: some View {
        List {
            ActivityListView(events: coordinator.events)
        }
        .navigationTitle("Activity")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button("Clear", systemImage: "trash") {
                    coordinator.clearActivity()
                }
                .disabled(coordinator.events.isEmpty)
            }
        }
        .refreshable { coordinator.reloadEvents() }
    }
}

struct SitesView: View {
    var body: some View {
        Form {
            Section("Check a site") {
                SiteCheckerView()
            }
            Section("Blocked by you") {
                BlockedSitesEditor()
            }
            Section("Allowlist") {
                AllowlistEditor()
            }
        }
        .navigationTitle("Sites")
    }
}

struct SettingsView: View {
    @Environment(ProtectionCoordinator.self) private var coordinator

    var body: some View {
        Form {
            Section {
                ExtensionStatusRow(
                    title: "Safari Content Blocker",
                    isEnabled: coordinator.contentBlockerEnabled,
                    helpText: "Enable BrowseGuard Blocker in the Settings app, under Safari › Extensions."
                )
            } header: {
                Text("Safari")
            } footer: {
                Text("\(coordinator.compiledRuleCount.formatted()) rules are compiled and ready.")
            }

            Section("What to block") {
                CategoryToggleList(settings: coordinator.settings) { category, enabled in
                    Task { await coordinator.setCategory(category, enabled: enabled) }
                }
            }

            Section {
                Toggle("Detect new threats", isOn: Binding(
                    get: { coordinator.settings.heuristicsEnabled },
                    set: { value in Task { await coordinator.setHeuristics(enabled: value) } }
                ))
                if coordinator.settings.heuristicsEnabled {
                    SensitivityPicker(selection: coordinator.settings.heuristicSensitivity) { level in
                        Task { await coordinator.setSensitivity(level) }
                    }
                }
            } header: {
                Text("Heuristics")
            } footer: {
                Text("Catches phishing sites that are too new to be on any blocklist, by looking at the shape of the domain name.")
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

            Section {
                Toggle("Update blocklists automatically", isOn: Binding(
                    get: { coordinator.settings.autoUpdatesEnabled },
                    set: { value in Task { await coordinator.setAutoUpdates(enabled: value) } }
                ))
                Button("Check for updates now") {
                    Task { await coordinator.checkForUpdates() }
                }
                .disabled(coordinator.isUpdating)
                LabeledContent("Rules") {
                    Text(coordinator.catalog.entryCount.formatted())
                }
                if let lastUpdateCheck = coordinator.lastUpdateCheck {
                    LabeledContent("Last checked") {
                        Text(lastUpdateCheck, format: .relative(presentation: .numeric))
                    }
                }
            } header: {
                Text("Blocklists")
            }
        }
        .navigationTitle("Settings")
    }
}
