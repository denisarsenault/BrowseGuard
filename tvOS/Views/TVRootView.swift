import SwiftUI

/// The tvOS face of BrowseGuard.
///
/// tvOS has no web browser and no Safari extension point, so there is nothing
/// on this device to filter. What the TV target *can* do is be the household's
/// shared view of what the other devices are blocking: the settings and
/// allowlist arrive over iCloud, the counters are legible from the sofa, and
/// the protection switches here take effect on the iPhone and Mac.
///
/// Anything requiring text entry is deliberately absent — that belongs on a
/// device with a keyboard.
struct TVRootView: View {
    var body: some View {
        TabView {
            TVOverviewView()
                .tabItem { Label("Overview", systemImage: "shield.lefthalf.filled") }
            TVActivityView()
                .tabItem { Label("Activity", systemImage: "list.bullet.rectangle") }
            TVCategoriesView()
                .tabItem { Label("What to Block", systemImage: "slider.horizontal.3") }
            TVAllowlistView()
                .tabItem { Label("Allowed Sites", systemImage: "checkmark.seal") }
            TVBlockedSitesView()
                .tabItem { Label("Blocked Sites", systemImage: "hand.raised.slash") }
        }
    }
}

struct TVOverviewView: View {
    @Environment(ProtectionCoordinator.self) private var coordinator

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 32) {
                Text("BrowseGuard")
                    .font(.largeTitle.weight(.bold))

                ProtectionStatusCard(
                    isEnabled: coordinator.settings.isProtectionEnabled,
                    // There is no Safari here to be half-configured, so on tvOS
                    // the master switch is the whole story.
                    isFullyArmed: coordinator.settings.isProtectionEnabled,
                    summary: coordinator.summary,
                    ruleCount: coordinator.compiledRuleCount,
                    isApplying: coordinator.isApplyingRules
                )

                Toggle("Protection", isOn: Binding(
                    get: { coordinator.settings.isProtectionEnabled },
                    set: { value in Task { await coordinator.setProtectionEnabled(value) } }
                ))
                .font(.title3)
                .cardBackground()

                Text("Blocked by category").font(.title2)
                CategoryStatsGrid(
                    summary: coordinator.summary,
                    enabledCategories: coordinator.settings.enabledCategories
                )

                Label(
                    "Apple TV has no web browser, so nothing is filtered on this device. These settings apply to your iPhone, iPad, and Mac.",
                    systemImage: "info.circle"
                )
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            }
            .padding(60)
        }
    }
}

struct TVActivityView: View {
    @Environment(ProtectionCoordinator.self) private var coordinator

    var body: some View {
        VStack(alignment: .leading, spacing: 24) {
            Text("Recent Activity").font(.largeTitle.weight(.bold))

            if coordinator.events.isEmpty {
                ContentUnavailableView(
                    "Nothing blocked yet",
                    systemImage: "checkmark.shield",
                    description: Text("Blocks from your other devices appear here once iCloud syncs.")
                )
            } else {
                List {
                    ActivityListView(events: coordinator.events, limit: 100)
                }
            }
        }
        .padding(60)
    }
}

struct TVCategoriesView: View {
    @Environment(ProtectionCoordinator.self) private var coordinator

    var body: some View {
        VStack(alignment: .leading, spacing: 24) {
            Text("What to Block").font(.largeTitle.weight(.bold))
            List {
                CategoryToggleList(settings: coordinator.settings) { category, enabled in
                    Task { await coordinator.setCategory(category, enabled: enabled) }
                }
            }
        }
        .padding(60)
    }
}

struct TVAllowlistView: View {
    @Environment(ProtectionCoordinator.self) private var coordinator

    var body: some View {
        VStack(alignment: .leading, spacing: 24) {
            Text("Allowed Sites").font(.largeTitle.weight(.bold))

            if coordinator.allowlist.activeItems.isEmpty {
                ContentUnavailableView(
                    "No allowed sites",
                    systemImage: "checkmark.seal",
                    description: Text("Add sites on your iPhone or Mac and they will show up here.")
                )
            } else {
                List {
                    ForEach(coordinator.allowlist.activeItems) { item in
                        AllowlistRow(item: item) {
                            Task { await coordinator.removeFromAllowlist(host: item.host) }
                        }
                    }
                }
            }
        }
        .padding(60)
    }
}

/// Read-only, like the allowlist screen: typing a domain on a remote is
/// miserable, and the list syncs from the phone or Mac anyway.
struct TVBlockedSitesView: View {
    @Environment(ProtectionCoordinator.self) private var coordinator

    var body: some View {
        VStack(alignment: .leading, spacing: 24) {
            Text("Blocked Sites").font(.largeTitle.weight(.bold))

            if coordinator.userBlocklist.items.isEmpty {
                ContentUnavailableView(
                    "No blocked sites",
                    systemImage: "hand.raised.slash",
                    description: Text("Block sites on your iPhone or Mac and they will show up here.")
                )
            } else {
                List {
                    ForEach(coordinator.userBlocklist.items) { item in
                        BlockedSiteRow(item: item) {
                            Task { await coordinator.unblock(host: item.host) }
                        }
                    }
                }
            }
        }
        .padding(60)
    }
}
