import SwiftUI

@main
@MainActor
struct BrowseGuardApp: App {
    @State private var coordinator = ProtectionCoordinator()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            SubscriptionGate { MacRootView() }
                .environment(coordinator)
                .frame(minWidth: 820, minHeight: 560)
                .task {
                    // Only one copy may run. Two copies would both write the same
                    // App Group state, and the stale one would overwrite the other's
                    // settings. A new launch hands focus to the running copy and quits.
                    if let running = Self.otherRunningCopy() {
                        running.activate()
                        NSApp.terminate(nil)
                        return
                    }
                    await coordinator.bootstrap()
                }
        }
        .onChange(of: scenePhase) { _, phase in
            guard phase == .active else { return }
            // A renewal or a lapse may have happened while the app was in the
            // background. Ask StoreKit rather than waiting for the next launch.
            Task { await coordinator.subscription.refresh() }
        }
        .defaultSize(width: 960, height: 660)
        .commands {
            CommandGroup(after: .appInfo) {
                Button("Check for Blocklist Updates…") {
                    Task { await coordinator.checkForUpdates() }
                }
                .disabled(coordinator.isUpdating)

                Button("Open Safari Extension Settings…") {
                    ExtensionBridge.presentExtensionPreferences()
                }
            }
        }

        Settings {
            SubscriptionGate { MacSettingsView() }
                .environment(coordinator)
                .frame(width: 520)
        }
    }

    /// Another running process with this bundle identifier, if there is one.
    /// The Safari extensions have their own identifiers, so they are not counted.
    private static func otherRunningCopy() -> NSRunningApplication? {
        guard let identifier = Bundle.main.bundleIdentifier else { return nil }
        return NSRunningApplication.runningApplications(withBundleIdentifier: identifier)
            .first { $0 != NSRunningApplication.current }
    }
}
