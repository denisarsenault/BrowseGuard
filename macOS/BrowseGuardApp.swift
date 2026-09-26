import SwiftUI

@main
@MainActor
struct BrowseGuardApp: App {
    @State private var coordinator = ProtectionCoordinator()

    var body: some Scene {
        WindowGroup {
            MacRootView()
                .environment(coordinator)
                .frame(minWidth: 820, minHeight: 560)
                .task { await coordinator.bootstrap() }
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
            MacSettingsView()
                .environment(coordinator)
                .frame(width: 520)
        }
    }
}
