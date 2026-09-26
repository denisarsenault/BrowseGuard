import SwiftUI

@main
@MainActor
struct BrowseGuardApp: App {
    @State private var coordinator = ProtectionCoordinator()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            RootTabView()
                .environment(coordinator)
                .task { await coordinator.bootstrap() }
        }
        .onChange(of: scenePhase) { _, phase in
            guard phase == .active else { return }
            // The extensions append to the log while we are backgrounded, and
            // the user may have flipped the Safari switch in Settings.
            coordinator.reloadEvents()
            Task { await coordinator.refreshExtensionState() }
        }
    }
}
