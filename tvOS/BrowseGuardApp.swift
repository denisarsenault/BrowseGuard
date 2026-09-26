import SwiftUI

@main
@MainActor
struct BrowseGuardApp: App {
    @State private var coordinator = ProtectionCoordinator()

    var body: some Scene {
        WindowGroup {
            TVRootView()
                .environment(coordinator)
                .task { await coordinator.bootstrap() }
        }
    }
}
