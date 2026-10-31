import SwiftUI

@main
struct KeyflapApproverApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var model = AppModel.shared
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(model)
                .tint(Theme.accent)
                .task { model.startPolling() }
                .onChange(of: scenePhase) { _, phase in
                    // Poll only while open; in the background, pushes (if set up) wake the user.
                    if phase == .active { model.startPolling() } else { model.stopPolling() }
                }
        }
    }
}

struct RootView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        NavigationStack {
            HomeView()
        }
        .sheet(item: $model.active) { active in
            RequestSheet(active: active)
                .environmentObject(model)
                .presentationDragIndicator(.visible)
                .interactiveDismissDisabled(false)
        }
    }
}
