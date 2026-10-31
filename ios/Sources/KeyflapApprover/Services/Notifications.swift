import Foundation
import UIKit
import UserNotifications

/// APNs: the notification category with lock-screen actions, permission, and the device
/// token. Pushes come only when the paid developer program is set up and the broker runs
/// with --apns-*; without them the app polls while open.
enum Push {
    static let category = "AAB_APPROVAL"
    static let approveAction = "AAB_APPROVE"
    static let denyAction = "AAB_DENY"

    /// Debug builds (xtool dev) talk to the APNs sandbox; release builds (TestFlight, App
    /// Store) to production. The broker sends to whichever the device reports.
    static var environment: String {
        #if DEBUG
        return "sandbox"
        #else
        return "production"
        #endif
    }

    /// Approve opens the app (foreground) after unlocking (authenticationRequired); the
    /// Secure Enclave signature then asks for Face ID itself, with the request on screen.
    /// Deny works from the lock screen without unlocking: a denial needs no key, fails
    /// closed, and a forged one could only refuse a sign-in (see docs).
    static func registerCategories() {
        let approve = UNNotificationAction(
            identifier: approveAction,
            title: "Approve",
            options: [.foreground, .authenticationRequired],
            icon: UNNotificationActionIcon(systemImageName: "faceid")
        )
        let deny = UNNotificationAction(
            identifier: denyAction,
            title: "Deny",
            options: [.destructive],
            icon: UNNotificationActionIcon(systemImageName: "xmark.circle")
        )
        let cat = UNNotificationCategory(
            identifier: category,
            actions: [approve, deny],
            intentIdentifiers: [],
            hiddenPreviewsBodyPlaceholder: "Sign-in request",
            options: []
        )
        UNUserNotificationCenter.current().setNotificationCategories([cat])
    }

    static func requestPermission() async -> Bool {
        let granted = (try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge])) ?? false
        if granted { await MainActor.run { UIApplication.shared.registerForRemoteNotifications() } }
        return granted
    }

    static func authorizationStatus() async -> UNAuthorizationStatus {
        await UNUserNotificationCenter.current().notificationSettings().authorizationStatus
    }

    /// The request id a notification carries (`aab.rid`), if any.
    static func requestId(from userInfo: [AnyHashable: Any]) -> String? {
        guard let aab = userInfo["aab"] as? [String: Any], let rid = aab["rid"] as? String,
              !rid.isEmpty, rid.count <= 128 else { return nil }
        return rid
    }
}

final class AppDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {
    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        UNUserNotificationCenter.current().delegate = self
        Push.registerCategories()
        Task {
            let status = await Push.authorizationStatus()
            if status == .authorized || status == .provisional {
                await MainActor.run { application.registerForRemoteNotifications() }
            }
        }
        return true
    }

    func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        let hex = deviceToken.map { String(format: "%02x", $0) }.joined()
        Task { @MainActor in AppModel.shared.pushTokenChanged(hex) }
    }

    func application(_ application: UIApplication, didFailToRegisterForRemoteNotificationsWithError error: Error) {
        // Typically: no aps-environment entitlement (free provisioning). Polling still works.
        Task { @MainActor in AppModel.shared.pushUnavailable(error.localizedDescription) }
    }

    /// In the foreground: refresh and show the request sheet instead of a banner.
    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification
    ) async -> UNNotificationPresentationOptions {
        let rid = Push.requestId(from: notification.request.content.userInfo)
        await MainActor.run { AppModel.shared.openFromNotification(requestId: rid, autoApprove: false) }
        return []
    }

    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse
    ) async {
        let rid = Push.requestId(from: response.notification.request.content.userInfo)
        switch response.actionIdentifier {
        case Push.denyAction:
            if let rid { await AppModel.shared.denyFromNotification(requestId: rid) }
        case Push.approveAction:
            await MainActor.run { AppModel.shared.openFromNotification(requestId: rid, autoApprove: true) }
        default:
            await MainActor.run { AppModel.shared.openFromNotification(requestId: rid, autoApprove: false) }
        }
    }
}
