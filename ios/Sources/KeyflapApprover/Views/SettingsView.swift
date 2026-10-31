import KeyflapApproverCore
import SwiftUI
import UIKit
import UserNotifications

struct SettingsView: View {
    @EnvironmentObject private var model: AppModel
    @State private var pairing = false
    @State private var unpairing: PairedBroker?
    @State private var note: String?

    var body: some View {
        Form {
            Section {
                if model.brokers.isEmpty {
                    Text("Not paired with any broker.").foregroundStyle(.secondary)
                }
                ForEach(model.brokers) { b in
                    VStack(alignment: .leading, spacing: 4) {
                        BrokerRow(broker: b, status: model.status[b.id] ?? BrokerStatus())
                        Text(b.origin).font(.caption.monospaced()).foregroundStyle(.secondary)
                        Text("Paired \(b.pairedAt.formatted(date: .abbreviated, time: .shortened)) · key \(String(b.keyId.prefix(10)))…")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                    .swipeActions {
                        Button("Unpair", role: .destructive) { unpairing = b }
                    }
                    .contextMenu {
                        Button("Unpair", systemImage: "trash", role: .destructive) { unpairing = b }
                    }
                }
                Button {
                    pairing = true
                } label: {
                    Label("Pair a broker", systemImage: "qrcode.viewfinder")
                }
            } header: {
                Text("Paired brokers")
            } footer: {
                Text("Swipe left on a broker to unpair. A lost phone is removed on the broker with `keyflap approver remove <id>`.")
            }

            Section {
                HStack {
                    Label("Notifications", systemImage: "bell.badge")
                    Spacer()
                    Text(notificationText).foregroundStyle(.secondary)
                }
                if model.notificationStatus == .notDetermined {
                    Button("Allow notifications") { Task { await model.requestNotifications() } }
                } else if model.notificationStatus == .denied {
                    Button("Open iOS Settings") {
                        if let url = URL(string: UIApplication.openSettingsURLString) { UIApplication.shared.open(url) }
                    }
                }
                ForEach(model.brokers) { b in
                    let st = model.status[b.id] ?? BrokerStatus()
                    HStack {
                        Text(b.host).lineLimit(1)
                        Spacer()
                        Text(st.apnsRegistered ? "Push on" : st.apnsConfigured ? "Not registered" : "Push not set up")
                            .foregroundStyle(.secondary)
                    }
                    .font(.callout)
                }
                if let p = model.pushProblem {
                    Text(p).font(.caption).foregroundStyle(.secondary)
                }
            } header: {
                Text("Notifications")
            } footer: {
                Text("Push needs the broker started with --apns-* options (Apple Developer Program). Without it, requests show up whenever Keyflap is open: it checks every two seconds. Notifications carry only the site's name and a request id.")
            }

            Section {
                Label("\(ApprovalKey.biometryName) for every approval", systemImage: "faceid")
                Label("Keys stay in the Secure Enclave", systemImage: "cpu")
                Label("Denying needs no Face ID", systemImage: "hand.raised")
            } header: {
                Text("Security")
            } footer: {
                Text("Each broker gets its own key, made in this iPhone's Secure Enclave. It can't be copied off the phone, and it only signs after \(ApprovalKey.biometryName) recognises you; enrolling a new face or fingerprint retires it. The app checks every request against what it shows you before signing, and the broker verifies the signature itself.")
            }

            Section("About") {
                LabeledContent("Version", value: version)
                LabeledContent("Approver protocol", value: "native v1")
                Text("Keyflap signs your AI agents into websites without them ever holding a password or key. This app is where you say yes or no.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
        .navigationTitle("Settings")
        .sheet(isPresented: $pairing) { PairingView().environmentObject(model) }
        .confirmationDialog(
            "Unpair \(unpairing?.host ?? "")?",
            isPresented: Binding(get: { unpairing != nil }, set: { if !$0 { unpairing = nil } }),
            titleVisibility: .visible,
            presenting: unpairing
        ) { b in
            Button("Unpair", role: .destructive) {
                Task { note = await model.unpair(b) }
            }
        } message: { _ in
            Text("This iPhone's key for that broker is deleted. You can pair again with a new link.")
        }
        .alert("Unpaired", isPresented: Binding(get: { note != nil }, set: { if !$0 { note = nil } })) {
            Button("OK") { note = nil }
        } message: {
            Text(note ?? "")
        }
        .task { await model.refreshNotificationStatus() }
    }

    private var notificationText: String {
        switch model.notificationStatus {
        case .authorized: return "On"
        case .denied: return "Off"
        case .provisional, .ephemeral: return "Quiet"
        case .notDetermined: return "Not asked"
        @unknown default: return "Unknown"
        }
    }

    private var version: String {
        let v = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "1.0"
        let b = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "1"
        return "\(v) (\(b))"
    }
}
