import Foundation
import KeyflapApproverCore
import SwiftUI
import UserNotifications

/// A pending request at one paired broker.
struct PendingItem: Identifiable, Equatable {
    let broker: PairedBroker
    let request: PendingRequest
    var id: String { "\(broker.id.uuidString)#\(request.id)" }
}

/// What the request sheet shows; `autoApprove` when opened from the lock-screen Approve
/// action (the sheet appears with the details, then Face ID starts).
struct ActiveRequest: Identifiable, Equatable {
    let item: PendingItem
    let autoApprove: Bool
    var id: String { item.id }
}

struct BrokerStatus: Equatable {
    enum Reachability: Equatable { case unknown, online, offline(String), unpaired }
    var reachability: Reachability = .unknown
    var lastSeen: Date?
    var apnsConfigured = false
    var apnsRegistered = false
}

enum ApprovalPhase: Equatable {
    case idle, checking, biometry, sending, approved, denied
    case failed(String)
}

@MainActor
final class AppModel: ObservableObject {
    static let shared = AppModel()

    @Published private(set) var brokers: [PairedBroker] = LocalStore.brokers()
    @Published private(set) var pending: [PendingItem] = []
    @Published private(set) var status: [UUID: BrokerStatus] = [:]
    @Published private(set) var history: [HistoryEntry] = LocalStore.history()
    @Published var active: ActiveRequest?
    @Published private(set) var notificationStatus: UNAuthorizationStatus = .notDetermined
    @Published private(set) var pushProblem: String?
    @Published private(set) var refreshing = false

    private var clockOffset: [UUID: Int64] = [:]
    private var pushToken: String?
    private var pollTask: Task<Void, Never>?
    /// Requests decided on this phone (so a vanished request isn't logged as expired).
    private var decidedHere: Set<String> = []
    /// Requests already offered in the sheet once (don't re-pop after "Later").
    private var offered: Set<String> = []
    private var openRequest: (id: String?, autoApprove: Bool)?

    // MARK: - Clock

    nonisolated static var nowMs: Int64 { Int64((Date().timeIntervalSince1970 * 1000).rounded()) }

    /// The broker's clock, from the offset seen in its last state answer.
    func brokerNow(_ b: PairedBroker) -> Int64 { Self.nowMs + (clockOffset[b.id] ?? 0) }

    func client(for b: PairedBroker) -> BrokerClient {
        BrokerClient(origin: b.origin, deviceToken: b.deviceToken, transport: URLSessionTransport())
    }

    // MARK: - Polling

    /// While the app is open it asks every paired broker for pending requests every two
    /// seconds: the path that works without APNs (no paid developer account).
    func startPolling() {
        pollTask?.cancel()
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.refresh()
                try? await Task.sleep(nanoseconds: 2_000_000_000)
            }
        }
        Task { notificationStatus = await Push.authorizationStatus() }
    }

    func stopPolling() {
        pollTask?.cancel()
        pollTask = nil
    }

    func refresh() async {
        guard !brokers.isEmpty else {
            pending = []
            return
        }
        refreshing = true
        defer { refreshing = false }
        var items: [PendingItem] = []
        await withTaskGroup(of: (PairedBroker, Result<BrokerState, Error>, Int64).self) { group in
            for b in brokers {
                let c = client(for: b)
                group.addTask {
                    let sent = AppModel.nowMs
                    do {
                        return (b, .success(try await c.state()), sent)
                    } catch {
                        return (b, .failure(error), sent)
                    }
                }
            }
            for await (b, result, sent) in group {
                var st = status[b.id] ?? BrokerStatus()
                switch result {
                case .success(let state):
                    // Midpoint of the round trip, for countdowns that ignore phone clock skew.
                    clockOffset[b.id] = state.now - (sent + AppModel.nowMs) / 2
                    st.reachability = .online
                    st.lastSeen = Date()
                    st.apnsConfigured = state.apnsConfigured
                    st.apnsRegistered = state.apnsRegistered
                    items += state.pending.map { PendingItem(broker: b, request: $0) }
                case .failure(let error):
                    if case BrokerError.notPaired = error {
                        st.reachability = .unpaired
                    } else {
                        st.reachability = .offline(Self.describe(error))
                    }
                    // Keep showing what we had for an unreachable broker until it expires.
                    items += pending.filter { $0.broker.id == b.id && $0.request.expiresAt > brokerNow(b) }
                }
                status[b.id] = st
            }
        }
        items.sort { $0.request.createdAt < $1.request.createdAt }
        let newIds = Set(items.map(\.id))
        for gone in pending where !newIds.contains(gone.id) && !decidedHere.contains(gone.id) {
            record(gone, .expired)
        }
        pending = items
        presentIfNeeded()
    }

    private func presentIfNeeded() {
        if let open = openRequest {
            if let id = open.id, let item = pending.first(where: { $0.request.id == id }) {
                openRequest = nil
                offered.insert(item.id)
                active = ActiveRequest(item: item, autoApprove: open.autoApprove)
                return
            }
            if open.id == nil { openRequest = nil }
        }
        // Duo-like: a new request opens its sheet when nothing else is showing.
        if active == nil, let next = pending.first(where: { !offered.contains($0.id) }) {
            offered.insert(next.id)
            active = ActiveRequest(item: next, autoApprove: false)
        }
    }

    func show(_ item: PendingItem) {
        offered.insert(item.id)
        active = ActiveRequest(item: item, autoApprove: false)
    }

    func isPending(_ item: PendingItem) -> Bool { pending.contains { $0.id == item.id } }

    // MARK: - Deciding

    /// Approve: fetch the statement, check it against what is on screen, sign it with the
    /// Secure Enclave key (Face ID), send the signature. The broker's signer verifies it.
    func approve(_ item: PendingItem, phase: @escaping (ApprovalPhase) -> Void) async {
        let b = item.broker
        guard let keyData = b.keyData else {
            phase(.failed("This iPhone's approval key is missing. Unpair and pair again."))
            return
        }
        let c = client(for: b)
        do {
            phase(.checking)
            let ch = try await c.challenge(id: item.request.id)
            try StatementCheck.verify(
                ch.statement, for: item.request, descriptor: ch.descriptor,
                brokerOrigin: b.origin, now: brokerNow(b)
            )
            phase(.biometry)
            let sig = try await ApprovalKey.sign(
                ch.statement.nativeSigningBytes, keyData: keyData, reason: Self.reason(for: item.request)
            )
            phase(.sending)
            try await c.approve(id: item.request.id, signature: sig)
            decidedHere.insert(item.id)
            record(item, .approved)
            pending.removeAll { $0.id == item.id }
            phase(.approved)
        } catch ApprovalKey.KeyError.cancelled {
            phase(.idle)
        } catch {
            phase(.failed(Self.describe(error)))
        }
    }

    func deny(_ item: PendingItem) async -> String? {
        do {
            try await client(for: item.broker).deny(id: item.request.id)
            decidedHere.insert(item.id)
            record(item, .denied)
            pending.removeAll { $0.id == item.id }
            return nil
        } catch {
            return Self.describe(error)
        }
    }

    private func record(_ item: PendingItem, _ outcome: HistoryEntry.Outcome) {
        let e = HistoryEntry(request: item.request, brokerOrigin: item.broker.origin, outcome: outcome, at: Date())
        history.removeAll { $0.id == e.id }
        history.insert(e, at: 0)
        LocalStore.saveHistory(history)
    }

    func clearHistory() {
        history = []
        LocalStore.saveHistory([])
    }

    static func reason(for r: PendingRequest) -> String {
        switch r.kind {
        case .credential(let d):
            let host = Formatting.siteHost(d.verifiedOrigin)
            return d.action == "register" ? "Approve a new passkey for \(host)" : "Approve sign-in to \(host)"
        case .pair(let p):
            return "Approve adding a new phone (code \(p.check))"
        case .unknown:
            return "Approve request"
        }
    }

    static func describe(_ error: Error) -> String {
        if let e = error as? BrokerError { return e.description }
        if let e = error as? StatementError { return e.description }
        if let e = error as? ApprovalKey.KeyError { return e.errorDescription ?? "Face ID failed." }
        if let e = error as? URLError {
            switch e.code {
            case .notConnectedToInternet, .networkConnectionLost: return "No network connection."
            case .timedOut: return "The broker didn't answer in time."
            case .cannotFindHost, .cannotConnectToHost, .dnsLookupFailed:
                return "Can't reach the broker. Is it running, and is this iPhone on your tailnet?"
            case .serverCertificateUntrusted, .serverCertificateHasBadDate, .secureConnectionFailed:
                return "The broker's certificate isn't trusted."
            default: return e.localizedDescription
            }
        }
        return error.localizedDescription
    }

    // MARK: - Pairing

    func add(_ broker: PairedBroker, token: String, keyData: Data) throws {
        try Keychain.set(Data(token.utf8), account: broker.tokenAccount)
        try Keychain.set(keyData, account: broker.keyAccount)
        brokers.append(broker)
        LocalStore.saveBrokers(brokers)
        if let t = pushToken { registerPush(t, with: broker) }
        Task { await refresh() }
    }

    /// Forgets a broker here and asks it to drop this phone. Returns a note for the user.
    func unpair(_ broker: PairedBroker) async -> String {
        var note = "Unpaired from \(broker.host)."
        do {
            let keyRemoved = try await client(for: broker).unpair()
            if !keyRemoved {
                note += " It was this broker's last phone, so the broker still lists its key until you run `keyflap approver remove \(broker.keyId)` (the key itself is deleted from this iPhone)."
            }
        } catch {
            note += " The broker couldn't be told (\(Self.describe(error))); remove this phone there with `keyflap approver remove \(broker.keyId)`."
        }
        Keychain.delete(broker.tokenAccount)
        Keychain.delete(broker.keyAccount)
        brokers.removeAll { $0.id == broker.id }
        status[broker.id] = nil
        pending.removeAll { $0.broker.id == broker.id }
        LocalStore.saveBrokers(brokers)
        return note
    }

    // MARK: - Push

    func refreshNotificationStatus() async {
        notificationStatus = await Push.authorizationStatus()
    }

    func requestNotifications() async {
        _ = await Push.requestPermission()
        notificationStatus = await Push.authorizationStatus()
    }

    func pushTokenChanged(_ hex: String) {
        pushToken = hex
        pushProblem = nil
        for b in brokers { registerPush(hex, with: b) }
    }

    func pushUnavailable(_ why: String) {
        pushProblem = why
    }

    private func registerPush(_ token: String, with b: PairedBroker) {
        let c = client(for: b)
        Task {
            do {
                try await c.registerPush(token: token, environment: Push.environment)
            } catch {
                self.pushProblem = "\(b.host): \(Self.describe(error))"
            }
        }
    }

    /// From a notification tap or the lock-screen Approve: show that request once known.
    func openFromNotification(requestId: String?, autoApprove: Bool) {
        if let rid = requestId, let item = pending.first(where: { $0.request.id == rid }) {
            offered.insert(item.id)
            active = ActiveRequest(item: item, autoApprove: autoApprove)
            return
        }
        openRequest = (requestId, autoApprove)
        Task { await refresh() }
    }

    /// The lock-screen Deny: needs only the bearer token, no Face ID.
    func denyFromNotification(requestId: String) async {
        await refresh()
        if let item = pending.first(where: { $0.request.id == requestId }) {
            _ = await deny(item)
            return
        }
        for b in brokers {
            try? await client(for: b).deny(id: requestId)
        }
    }
}
