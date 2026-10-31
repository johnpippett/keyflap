import KeyflapApproverCore
import SwiftUI

struct HomeView: View {
    @EnvironmentObject private var model: AppModel
    @State private var pairing = false

    var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                StatusHero()
                if model.brokers.isEmpty {
                    WelcomeCard { pairing = true }
                } else {
                    if !model.pending.isEmpty { pendingSection }
                    brokersSection
                    activitySection
                }
            }
            .padding(.horizontal)
            .padding(.bottom, 32)
        }
        .background(Theme.background.ignoresSafeArea())
        .refreshable { await model.refresh() }
        .navigationTitle("Keyflap")
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                NavigationLink {
                    SettingsView()
                } label: {
                    Image(systemName: "gearshape")
                }
                .accessibilityLabel("Settings")
            }
        }
        .sheet(isPresented: $pairing) {
            PairingView()
                .environmentObject(model)
        }
    }

    private var pendingSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionHeader(title: "Waiting for you")
            ForEach(model.pending) { item in
                Button { model.show(item) } label: { PendingCard(item: item) }
                    .buttonStyle(.plain)
            }
        }
    }

    private var brokersSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionHeader(title: model.brokers.count == 1 ? "Broker" : "Brokers")
            Card(padding: 0) {
                ForEach(Array(model.brokers.enumerated()), id: \.element.id) { index, b in
                    if index > 0 { Divider().padding(.leading, 56) }
                    BrokerRow(broker: b, status: model.status[b.id] ?? BrokerStatus())
                        .padding(.horizontal, 16)
                        .padding(.vertical, 12)
                }
            }
        }
    }

    private var activitySection: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                SectionHeader(title: "Recent activity")
                Spacer()
                if !model.history.isEmpty {
                    NavigationLink("See all") { HistoryView() }
                        .font(.subheadline.weight(.medium))
                }
            }
            if model.history.isEmpty {
                Card {
                    Label("Approvals and denials made on this iPhone show up here.", systemImage: "clock")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
            } else {
                Card(padding: 0) {
                    ForEach(Array(model.history.prefix(5).enumerated()), id: \.element.id) { index, e in
                        if index > 0 { Divider().padding(.leading, 56) }
                        HistoryRow(entry: e)
                            .padding(.horizontal, 16)
                            .padding(.vertical, 10)
                    }
                }
            }
        }
    }
}

struct SectionHeader: View {
    let title: String

    var body: some View {
        Text(title)
            .font(.headline)
            .foregroundStyle(.secondary)
            .accessibilityAddTraits(.isHeader)
    }
}

/// The calm top of the home screen: a shield and one line of status.
struct StatusHero: View {
    @EnvironmentObject private var model: AppModel
    @ScaledMetric(relativeTo: .largeTitle) private var size: CGFloat = 76

    private var line: (String, String) {
        if model.brokers.isEmpty { return ("Not paired yet", "Pair this iPhone with your Keyflap broker to approve sign-ins.") }
        let n = model.pending.count
        if n > 0 { return (n == 1 ? "1 request waiting" : "\(n) requests waiting", "Review it before your agent signs in.") }
        let offline = model.brokers.filter {
            if case .offline = model.status[$0.id]?.reachability { return true }
            return false
        }
        if !offline.isEmpty { return ("Can't reach \(offline.count == 1 ? offline[0].host : "\(offline.count) brokers")", "Pull down to try again.") }
        return ("All quiet", "Nothing is waiting. Requests appear here the moment an agent needs to sign in.")
    }

    var body: some View {
        VStack(spacing: 12) {
            ZStack {
                Circle()
                    .fill(LinearGradient(colors: [Theme.accent.opacity(0.25), Theme.accent.opacity(0.08)], startPoint: .top, endPoint: .bottom))
                Image(systemName: model.pending.isEmpty ? "checkmark.shield.fill" : "bell.badge.fill")
                    .font(.system(size: size * 0.42, weight: .semibold))
                    .foregroundStyle(Theme.accent)
                    .symbolEffect(.bounce, value: model.pending.count)
                    .contentTransition(.symbolEffect(.replace))
            }
            .frame(width: size, height: size)
            .accessibilityHidden(true)
            Text(line.0)
                .font(.title2.weight(.bold))
                .fontDesign(.rounded)
            Text(line.1)
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity)
        .padding(.top, 8)
        .accessibilityElement(children: .combine)
    }
}

struct WelcomeCard: View {
    let pair: () -> Void

    var body: some View {
        Card(padding: 20) {
            Text("How it works")
                .font(.headline)
            Step(n: 1, text: "On the broker machine, start the daemon with --approver phone. It prints a pairing QR code.")
            Step(n: 2, text: "Scan it here. This iPhone makes an approval key in its Secure Enclave, protected by \(ApprovalKey.biometryName).")
            Step(n: 3, text: "When an agent needs to sign in, you see the site, the agent and your own words, and approve with \(ApprovalKey.biometryName).")
            Button(action: pair) {
                Label("Pair with a broker", systemImage: "qrcode.viewfinder")
                    .font(.headline)
                    .frame(maxWidth: .infinity, minHeight: 50)
            }
            .buttonStyle(.borderedProminent)
            .buttonBorderShape(.roundedRectangle(radius: 14))
            .padding(.top, 4)
        }
    }

    struct Step: View {
        let n: Int
        let text: String

        var body: some View {
            HStack(alignment: .top, spacing: 12) {
                Text("\(n)")
                    .font(.footnote.weight(.bold))
                    .foregroundStyle(.white)
                    .frame(width: 24, height: 24)
                    .background(Theme.accent, in: Circle())
                    .accessibilityHidden(true)
                Text(text)
                    .font(.callout)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

struct PendingCard: View {
    @EnvironmentObject private var model: AppModel
    let item: PendingItem

    var body: some View {
        Card {
            HStack(spacing: 14) {
                switch item.request.kind {
                case .credential(let d):
                    SiteMonogram(host: Formatting.siteHost(d.verifiedOrigin))
                        .scaleEffect(0.75)
                        .frame(width: 48, height: 48)
                    VStack(alignment: .leading, spacing: 3) {
                        Text(Formatting.siteHost(d.verifiedOrigin))
                            .font(.headline)
                            .lineLimit(1)
                        Text("\(Formatting.clean(d.agentName)) · \(Formatting.credentialLabel(d.credentialType))")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }
                case .pair:
                    Image(systemName: "iphone.badge.plus")
                        .font(.title)
                        .foregroundStyle(Theme.accent)
                        .frame(width: 48, height: 48)
                    Text("Add another phone?").font(.headline)
                case .unknown:
                    Image(systemName: "questionmark.circle").font(.title).frame(width: 48, height: 48)
                    Text("Unknown request").font(.headline)
                }
                Spacer()
                CountdownRing(
                    expiresAt: item.request.expiresAt,
                    total: item.request.expiresAt - item.request.createdAt,
                    now: { model.brokerNow(item.broker) }
                )
                .scaleEffect(0.8)
            }
        }
        .overlay {
            RoundedRectangle(cornerRadius: 20, style: .continuous)
                .strokeBorder(Theme.accent.opacity(0.35), lineWidth: 1)
        }
        .accessibilityElement(children: .combine)
        .accessibilityHint("Opens the request to approve or deny")
    }
}

struct BrokerRow: View {
    let broker: PairedBroker
    let status: BrokerStatus

    private var dot: (Color, String) {
        switch status.reachability {
        case .unknown: return (.secondary, "Checking…")
        case .online: return (Theme.approve, status.apnsRegistered ? "Connected · push on" : "Connected")
        case .offline(let why): return (Theme.notice, why)
        case .unpaired: return (Theme.deny, "No longer paired. Unpair and pair again.")
        }
    }

    var body: some View {
        HStack(spacing: 14) {
            Image(systemName: "server.rack")
                .font(.title3)
                .foregroundStyle(Theme.accent)
                .frame(width: 28)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                Text(broker.host).font(.body.weight(.semibold)).lineLimit(1)
                HStack(spacing: 6) {
                    Circle().fill(dot.0).frame(width: 8, height: 8).accessibilityHidden(true)
                    Text(dot.1).font(.caption).foregroundStyle(.secondary).lineLimit(2)
                }
            }
            Spacer()
        }
        .accessibilityElement(children: .combine)
    }
}
