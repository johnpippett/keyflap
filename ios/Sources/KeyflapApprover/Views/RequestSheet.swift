import KeyflapApproverCore
import SwiftUI

/// The incoming-request sheet. Shows only the broker's display fields (invariant 5): the
/// site's verified origin, the agent's name, the user's own words, the credential type,
/// and broker-authored lines (time, allow-for window). Approve checks the statement
/// against exactly this, then signs it with the Secure Enclave key (Face ID).
struct RequestSheet: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    let active: ActiveRequest

    @State private var phase: ApprovalPhase = .idle
    @State private var denyError: String?
    @State private var started = false

    private var item: PendingItem { active.item }
    private var request: PendingRequest { item.request }
    private var ended: Bool { !model.isPending(item) && phase != .approved && phase != .denied }
    private var busy: Bool { ([.checking, .biometry, .sending] as [ApprovalPhase]).contains(phase) }

    var body: some View {
        ZStack {
            Theme.background.ignoresSafeArea()
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    header
                    switch request.kind {
                    case .credential(let d): credential(d)
                    case .pair(let p): pair(p)
                    case .unknown(let kind): unknown(kind)
                    }
                }
                .padding(.horizontal, 20)
                .padding(.top, 24)
                .padding(.bottom, 160)
            }
            VStack {
                Spacer()
                actions
            }
            if phase == .approved || phase == .denied {
                ResultOverlay(approved: phase == .approved)
                    .transition(.opacity.combined(with: .scale(scale: 0.9)))
            }
        }
        .animation(.spring(duration: 0.35), value: phase)
        .sensoryFeedback(.success, trigger: phase) { _, new in new == .approved }
        .sensoryFeedback(.warning, trigger: phase) { _, new in new == .denied }
        .sensoryFeedback(.error, trigger: phase) { _, new in new.isFailure }
        .task {
            // Lock-screen Approve: show the details first, then start Face ID.
            guard active.autoApprove, !started else { return }
            try? await Task.sleep(nanoseconds: 700_000_000)
            approve()
        }
    }

    // MARK: Header

    private var header: some View {
        HStack(alignment: .center) {
            switch request.kind {
            case .credential(let d):
                Tag(text: d.action == "register" ? "New passkey" : "Sign-in request")
            case .pair:
                Tag(text: "Add a phone", color: Theme.notice)
            case .unknown:
                Tag(text: "Unknown request", color: .secondary)
            }
            Spacer()
            if !ended {
                CountdownRing(
                    expiresAt: request.expiresAt,
                    total: request.expiresAt - request.createdAt,
                    now: { model.brokerNow(item.broker) }
                )
            }
        }
    }

    // MARK: Credential request

    @ViewBuilder
    private func credential(_ d: Display) -> some View {
        let host = Formatting.siteHost(d.verifiedOrigin)
        VStack(alignment: .leading, spacing: 14) {
            SiteMonogram(host: host)
            Text(d.action == "register" ? "Add a passkey for" : "Sign in to")
                .font(.title3)
                .foregroundStyle(.secondary)
            Text(host)
                .font(.largeTitle.weight(.bold))
                .fontDesign(.rounded)
                .lineLimit(2)
                .minimumScaleFactor(0.5)
                .textSelection(.enabled)
                .accessibilityLabel("Site \(host)")
            Label {
                Text(Formatting.clean(d.verifiedOrigin)).font(.footnote.monospaced())
            } icon: {
                Image(systemName: "checkmark.seal.fill").foregroundStyle(Theme.approve)
            }
            .foregroundStyle(.secondary)
            .accessibilityElement(children: .combine)
            .accessibilityLabel("Verified origin \(d.verifiedOrigin), checked by the broker")
        }

        Card {
            Text("You said")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .textCase(.uppercase)
            Text("“\(Formatting.clean(d.intentText))”")
                .font(.title3)
                .fontDesign(.serif)
                .italic()
                .fixedSize(horizontal: false, vertical: true)
                .textSelection(.enabled)
            Text("\(Date(timeIntervalSince1970: Double(d.intentAt) / 1000), style: .relative) ago")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .accessibilityElement(children: .combine)

        Card {
            DetailRow(icon: "cpu", label: "Agent", value: Formatting.clean(d.agentName))
            Divider()
            DetailRow(icon: d.credentialType == "passkey" ? "person.badge.key" : "key.horizontal",
                      label: "Credential", value: Formatting.credentialLabel(d.credentialType))
            Divider()
            DetailRow(icon: "clock", label: "Requested",
                      value: Date(timeIntervalSince1970: Double(request.createdAt) / 1000).formatted(date: .omitted, time: .standard))
            Divider()
            DetailRow(icon: "server.rack", label: "Broker", value: item.broker.host)
        }

        if let ms = d.allowForMs {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: "clock.arrow.circlepath")
                    .font(.title3)
                    .foregroundStyle(Theme.notice)
                    .accessibilityHidden(true)
                Text(sentence(Formatting.allowForText(ms: ms)) + ".")
                    .font(.callout.weight(.medium))
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(14)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Theme.notice.opacity(0.12), in: RoundedRectangle(cornerRadius: 16, style: .continuous))
            .accessibilityElement(children: .combine)
        }

        if !d.extra.isEmpty {
            Card {
                Text("Other details from the broker")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                ForEach(Formatting.extraLines(d.extra), id: \.self) { line in
                    Text(line).font(.footnote.monospaced())
                }
            }
        }
    }

    // MARK: Pair request

    @ViewBuilder
    private func pair(_ p: PairView) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Image(systemName: p.newDevice == "ios-app" ? "iphone.badge.plus" : "plus.app")
                .font(.system(size: 44))
                .foregroundStyle(Theme.notice)
                .accessibilityHidden(true)
            Text(Formatting.title(for: request))
                .font(.largeTitle.weight(.bold))
                .fontDesign(.rounded)
            Text("Someone used a pairing link to add \(p.newDevice == "ios-app" ? "an iPhone with the Keyflap app" : "a phone") as an approver for \(item.broker.host).")
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        Card {
            Text("Check code")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .textCase(.uppercase)
            Text(p.check)
                .font(.system(.largeTitle, design: .monospaced).weight(.semibold))
                .minimumScaleFactor(0.5)
                .lineLimit(1)
                .accessibilityLabel("Check code \(p.check.map { String($0) }.joined(separator: " "))")
            Label("Approve only if the new phone shows exactly this code. If you didn't start pairing, deny.",
                  systemImage: "exclamationmark.shield")
                .font(.callout)
                .foregroundStyle(Theme.notice)
        }
    }

    @ViewBuilder
    private func unknown(_ kind: String) -> some View {
        Text("This version of Keyflap can't show this request (\(Formatting.clean(kind))), so it can't be approved here. Update the app, or deny it.")
            .font(.body)
            .fixedSize(horizontal: false, vertical: true)
    }

    // MARK: Actions

    private var actions: some View {
        VStack(spacing: 10) {
            if ended {
                Label("This request has ended: it expired, was withdrawn, or was answered on another phone.",
                      systemImage: "clock.badge.xmark")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                Button("Close") { dismiss() }
                    .buttonStyle(.bordered)
                    .controlSize(.large)
            } else {
                statusLine
                HStack(spacing: 12) {
                    Button(role: .destructive) {
                        deny()
                    } label: {
                        Label("Deny", systemImage: "xmark")
                            .font(.headline)
                            .frame(maxWidth: .infinity, minHeight: 56)
                    }
                    .buttonStyle(.bordered)
                    .tint(Theme.deny)
                    .disabled(busy)
                    .accessibilityHint("Refuses this request. No Face ID needed.")

                    if approvable {
                        Button {
                            approve()
                        } label: {
                            Label("Approve", systemImage: "faceid")
                                .font(.headline)
                                .frame(maxWidth: .infinity, minHeight: 56)
                        }
                        .buttonStyle(.borderedProminent)
                        .tint(Theme.approve)
                        .disabled(busy)
                        .accessibilityHint("Approves with \(ApprovalKey.biometryName)")
                    }
                }
                .buttonBorderShape(.roundedRectangle(radius: 16))
            }
        }
        .padding(.horizontal, 20)
        .padding(.top, 14)
        .padding(.bottom, 8)
        .background(.regularMaterial)
    }

    private var approvable: Bool {
        if case .unknown = request.kind { return false }
        return true
    }

    @ViewBuilder
    private var statusLine: some View {
        switch phase {
        case .checking:
            ProgressView("Checking the request…").font(.callout)
        case .biometry:
            Label("Confirm with \(ApprovalKey.biometryName)", systemImage: "faceid").font(.callout)
        case .sending:
            ProgressView("Sending your approval…").font(.callout)
        case .failed(let message):
            Label(message, systemImage: "exclamationmark.triangle.fill")
                .font(.callout)
                .foregroundStyle(Theme.deny)
                .fixedSize(horizontal: false, vertical: true)
        default:
            if let denyError {
                Label(denyError, systemImage: "exclamationmark.triangle.fill")
                    .font(.callout)
                    .foregroundStyle(Theme.deny)
            }
        }
    }

    private func approve() {
        guard !busy, !ended else { return }
        started = true
        Task {
            await model.approve(item) { p in phase = p }
            if phase == .approved { await closeSoon() }
        }
    }

    private func deny() {
        guard !busy else { return }
        started = true
        Task {
            if let err = await model.deny(item) {
                denyError = err
            } else {
                phase = .denied
                await closeSoon()
            }
        }
    }

    private func closeSoon() async {
        try? await Task.sleep(nanoseconds: 1_300_000_000)
        dismiss()
    }

    private func sentence(_ s: String) -> String {
        s.prefix(1).uppercased() + s.dropFirst()
    }
}

extension ApprovalPhase {
    var isFailure: Bool {
        if case .failed = self { return true }
        return false
    }
}

/// The big checkmark / cross after a decision.
struct ResultOverlay: View {
    let approved: Bool
    @State private var shown = false

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: approved ? "checkmark.circle.fill" : "xmark.circle.fill")
                .font(.system(size: 96, weight: .semibold))
                .foregroundStyle(.white, approved ? Theme.approve : Theme.deny)
                .symbolEffect(.bounce, value: shown)
            Text(approved ? "Approved" : "Denied")
                .font(.title.weight(.bold))
                .fontDesign(.rounded)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(.ultraThinMaterial)
        .onAppear { shown = true }
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isStaticText)
    }
}
