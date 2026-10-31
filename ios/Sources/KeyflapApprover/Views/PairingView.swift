import AVFoundation
import KeyflapApproverCore
import SwiftUI

/// Pairing: scan the broker's QR code (or paste its link). The app makes a new Secure
/// Enclave key, signs a proof with it (the first Face ID), and registers it with the
/// one-time code. A second phone waits until an already-paired phone approves it; both
/// show the same check code.
@MainActor
final class PairingFlow: ObservableObject {
    enum Step: Equatable {
        case input
        case working(String)
        case waiting(check: String, host: String)
        case done(host: String)
        case failed(String)
    }

    @Published var step: Step = .input
    private var task: Task<Void, Never>?

    func start(_ raw: String, model: AppModel) {
        guard case .input = step else { return }
        let link: PairingLink
        do {
            link = try PairingLink.parse(raw)
        } catch {
            step = .failed("\(error)")
            return
        }
        if model.brokers.contains(where: { $0.origin == link.origin }) {
            step = .failed("This iPhone is already paired with \(Formatting.siteHost(link.origin)). Unpair it in Settings first to pair again.")
            return
        }
        task = Task { await run(link, model: model) }
    }

    func cancel() {
        task?.cancel()
    }

    func reset() {
        task?.cancel()
        step = .input
    }

    private func run(_ link: PairingLink, model: AppModel) async {
        let host = Formatting.siteHost(link.origin)
        do {
            step = .working("Creating this iPhone's approval key…")
            let key = try ApprovalKey.create()
            let (x, y, keyId) = ApprovalKey.publicCoordinates(key)
            let descriptor = ApproverEncoding.nativeApproverDescriptor(keyId: keyId, x: x, y: y, origin: link.origin)
            step = .working("Confirm with \(ApprovalKey.biometryName) to pair…")
            let proof = try await ApprovalKey.sign(
                ApproverEncoding.pairingProofBytes(descriptor: descriptor),
                keyData: key.dataRepresentation,
                reason: "Pair this iPhone with \(host)"
            )
            step = .working("Pairing with \(host)…")
            let client = BrokerClient(origin: link.origin, deviceToken: nil, transport: URLSessionTransport())
            let token: String
            switch try await client.pair(code: link.code, x: x, y: y, proof: proof) {
            case .paired(let t, _):
                token = t
            case .waiting(let check, _):
                step = .waiting(check: check, host: host)
                token = try await waitForApproval(client, code: link.code)
            }
            let broker = PairedBroker(id: UUID(), origin: link.origin, keyId: keyId, pairedAt: Date())
            try model.add(broker, token: token, keyData: key.dataRepresentation)
            step = .done(host: host)
            if model.notificationStatus == .notDetermined { await model.requestNotifications() }
        } catch is CancellationError {
            step = .input
        } catch ApprovalKey.KeyError.cancelled {
            step = .failed("Pairing needs \(ApprovalKey.biometryName). Scan the code again to retry (it's valid for 10 minutes).")
        } catch {
            step = .failed(AppModel.describe(error))
        }
    }

    private func waitForApproval(_ client: BrokerClient, code: String) async throws -> String {
        let deadline = Date().addingTimeInterval(10 * 60)
        while Date() < deadline {
            try await Task.sleep(nanoseconds: 2_000_000_000)
            switch try await client.pairStatus(code: code) {
            case .paired(let token): return token
            case .waiting: continue
            case .failed: throw BrokerError.server(status: 409, code: "not_approved")
            }
        }
        throw BrokerError.server(status: 408, code: "not_approved")
    }
}

struct PairingView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @StateObject private var flow = PairingFlow()
    @State private var pasted = ""
    @State private var camera = AVCaptureDevice.authorizationStatus(for: .video)

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 20) {
                    switch flow.step {
                    case .input: input
                    case .working(let message): working(message)
                    case .waiting(let check, let host): waiting(check, host)
                    case .done(let host): done(host)
                    case .failed(let message): failed(message)
                    }
                }
                .padding(20)
            }
            .background(Theme.background.ignoresSafeArea())
            .navigationTitle("Pair a broker")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(flow.step == .done(host: doneHost) ? "Done" : "Cancel") {
                        flow.cancel()
                        dismiss()
                    }
                }
            }
            .sensoryFeedback(.success, trigger: flow.step) { _, new in
                if case .done = new { return true }
                return false
            }
        }
    }

    private var doneHost: String {
        if case .done(let h) = flow.step { return h }
        return ""
    }

    // MARK: Steps

    @ViewBuilder
    private var input: some View {
        Text("On the broker machine, the daemon shows a QR code when a phone can pair (or run `keyflap approver qr`).")
            .font(.callout)
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.center)
            .fixedSize(horizontal: false, vertical: true)

        scanner
            .frame(height: 300)
            .clipShape(RoundedRectangle(cornerRadius: 24, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: 24, style: .continuous)
                    .strokeBorder(Theme.accent.opacity(0.5), lineWidth: 2)
            )

        HStack {
            VStack { Divider() }
            Text("or").font(.footnote).foregroundStyle(.secondary)
            VStack { Divider() }
        }

        Card {
            Text("Paste the pairing link")
                .font(.subheadline.weight(.semibold))
            TextField("https://…/pair#…", text: $pasted, axis: .vertical)
                .font(.footnote.monospaced())
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .keyboardType(.URL)
                .lineLimit(1...3)
            HStack {
                PasteButton(payloadType: String.self) { strings in
                    let s = strings.first
                    Task { @MainActor in
                        if let s { pasted = s }
                    }
                }
                .labelStyle(.titleAndIcon)
                Spacer()
                Button("Pair") { flow.start(pasted, model: model) }
                    .buttonStyle(.borderedProminent)
                    .disabled(pasted.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }

        Label("Treat the link like a password: whoever uses it first becomes an approver. It works once and expires after 10 minutes.",
              systemImage: "lock.shield")
            .font(.footnote)
            .foregroundStyle(.secondary)
    }

    @ViewBuilder
    private var scanner: some View {
        switch camera {
        case .authorized:
            QRScannerView { code in flow.start(code, model: model) }
        case .notDetermined:
            placeholder("Scan with the camera", button: "Allow camera") {
                AVCaptureDevice.requestAccess(for: .video) { _ in
                    Task { @MainActor in camera = AVCaptureDevice.authorizationStatus(for: .video) }
                }
            }
        default:
            placeholder("Camera access is off. Allow it in Settings, or paste the link below.", button: "Open Settings") {
                if let url = URL(string: UIApplication.openSettingsURLString) { UIApplication.shared.open(url) }
            }
        }
    }

    private func placeholder(_ text: String, button: String, action: @escaping () -> Void) -> some View {
        VStack(spacing: 14) {
            Image(systemName: "qrcode.viewfinder")
                .font(.system(size: 54))
                .foregroundStyle(Theme.accent)
                .accessibilityHidden(true)
            Text(text).multilineTextAlignment(.center).foregroundStyle(.secondary)
            Button(button, action: action).buttonStyle(.bordered)
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Theme.card)
    }

    private func working(_ message: String) -> some View {
        VStack(spacing: 16) {
            ProgressView().controlSize(.large)
            Text(message).font(.headline).multilineTextAlignment(.center)
        }
        .padding(.top, 60)
    }

    private func waiting(_ check: String, _ host: String) -> some View {
        VStack(spacing: 18) {
            Image(systemName: "iphone.and.arrow.forward")
                .font(.system(size: 48))
                .foregroundStyle(Theme.accent)
                .accessibilityHidden(true)
            Text("Approve on your other phone")
                .font(.title2.weight(.bold))
                .fontDesign(.rounded)
            Text("\(host) already has a phone. On it, approve the request that shows this code:")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
            Text(check)
                .font(.system(.largeTitle, design: .monospaced).weight(.semibold))
                .minimumScaleFactor(0.5)
                .lineLimit(1)
                .padding(.vertical, 14)
                .padding(.horizontal, 20)
                .background(Theme.card, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
                .accessibilityLabel("Check code \(check.map { String($0) }.joined(separator: " "))")
            ProgressView()
        }
        .padding(.top, 30)
    }

    private func done(_ host: String) -> some View {
        VStack(spacing: 16) {
            Image(systemName: "checkmark.circle.fill")
                .font(.system(size: 72))
                .foregroundStyle(Theme.approve)
                .symbolEffect(.bounce, value: host)
                .accessibilityHidden(true)
            Text("Paired with \(host)")
                .font(.title2.weight(.bold))
                .fontDesign(.rounded)
                .multilineTextAlignment(.center)
            Text("Sign-in requests from this broker will appear here. Approving always takes \(ApprovalKey.biometryName).")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
            Button("Done") { dismiss() }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
        }
        .padding(.top, 40)
    }

    private func failed(_ message: String) -> some View {
        VStack(spacing: 16) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 56))
                .foregroundStyle(Theme.notice)
                .accessibilityHidden(true)
            Text(message)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
            Button("Try again") {
                pasted = ""
                flow.reset()
            }
            .buttonStyle(.borderedProminent)
        }
        .padding(.top, 40)
    }
}

/// A camera view that reports the first QR code it sees.
struct QRScannerView: UIViewControllerRepresentable {
    let onCode: (String) -> Void

    func makeUIViewController(context: Context) -> ScannerController {
        let c = ScannerController()
        c.onCode = onCode
        return c
    }

    func updateUIViewController(_ controller: ScannerController, context: Context) {}

    final class ScannerController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
        var onCode: ((String) -> Void)?
        private let session = AVCaptureSession()
        private var preview: AVCaptureVideoPreviewLayer?
        private var reported = false

        override func viewDidLoad() {
            super.viewDidLoad()
            view.backgroundColor = .black
            guard let device = AVCaptureDevice.default(for: .video),
                  let input = try? AVCaptureDeviceInput(device: device),
                  session.canAddInput(input)
            else { return }
            session.addInput(input)
            let output = AVCaptureMetadataOutput()
            guard session.canAddOutput(output) else { return }
            session.addOutput(output)
            output.setMetadataObjectsDelegate(self, queue: .main)
            output.metadataObjectTypes = [.qr]
            let layer = AVCaptureVideoPreviewLayer(session: session)
            layer.videoGravity = .resizeAspectFill
            view.layer.addSublayer(layer)
            preview = layer
        }

        override func viewDidLayoutSubviews() {
            super.viewDidLayoutSubviews()
            preview?.frame = view.bounds
        }

        override func viewWillAppear(_ animated: Bool) {
            super.viewWillAppear(animated)
            let s = session
            DispatchQueue.global(qos: .userInitiated).async { if !s.isRunning { s.startRunning() } }
        }

        override func viewWillDisappear(_ animated: Bool) {
            super.viewWillDisappear(animated)
            let s = session
            DispatchQueue.global(qos: .userInitiated).async { if s.isRunning { s.stopRunning() } }
        }

        func metadataOutput(
            _ output: AVCaptureMetadataOutput,
            didOutput metadataObjects: [AVMetadataObject],
            from connection: AVCaptureConnection
        ) {
            guard !reported,
                  let obj = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
                  let value = obj.stringValue
            else { return }
            reported = true
            let s = session
            DispatchQueue.global(qos: .userInitiated).async { s.stopRunning() }
            onCode?(value)
        }
    }
}
