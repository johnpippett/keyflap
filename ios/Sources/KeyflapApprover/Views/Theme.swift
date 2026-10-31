import KeyflapApproverCore
import SwiftUI
import UIKit

enum Theme {
    /// A calm indigo-blue, a little lighter in dark mode.
    static let accent = Color(UIColor { t in
        t.userInterfaceStyle == .dark
            ? UIColor(red: 0.45, green: 0.56, blue: 1.0, alpha: 1)
            : UIColor(red: 0.22, green: 0.33, blue: 0.86, alpha: 1)
    })
    static let approve = Color(UIColor.systemGreen)
    static let deny = Color(UIColor.systemRed)
    static let card = Color(UIColor.secondarySystemGroupedBackground)
    static let background = Color(UIColor.systemGroupedBackground)
    static let notice = Color(UIColor.systemOrange)
}

/// A rounded card on the grouped background.
struct Card<Content: View>: View {
    var padding: CGFloat = 16
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 12) { content }
            .padding(padding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Theme.card, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
    }
}

/// A circle with the site's first letter, tinted from the host name (stable per site).
struct SiteMonogram: View {
    let host: String
    @ScaledMetric(relativeTo: .largeTitle) private var size: CGFloat = 64

    private var tint: Color {
        let h = host.unicodeScalars.reduce(UInt32(5381)) { ($0 &* 33) &+ $1.value }
        return Color(hue: Double(h % 360) / 360, saturation: 0.55, brightness: 0.85)
    }

    var body: some View {
        Text(host.isEmpty ? "?" : host.prefix(1).uppercased())
            .font(.system(size: size * 0.45, weight: .bold, design: .rounded))
            .foregroundStyle(.white)
            .frame(width: size, height: size)
            .background(
                LinearGradient(colors: [tint, tint.opacity(0.7)], startPoint: .topLeading, endPoint: .bottomTrailing),
                in: RoundedRectangle(cornerRadius: size * 0.28, style: .continuous)
            )
            .accessibilityHidden(true)
    }
}

/// A small capsule label ("SIGN-IN REQUEST").
struct Tag: View {
    let text: String
    var color: Color = Theme.accent

    var body: some View {
        Text(text.uppercased())
            .font(.caption2.weight(.bold))
            .tracking(0.8)
            .foregroundStyle(color)
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
            .background(color.opacity(0.12), in: Capsule())
    }
}

/// Remaining time as a ring with m:ss, ticking every second against the broker's clock.
struct CountdownRing: View {
    let expiresAt: Int64
    let total: Int64
    let now: () -> Int64

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { _ in
            let left = max(0, expiresAt - now())
            let fraction = total > 0 ? Double(left) / Double(total) : 0
            ZStack {
                Circle().stroke(Color.secondary.opacity(0.2), lineWidth: 4)
                Circle()
                    .trim(from: 0, to: fraction)
                    .stroke(left < 15_000 ? Theme.deny : Theme.accent, style: StrokeStyle(lineWidth: 4, lineCap: .round))
                    .rotationEffect(.degrees(-90))
                    .animation(.linear(duration: 1), value: fraction)
                Text(Formatting.countdown(ms: left))
                    .font(.caption.monospacedDigit().weight(.semibold))
            }
            .frame(width: 52, height: 52)
            .accessibilityElement(children: .ignore)
            .accessibilityLabel("Expires in \(Int((Double(left) / 1000).rounded(.up))) seconds")
        }
    }
}

/// One labelled row on the request sheet.
struct DetailRow: View {
    let icon: String
    let label: String
    let value: String
    var monospaced = false

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Image(systemName: icon)
                .foregroundStyle(.secondary)
                .frame(width: 22)
                .accessibilityHidden(true)
            Text(label)
                .foregroundStyle(.secondary)
            Spacer(minLength: 12)
            Text(value)
                .font(monospaced ? .callout.monospaced() : .callout.weight(.medium))
                .multilineTextAlignment(.trailing)
                .textSelection(.enabled)
        }
        .font(.callout)
        .accessibilityElement(children: .combine)
    }
}

extension HistoryEntry.Outcome {
    var icon: String {
        switch self {
        case .approved: return "checkmark.circle.fill"
        case .denied: return "xmark.circle.fill"
        case .expired: return "clock.badge.xmark"
        case .failed: return "exclamationmark.triangle.fill"
        }
    }

    var color: Color {
        switch self {
        case .approved: return Theme.approve
        case .denied: return Theme.deny
        case .expired: return .secondary
        case .failed: return Theme.notice
        }
    }

    var label: String {
        switch self {
        case .approved: return "Approved"
        case .denied: return "Denied"
        case .expired: return "Ended"
        case .failed: return "Failed"
        }
    }
}

struct HistoryRow: View {
    let entry: HistoryEntry

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: entry.outcome.icon)
                .font(.title3)
                .foregroundStyle(entry.outcome.color)
                .frame(width: 28)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(entry.site.map(Formatting.siteHost) ?? "New phone")
                    .font(.body.weight(.semibold))
                    .lineLimit(1)
                Text(subtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 2) {
                Text(entry.outcome.label).font(.caption.weight(.semibold)).foregroundStyle(entry.outcome.color)
                Text(entry.at, style: .time).font(.caption2).foregroundStyle(.secondary)
            }
        }
        .accessibilityElement(children: .combine)
    }

    private var subtitle: String {
        var parts: [String] = []
        if let a = entry.agentName { parts.append(Formatting.clean(a)) }
        if let c = entry.credentialType { parts.append(Formatting.credentialLabel(c)) }
        if entry.site == nil { parts.append("added on another phone's request") }
        return parts.joined(separator: " · ")
    }
}
