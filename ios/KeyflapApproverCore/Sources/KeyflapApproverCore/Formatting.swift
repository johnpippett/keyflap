import Foundation

/// Text the app shows, in the broker's own wording where one exists (render.ts / app.js).
public enum Formatting {
    /// Control characters and bidi controls become U+FFFD, so nothing in the user's words
    /// or an agent name can reorder or hide what the user reads. Same set as the broker's
    /// terminal prompt and phone page.
    public static func clean(_ s: String) -> String {
        var out = String.UnicodeScalarView()
        for u in s.unicodeScalars {
            let v = u.value
            let bad = (v <= 0x08) || (v >= 0x0b && v <= 0x1f) || (v >= 0x7f && v <= 0x9f) || v == 0x061c
                || v == 0x200e || v == 0x200f || (v >= 0x202a && v <= 0x202e) || (v >= 0x2066 && v <= 0x2069)
            out.append(bad ? "\u{FFFD}" : u)
        }
        return String(out)
    }

    public static func credentialLabel(_ type: String) -> String {
        switch type {
        case "passkey": return "Passkey"
        case "password": return "Password"
        case "password+totp": return "Password + one-time code"
        case "totp": return "One-time code"
        default: return "Unknown credential"
        }
    }

    /// The title of a request card.
    public static func title(for request: PendingRequest) -> String {
        switch request.kind {
        case .credential(let d): return d.action == "register" ? "Add a passkey?" : "Sign in?"
        case .pair(let p): return p.newDevice == "ios-app" ? "Add another iPhone?" : "Add another phone?"
        case .unknown: return "Unknown request"
        }
    }

    /// "30 minutes", "2 hours", "1 hour 30 minutes", "45 seconds" (`formatDuration`).
    public static func duration(ms: Int64) -> String {
        func unit(_ n: Int64, _ w: String) -> String { "\(n) \(w)\(n == 1 ? "" : "s")" }
        let s = Int64((Double(ms) / 1000).rounded(.toNearestOrAwayFromZero))
        if s < 60 { return unit(s, "second") }
        let m = Int64((Double(s) / 60).rounded(.toNearestOrAwayFromZero))
        if m < 60 { return unit(m, "minute") }
        let h = m / 60
        let rest = m % 60
        return rest == 0 ? unit(h, "hour") : "\(unit(h, "hour")) \(unit(rest, "minute"))"
    }

    /// The broker-authored allow-for line (`allowForText`).
    public static func allowForText(ms: Int64) -> String {
        "approving also lets this agent sign in here again without asking, for \(duration(ms: ms))"
    }

    /// The host of an origin for the big headline ("github.com"), or the origin itself.
    public static func siteHost(_ origin: String) -> String {
        OriginParts(origin).map { $0.host + ($0.port.map { ":\($0)" } ?? "") } ?? clean(origin)
    }

    /// "1:05" for a countdown.
    public static func countdown(ms: Int64) -> String {
        let s = max(0, Int((Double(ms) / 1000).rounded(.up)))
        return "\(s / 60):\(String(format: "%02d", s % 60))"
    }

    /// Extra display fields from a newer broker, as "key: value" lines (never hidden).
    public static func extraLines(_ extra: [String: JSONValue]) -> [String] {
        extra.keys.sorted().map { k in
            let v = extra[k]!
            let text: String
            switch v {
            case .string(let s): text = s
            default: text = CanonicalJSON.encode(v)
            }
            return clean("\(k): \(text)")
        }
    }
}
