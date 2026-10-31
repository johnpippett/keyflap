import Foundation

/// What the broker shows for a credential request: `ApprovalRequest.display` only
/// (invariant 5) — the user's own words, the verified origin, the agent's name, the
/// credential type, plus fields the broker itself writes. Never page or agent text other
/// than the agent's registered name.
public struct Display: Equatable, Sendable {
    public let intentText: String
    public let intentAt: Int64
    public let verifiedOrigin: String
    public let agentName: String
    public let credentialType: String
    public let action: String
    /// M5 `allow-for` window (broker-authored), if approving would also grant one.
    public let allowForMs: Int64?
    /// Display fields this app version doesn't know (a newer broker). Shown generically.
    public let extra: [String: JSONValue]

    static let known: Set<String> = [
        "intentText", "intentAt", "verifiedOrigin", "agentName", "credentialType", "action", "allowForMs",
    ]

    public init(json: JSONValue) throws {
        guard let o = json.objectValue,
              let intentText = o["intentText"]?.stringValue,
              let intentAt = o["intentAt"]?.intValue,
              let verifiedOrigin = o["verifiedOrigin"]?.stringValue,
              let agentName = o["agentName"]?.stringValue,
              let credentialType = o["credentialType"]?.stringValue,
              let action = o["action"]?.stringValue
        else { throw StatementError.malformed("display") }
        self.intentText = intentText
        self.intentAt = intentAt
        self.verifiedOrigin = verifiedOrigin
        self.agentName = agentName
        self.credentialType = credentialType
        self.action = action
        switch o["allowForMs"] {
        case .none: allowForMs = nil
        case .some(.int(let ms)): allowForMs = ms
        default: throw StatementError.malformed("allowForMs")
        }
        extra = o.filter { !Self.known.contains($0.key) }
    }

    public init(
        intentText: String, intentAt: Int64, verifiedOrigin: String, agentName: String,
        credentialType: String, action: String, allowForMs: Int64? = nil, extra: [String: JSONValue] = [:]
    ) {
        self.intentText = intentText
        self.intentAt = intentAt
        self.verifiedOrigin = verifiedOrigin
        self.agentName = agentName
        self.credentialType = credentialType
        self.action = action
        self.allowForMs = allowForMs
        self.extra = extra
    }
}

public struct PairView: Equatable, Sendable {
    public let requestedAt: Int64
    public let check: String
    /// "passkey" (a phone browser) or "ios-app".
    public let newDevice: String
}

public struct PendingRequest: Equatable, Sendable, Identifiable {
    public enum Kind: Equatable, Sendable {
        case credential(Display)
        case pair(PairView)
        /// A kind this app doesn't know: shown as such, never approvable.
        case unknown(String)
    }

    public let id: String
    public let createdAt: Int64
    public let expiresAt: Int64
    public let kind: Kind

    public init(id: String, createdAt: Int64, expiresAt: Int64, kind: Kind) {
        self.id = id
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        self.kind = kind
    }

    init(json: JSONValue) throws {
        guard let id = json["id"]?.stringValue, !id.isEmpty, id.count <= 128,
              let createdAt = json["createdAt"]?.intValue
        else { throw StatementError.malformed("pending") }
        self.id = id
        self.createdAt = createdAt
        expiresAt = json["expiresAt"]?.intValue ?? createdAt + 120_000
        switch json["kind"]?.stringValue {
        case "credential":
            guard let d = json["display"] else { throw StatementError.malformed("display") }
            kind = .credential(try Display(json: d))
        case "pair":
            guard let check = json["check"]?.stringValue else { throw StatementError.malformed("check") }
            kind = .pair(PairView(
                requestedAt: json["requestedAt"]?.intValue ?? createdAt,
                check: check,
                newDevice: json["newDevice"]?.stringValue ?? "passkey"
            ))
        case let other:
            kind = .unknown(other ?? "?")
        }
    }

    /// The site's origin, for credential requests.
    public var display: Display? {
        if case .credential(let d) = kind { return d }
        return nil
    }
}

/// `GET /api/native/state`.
public struct BrokerState: Equatable, Sendable {
    /// The broker's clock when it answered (ms), for countdowns that ignore phone clock skew.
    public let now: Int64
    public let pending: [PendingRequest]
    public let keyId: String?
    public let apnsConfigured: Bool
    public let apnsRegistered: Bool

    public init(json: JSONValue) throws {
        guard let now = json["now"]?.intValue, case .array(let items)? = json["pending"] else {
            throw StatementError.malformed("state")
        }
        self.now = now
        pending = try items.map(PendingRequest.init(json:))
        keyId = json["device"]?["keyId"]?.stringValue
        apnsConfigured = json["apns"]?["configured"]?.boolValue ?? false
        apnsRegistered = json["apns"]?["registered"]?.boolValue ?? false
    }
}

/// `POST /api/native/challenge`: the statement to sign, and for approver.add the new key's
/// descriptor (so the app can recompute the check code and the statement's hash).
public struct Challenge: Equatable, Sendable {
    public let statement: ApprovalStatement
    public let descriptor: String?

    public init(json: JSONValue) throws {
        guard let s = json["statement"] else { throw StatementError.malformed("statement") }
        statement = try ApprovalStatement(json: s)
        descriptor = json["descriptor"]?.stringValue
    }
}

/// One line of the app's local history (never synced anywhere).
public struct HistoryEntry: Codable, Equatable, Sendable, Identifiable {
    public enum Outcome: String, Codable, Sendable {
        case approved, denied, expired, failed
    }

    public var id: String { "\(brokerOrigin)#\(requestId)" }
    public let requestId: String
    public let brokerOrigin: String
    /// The verified site origin, or nil for "add a phone".
    public let site: String?
    public let agentName: String?
    public let credentialType: String?
    public let action: String?
    public let outcome: Outcome
    public let at: Date

    public init(
        requestId: String, brokerOrigin: String, site: String?, agentName: String?,
        credentialType: String?, action: String?, outcome: Outcome, at: Date
    ) {
        self.requestId = requestId
        self.brokerOrigin = brokerOrigin
        self.site = site
        self.agentName = agentName
        self.credentialType = credentialType
        self.action = action
        self.outcome = outcome
        self.at = at
    }

    public init(request: PendingRequest, brokerOrigin: String, outcome: Outcome, at: Date) {
        let d = request.display
        self.init(
            requestId: request.id, brokerOrigin: brokerOrigin, site: d?.verifiedOrigin,
            agentName: d?.agentName, credentialType: d?.credentialType, action: d?.action,
            outcome: outcome, at: at
        )
    }
}
