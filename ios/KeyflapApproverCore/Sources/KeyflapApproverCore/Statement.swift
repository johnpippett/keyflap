import Foundation

/// The approval statement the broker asks the phone to sign (`ApprovalStatement` in
/// packages/signer/src/approval.ts). Kept as the parsed JSON so the signed bytes are the
/// broker's own canonical form, plus typed views of the fields the app checks.
public struct ApprovalStatement: Equatable, Sendable {
    public static let nativeDomain = "aab-native-approval-v1\n"
    /// Every field the app understands. A statement with anything else is refused: the
    /// user must have seen everything their signature covers.
    public static let knownFields: Set<String> = [
        "v", "requestId", "kind", "verifiedOrigin", "rpId", "credentialId", "intentHash",
        "clientDataHash", "userVerified", "issuedAt", "expiresAt", "strong", "grant",
    ]

    public let json: JSONValue
    public let requestId: String
    public let kind: String
    public let verifiedOrigin: String
    public let rpId: String
    public let credentialId: String?
    public let intentHash: String
    public let clientDataHash: String
    public let userVerified: Bool
    public let issuedAt: Int64
    public let expiresAt: Int64
    /// M5: policy `ask-strong` (or a high-risk site).
    public let strong: Bool
    /// M5 `allow-for`: approving also authorizes this agent until `until`.
    public let grant: Grant?

    public struct Grant: Equatable, Sendable {
        public let agentId: String
        public let until: Int64
    }

    public init(json: JSONValue) throws {
        guard let o = json.objectValue else { throw StatementError.malformed("not an object") }
        if let unknown = o.keys.sorted().first(where: { !Self.knownFields.contains($0) }) {
            throw StatementError.unknownField(unknown)
        }
        func str(_ k: String) throws -> String {
            guard let s = o[k]?.stringValue else { throw StatementError.malformed(k) }
            return s
        }
        func int(_ k: String) throws -> Int64 {
            guard let i = o[k]?.intValue else { throw StatementError.malformed(k) }
            return i
        }
        guard o["v"]?.intValue == 1 else { throw StatementError.malformed("v") }
        self.json = json
        requestId = try str("requestId")
        kind = try str("kind")
        verifiedOrigin = try str("verifiedOrigin")
        rpId = try str("rpId")
        switch o["credentialId"] {
        case .some(.null): credentialId = nil
        case .some(.string(let s)): credentialId = s
        default: throw StatementError.malformed("credentialId")
        }
        intentHash = try str("intentHash")
        clientDataHash = try str("clientDataHash")
        guard let uv = o["userVerified"]?.boolValue else { throw StatementError.malformed("userVerified") }
        userVerified = uv
        issuedAt = try int("issuedAt")
        expiresAt = try int("expiresAt")
        switch o["strong"] {
        case .none: strong = false
        case .some(.bool(true)): strong = true
        default: throw StatementError.malformed("strong")
        }
        switch o["grant"] {
        case .none: grant = nil
        case .some(.object(let g)):
            guard g.count == 2, let agentId = g["agentId"]?.stringValue, !agentId.isEmpty,
                  let until = g["until"]?.intValue
            else { throw StatementError.malformed("grant") }
            grant = Grant(agentId: agentId, until: until)
        default: throw StatementError.malformed("grant")
        }
    }

    public init(jsonText: String) throws {
        try self.init(json: JSONParser.parse(jsonText))
    }

    /// The canonical statement JSON (keys sorted, `JSON.stringify` escaping).
    public var canonicalJSON: String { CanonicalJSON.encode(json) }

    /// What the app's Secure Enclave key signs (ECDSA P-256 / SHA-256, DER):
    /// `nativeApprovalSigningBytes` on the broker side.
    public var nativeSigningBytes: Data { Data((Self.nativeDomain + canonicalJSON).utf8) }
}

public enum StatementError: Error, Equatable, CustomStringConvertible {
    case malformed(String)
    case unknownField(String)
    case mismatch(String)

    public var description: String {
        switch self {
        case .malformed(let f): return "The request is malformed (\(f))."
        case .unknownField(let f):
            return "This request includes terms this version of the app doesn't understand (\(f)). Update the app to approve it."
        case .mismatch(let what): return "The request doesn't match what was shown (\(what))."
        }
    }
}

/// The broker's other canonical byte strings the app must reproduce exactly.
public enum ApproverEncoding {
    /// `fillScope`: the secrets a fill approval may release.
    public static func fillScope(_ credentialType: String) -> String? {
        switch credentialType {
        case "password": return "aab-fill-v1\npassword"
        case "totp": return "aab-fill-v1\ntotp"
        case "password+totp": return "aab-fill-v1\npassword,totp"
        default: return nil
        }
    }

    /// `nativeKeyId`: b64url SHA-256 of the uncompressed point 04||X||Y.
    public static func keyId(x: Data, y: Data) -> String {
        Base64URL.encode(SHA256Digest.hash(Data([4]) + x + y))
    }

    /// `nativeApproverDescriptor`: what an approver.add approval of this key covers.
    public static func nativeApproverDescriptor(keyId: String, x: String, y: String, origin: String) -> String {
        "aab-native-approver-add-v1\n" + CanonicalJSON.encode(.object([
            "keyId": .string(keyId),
            "origin": .string(origin),
            "userVerification": .string("biometry"),
            "x": .string(x),
            "y": .string(y),
        ]))
    }

    /// `nativePairingProofBytes`: what the app signs at pairing to show it holds the key.
    public static func pairingProofBytes(descriptor: String) -> Data {
        Data(("aab-native-pair-v1\n" + descriptor).utf8)
    }

    /// `checkCode`: the 12-hex-digit code both phones show while a phone is being added.
    public static func checkCode(descriptor: String) -> String {
        let hex = SHA256Digest.hash(descriptor).hexString.uppercased()
        let c = Array(hex.prefix(12))
        return "\(String(c[0..<4]))-\(String(c[4..<8]))-\(String(c[8..<12]))"
    }

    public static func sha256B64url(_ s: String) -> String {
        Base64URL.encode(SHA256Digest.hash(s))
    }

    /// The id a descriptor names: `credentialId` (passkey) or `keyId` (native app).
    public static func descriptorKeyId(_ descriptor: String) -> String? {
        for (prefix, field) in [("aab-approver-add-v1\n", "credentialId"), ("aab-native-approver-add-v1\n", "keyId")] {
            if descriptor.hasPrefix(prefix),
               let v = try? JSONParser.parse(String(descriptor.dropFirst(prefix.count))) {
                return v[field]?.stringValue
            }
        }
        return nil
    }

    /// The approver origin a descriptor names.
    public static func descriptorOrigin(_ descriptor: String) -> String? {
        for prefix in ["aab-approver-add-v1\n", "aab-native-approver-add-v1\n"] where descriptor.hasPrefix(prefix) {
            return (try? JSONParser.parse(String(descriptor.dropFirst(prefix.count))))?["origin"]?.stringValue
        }
        return nil
    }
}

/// Before the app signs anything, it checks that the statement is exactly what it showed
/// the user. The broker's signer enforces its own rules again; these checks are what the
/// phone can verify on its own (Phase C: the app's code doesn't come from the broker).
public enum StatementCheck {
    public static let maxLifetimeMs: Int64 = 5 * 60_000
    public static let strongMaxLifetimeMs: Int64 = 60_000
    public static let clockSkewMs: Int64 = 30_000
    public static let maxGrantMs: Int64 = 24 * 60 * 60_000

    /// - Parameters:
    ///   - now: the broker's clock as the app estimates it (ms).
    ///   - brokerOrigin: the approver origin this app paired with.
    public static func verify(
        _ s: ApprovalStatement,
        for request: PendingRequest,
        descriptor: String?,
        brokerOrigin: String,
        now: Int64
    ) throws {
        func fail(_ why: String) -> StatementError { .mismatch(why) }
        guard s.requestId == request.id else { throw fail("request id") }
        guard s.userVerified else { throw fail("user verification") }
        let lifetime = s.expiresAt - s.issuedAt
        guard lifetime > 0, lifetime <= (s.strong ? strongMaxLifetimeMs : maxLifetimeMs) else {
            throw fail("lifetime")
        }
        guard now <= s.expiresAt, now + clockSkewMs >= s.issuedAt else { throw fail("expired") }
        guard !s.intentHash.isEmpty else { throw fail("intent") }

        switch request.kind {
        case .credential(let d):
            guard s.verifiedOrigin == d.verifiedOrigin else { throw fail("site") }
            guard let host = OriginParts(d.verifiedOrigin)?.host, Self.host(host, isWithin: s.rpId) else {
                throw fail("site")
            }
            switch (s.kind, d.action, d.credentialType) {
            case ("webauthn.get", "sign-in", "passkey"):
                guard s.credentialId != nil else { throw fail("credential") }
            case ("webauthn.create", "register", "passkey"):
                guard s.credentialId == nil else { throw fail("credential") }
            case ("fill", "sign-in", let type):
                guard let scope = ApproverEncoding.fillScope(type),
                      s.clientDataHash == ApproverEncoding.sha256B64url(scope),
                      s.credentialId != nil
                else { throw fail("credential type") }
            default:
                throw fail("credential type")
            }
            // M5 allow-for: what was shown must be exactly what is granted.
            switch (d.allowForMs, s.grant) {
            case (nil, nil):
                break
            case (let shown?, let g?):
                guard !s.strong, shown > 0, shown <= maxGrantMs, g.until - s.issuedAt == shown else {
                    throw fail("allow-for window")
                }
            default:
                throw fail("allow-for window")
            }
        case .pair(let p):
            guard s.kind == "approver.add", s.grant == nil else { throw fail("kind") }
            guard let descriptor else { throw fail("new phone's key") }
            guard s.clientDataHash == ApproverEncoding.sha256B64url(descriptor),
                  ApproverEncoding.checkCode(descriptor: descriptor) == p.check,
                  ApproverEncoding.descriptorKeyId(descriptor) == s.credentialId,
                  ApproverEncoding.descriptorOrigin(descriptor) == brokerOrigin,
                  s.verifiedOrigin == brokerOrigin
            else { throw fail("new phone's key") }
        case .unknown:
            throw fail("unknown request type")
        }
    }

    /// The origin's host is the rpId or a subdomain of it (label boundary).
    public static func host(_ host: String, isWithin rpId: String) -> Bool {
        guard !rpId.isEmpty, !rpId.hasPrefix("."), rpId == rpId.lowercased() else { return false }
        return host == rpId || host.hasSuffix("." + rpId)
    }
}
