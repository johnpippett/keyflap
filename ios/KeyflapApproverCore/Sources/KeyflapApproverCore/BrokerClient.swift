import Foundation

public struct HTTPRequest: Equatable, Sendable {
    public let method: String
    public let url: URL
    public let headers: [String: String]
    public let body: Data?
}

public struct HTTPResponse: Equatable, Sendable {
    public let status: Int
    public let body: Data

    public init(status: Int, body: Data) {
        self.status = status
        self.body = body
    }
}

/// The network, behind a protocol so the client is testable on Linux (the app plugs in
/// URLSession).
public protocol HTTPTransport: Sendable {
    func send(_ request: HTTPRequest) async throws -> HTTPResponse
}

public enum BrokerError: Error, Equatable, CustomStringConvertible {
    /// 401: the broker no longer knows this phone.
    case notPaired
    /// 404 for a request id: it was decided elsewhere, expired or withdrawn.
    case gone
    case server(status: Int, code: String)
    case badResponse

    public var description: String {
        switch self {
        case .notPaired: return "This broker no longer knows this iPhone. Pair it again."
        case .gone: return "This request is no longer pending."
        case .server(_, let code): return BrokerError.explain(code)
        case .badResponse: return "The broker sent something unexpected."
        }
    }

    static func explain(_ code: String) -> String {
        switch code {
        case "bad_code", "code_expired": return "This pairing link is invalid or expired. Start pairing again on the broker."
        case "pairing_in_progress", "no_ceremony":
            return "This link is already being used by another device. Don't approve anything; start pairing again on the broker."
        case "paired_at_other_origin", "pairing_refused":
            return "The broker refused. Remove old phones with `keyflap approver remove` and pair again."
        case "native_unsupported": return "This broker is too old for the iOS app."
        case "bad_proof", "bad_key": return "The broker couldn't verify this iPhone's key."
        case "bad_signature": return "The broker didn't accept the signature."
        case "expired": return "The approval expired before it reached the broker."
        case "unknown_approver": return "This iPhone's key is no longer trusted by the broker."
        default: return "The broker said: \(Formatting.clean(code))"
        }
    }
}

public enum PairResult: Equatable, Sendable {
    case paired(deviceToken: String, keyId: String?)
    /// Another phone must approve; both show `check`.
    case waiting(check: String, keyId: String?)
}

public enum PairStatus: Equatable, Sendable {
    case paired(deviceToken: String)
    case waiting
    case failed
}

/// The broker's native-app API (`/api/native/*` on the approver origin).
public struct BrokerClient: Sendable {
    public let origin: String
    public let deviceToken: String?
    let transport: HTTPTransport

    public init(origin: String, deviceToken: String?, transport: HTTPTransport) {
        self.origin = origin
        self.deviceToken = deviceToken
        self.transport = transport
    }

    public func state() async throws -> BrokerState {
        try BrokerState(json: try await call("GET", "/api/native/state", nil))
    }

    public func pair(code: String, x: String, y: String, proof: Data) async throws -> PairResult {
        let body: JSONValue = .object([
            "code": .string(code),
            "key": .object(["x": .string(x), "y": .string(y)]),
            "userVerification": .string("biometry"),
            "proof": .string(Base64URL.encode(proof)),
        ])
        let r = try await call("POST", "/api/native/pair", body, authenticated: false)
        let keyId = r["keyId"]?.stringValue
        switch r["status"]?.stringValue {
        case "paired":
            guard let t = r["deviceToken"]?.stringValue, Self.validToken(t) else { throw BrokerError.badResponse }
            return .paired(deviceToken: t, keyId: keyId)
        case "waiting":
            guard let check = r["check"]?.stringValue else { throw BrokerError.badResponse }
            return .waiting(check: check, keyId: keyId)
        default:
            throw BrokerError.badResponse
        }
    }

    public func pairStatus(code: String) async throws -> PairStatus {
        let r = try await call("POST", "/api/native/pair/status", .object(["code": .string(code)]), authenticated: false)
        switch r["status"]?.stringValue {
        case "paired":
            guard let t = r["deviceToken"]?.stringValue, Self.validToken(t) else { throw BrokerError.badResponse }
            return .paired(deviceToken: t)
        case "waiting", "open": return .waiting
        default: return .failed
        }
    }

    public func challenge(id: String) async throws -> Challenge {
        try Challenge(json: try await call("POST", "/api/native/challenge", .object(["id": .string(id)])))
    }

    public func approve(id: String, signature: Data) async throws {
        _ = try await call("POST", "/api/native/decide", .object([
            "id": .string(id), "decision": .string("approve"), "signature": .string(Base64URL.encode(signature)),
        ]))
    }

    public func deny(id: String) async throws {
        _ = try await call("POST", "/api/native/decide", .object(["id": .string(id), "decision": .string("deny")]))
    }

    /// Registers (or with nil, removes) this device's APNs token.
    public func registerPush(token: String?, environment: String) async throws {
        let body: JSONValue = token.map {
            .object(["token": .string($0), "environment": .string(environment)])
        } ?? .object(["token": .null])
        _ = try await call("POST", "/api/native/apns", body)
    }

    /// Forgets this device on the broker. Returns whether its key was untrusted too (the
    /// last phone's key stays until `keyflap approver remove`).
    public func unpair() async throws -> Bool {
        try await call("POST", "/api/native/unpair", .object([:]))["keyRemoved"]?.boolValue ?? false
    }

    static func validToken(_ t: String) -> Bool {
        t.count == 43 && t.utf8.allSatisfy(Base64URL.isB64urlByte)
    }

    func call(_ method: String, _ path: String, _ body: JSONValue?, authenticated: Bool = true) async throws -> JSONValue {
        guard let url = URL(string: origin + path) else { throw BrokerError.badResponse }
        var headers = ["accept": "application/json"]
        if body != nil { headers["content-type"] = "application/json" }
        if authenticated {
            guard let t = deviceToken else { throw BrokerError.notPaired }
            headers["authorization"] = "Bearer \(t)"
        }
        let req = HTTPRequest(
            method: method, url: url, headers: headers,
            body: body.map { Data(CanonicalJSON.encode($0).utf8) }
        )
        let res = try await transport.send(req)
        let json = (try? JSONParser.parse(res.body)) ?? .object([:])
        switch res.status {
        case 200, 202: return json
        case 401: throw BrokerError.notPaired
        case 404 where path != "/api/native/state": throw BrokerError.gone
        default: throw BrokerError.server(status: res.status, code: json["error"]?.stringValue ?? "http_\(res.status)")
        }
    }
}
