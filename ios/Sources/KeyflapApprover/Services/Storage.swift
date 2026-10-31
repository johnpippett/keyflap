import Foundation
import KeyflapApproverCore
import Security

/// Secrets live only in the Keychain, this device only, never synced: the broker's bearer
/// token for this phone, and the Secure Enclave key's opaque handle. Readable after first
/// unlock, so a Deny from the lock screen can reach the broker (denying needs no key).
enum Keychain {
    static let service = "keyflap.approver"

    static func set(_ data: Data, account: String) throws {
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(base as CFDictionary)
        var add = base
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        add[kSecAttrSynchronizable as String] = false
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
    }

    static func get(_ account: String) -> Data? {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess else { return nil }
        return out as? Data
    }

    static func delete(_ account: String) {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(q as CFDictionary)
    }
}

/// A broker this phone is paired with. Not secret (the token and key are in the Keychain).
struct PairedBroker: Codable, Identifiable, Hashable {
    let id: UUID
    /// The approver origin, e.g. https://broker.tail1234.ts.net:8766.
    let origin: String
    /// This phone's key id at that broker (b64url SHA-256 of the public key).
    let keyId: String
    let pairedAt: Date

    var host: String { Formatting.siteHost(origin) }
    var tokenAccount: String { "\(id.uuidString).token" }
    var keyAccount: String { "\(id.uuidString).key" }

    var deviceToken: String? {
        Keychain.get(tokenAccount).flatMap { String(data: $0, encoding: .utf8) }
    }

    var keyData: Data? { Keychain.get(keyAccount) }
}

/// Non-secret app state on disk: paired brokers and the local history. History holds
/// display fields (sites, agent names), so it's file-protected and stays on this phone.
enum LocalStore {
    private static var dir: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let d = base.appendingPathComponent("Keyflap", isDirectory: true)
        try? FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
        return d
    }

    private static func load<T: Decodable>(_ name: String, as: T.Type) -> T? {
        guard let data = try? Data(contentsOf: dir.appendingPathComponent(name)) else { return nil }
        let dec = JSONDecoder()
        dec.dateDecodingStrategy = .millisecondsSince1970
        return try? dec.decode(T.self, from: data)
    }

    private static func save<T: Encodable>(_ value: T, _ name: String) {
        let enc = JSONEncoder()
        enc.dateEncodingStrategy = .millisecondsSince1970
        guard let data = try? enc.encode(value) else { return }
        try? data.write(to: dir.appendingPathComponent(name), options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    }

    static func brokers() -> [PairedBroker] { load("brokers.json", as: [PairedBroker].self) ?? [] }
    static func saveBrokers(_ b: [PairedBroker]) { save(b, "brokers.json") }

    static func history() -> [HistoryEntry] { load("history.json", as: [HistoryEntry].self) ?? [] }
    static func saveHistory(_ h: [HistoryEntry]) { save(Array(h.prefix(500)), "history.json") }
}

/// URLSession without cookies, caches or credentials storage: the bearer token is the
/// only credential, and responses are never kept.
struct URLSessionTransport: HTTPTransport {
    static let session: URLSession = {
        let c = URLSessionConfiguration.ephemeral
        c.httpCookieStorage = nil
        c.httpShouldSetCookies = false
        c.urlCache = nil
        c.requestCachePolicy = .reloadIgnoringLocalCacheData
        c.timeoutIntervalForRequest = 15
        c.waitsForConnectivity = false
        return URLSession(configuration: c)
    }()

    func send(_ request: HTTPRequest) async throws -> HTTPResponse {
        var r = URLRequest(url: request.url)
        r.httpMethod = request.method
        for (k, v) in request.headers { r.setValue(v, forHTTPHeaderField: k) }
        r.httpBody = request.body
        let (data, response) = try await Self.session.data(for: r)
        guard let http = response as? HTTPURLResponse else { throw BrokerError.badResponse }
        return HTTPResponse(status: http.statusCode, body: data.prefix(256 * 1024))
    }
}
