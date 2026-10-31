import Foundation

/// Scheme, host and port of an origin, normalized the way the WHATWG URL parser's `origin`
/// does for the hosts we accept (lower case, default port dropped). ASCII hosts only:
/// tailnet and DNS names; IDNs would need punycode, which the broker would show anyway.
public struct OriginParts: Equatable, Sendable {
    public let scheme: String
    public let host: String
    public let port: Int?

    public init?(_ s: String) {
        guard let c = URLComponents(string: s), let scheme = c.scheme?.lowercased(),
              scheme == "https" || scheme == "http",
              let rawHost = c.host, !rawHost.isEmpty
        else { return nil }
        let host = rawHost.lowercased()
        let allowed = host.utf8.allSatisfy { ($0 >= 0x61 && $0 <= 0x7a) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x2e || $0 == 0x2d }
        guard allowed, !host.hasPrefix("."), !host.hasSuffix("."), !host.contains("..") else { return nil }
        self.scheme = scheme
        self.host = host
        let defaultPort = scheme == "https" ? 443 : 80
        if let p = c.port, p != defaultPort {
            guard p > 0, p < 65536 else { return nil }
            port = p
        } else {
            port = nil
        }
    }

    public var origin: String {
        "\(scheme)://\(host)\(port.map { ":\($0)" } ?? "")"
    }

    public var isLocalhost: Bool { host == "localhost" || host.hasSuffix(".localhost") }
}

/// The one-time pairing link the broker prints (and shows as a QR code):
/// `https://<approver origin>/pair#<43-char code>`. The same link pairs the web page or
/// this app; the code is in the fragment, which never reaches a server log.
public struct PairingLink: Equatable, Sendable {
    public let origin: String
    public let code: String

    public enum ParseError: Error, Equatable, CustomStringConvertible {
        case notALink, notHTTPS, notAPairingLink, badCode

        public var description: String {
            switch self {
            case .notALink: return "That isn't a pairing link."
            case .notHTTPS: return "The broker's approver address must use https."
            case .notAPairingLink: return "That link isn't a Keyflap pairing link (it should end in /pair#…)."
            case .badCode: return "The pairing code in that link is incomplete."
            }
        }
    }

    /// - Parameter allowInsecureLocalhost: tests only (`http://*.localhost`).
    public static func parse(_ raw: String, allowInsecureLocalhost: Bool = false) throws -> PairingLink {
        let text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard text.count <= 2048, let c = URLComponents(string: text), let parts = OriginParts(text) else {
            throw ParseError.notALink
        }
        guard parts.scheme == "https" || (allowInsecureLocalhost && parts.isLocalhost) else {
            throw ParseError.notHTTPS
        }
        guard c.user == nil, c.password == nil, c.path == "/pair", c.query == nil else {
            throw ParseError.notAPairingLink
        }
        guard let code = c.fragment, code.count == 43, code.utf8.allSatisfy(Base64URL.isB64urlByte) else {
            throw ParseError.badCode
        }
        return PairingLink(origin: parts.origin, code: code)
    }
}
