import Foundation

/// A JSON value with integers kept exact. The approval statement is parsed into this and
/// re-encoded canonically, so the bytes the app signs are exactly the bytes the broker's
/// signer rebuilds (`canonicalJson` in packages/signer/src/approval.ts).
public indirect enum JSONValue: Equatable, Sendable {
    case null
    case bool(Bool)
    /// Integers only, within ±(2^53 - 1): what JavaScript represents exactly. Fractions and
    /// exponents are refused when parsing (no statement field uses them).
    case int(Int64)
    case string(String)
    case array([JSONValue])
    case object([String: JSONValue])

    public subscript(key: String) -> JSONValue? {
        if case .object(let o) = self { return o[key] }
        return nil
    }

    public var stringValue: String? {
        if case .string(let s) = self { return s }
        return nil
    }

    public var intValue: Int64? {
        if case .int(let i) = self { return i }
        return nil
    }

    public var boolValue: Bool? {
        if case .bool(let b) = self { return b }
        return nil
    }

    public var objectValue: [String: JSONValue]? {
        if case .object(let o) = self { return o }
        return nil
    }

    public var isNull: Bool {
        if case .null = self { return true }
        return false
    }
}

public enum JSONError: Error, Equatable {
    case invalid(String)
}

public enum JSONParser {
    public static let maxSafeInteger: Int64 = 9_007_199_254_740_991

    public static func parse(_ data: Data, maxDepth: Int = 32) throws -> JSONValue {
        var p = Parser(bytes: [UInt8](data), maxDepth: maxDepth)
        p.skipWS()
        let v = try p.value(depth: 0)
        p.skipWS()
        guard p.i == p.bytes.count else { throw JSONError.invalid("trailing data") }
        return v
    }

    public static func parse(_ string: String) throws -> JSONValue {
        try parse(Data(string.utf8))
    }

    private struct Parser {
        let bytes: [UInt8]
        let maxDepth: Int
        var i = 0

        init(bytes: [UInt8], maxDepth: Int) {
            self.bytes = bytes
            self.maxDepth = maxDepth
        }

        mutating func skipWS() {
            while i < bytes.count, [0x20, 0x09, 0x0a, 0x0d].contains(bytes[i]) { i += 1 }
        }

        mutating func expect(_ literal: String) throws {
            for b in literal.utf8 {
                guard i < bytes.count, bytes[i] == b else { throw JSONError.invalid("bad literal") }
                i += 1
            }
        }

        mutating func value(depth: Int) throws -> JSONValue {
            guard depth <= maxDepth else { throw JSONError.invalid("too deep") }
            guard i < bytes.count else { throw JSONError.invalid("unexpected end") }
            switch bytes[i] {
            case UInt8(ascii: "{"): return try object(depth: depth)
            case UInt8(ascii: "["): return try array(depth: depth)
            case UInt8(ascii: "\""): return .string(try string())
            case UInt8(ascii: "t"): try expect("true"); return .bool(true)
            case UInt8(ascii: "f"): try expect("false"); return .bool(false)
            case UInt8(ascii: "n"): try expect("null"); return .null
            default: return .int(try integer())
            }
        }

        mutating func object(depth: Int) throws -> JSONValue {
            i += 1
            var out: [String: JSONValue] = [:]
            skipWS()
            if i < bytes.count, bytes[i] == UInt8(ascii: "}") { i += 1; return .object(out) }
            while true {
                skipWS()
                guard i < bytes.count, bytes[i] == UInt8(ascii: "\"") else { throw JSONError.invalid("key") }
                let k = try string()
                guard out[k] == nil else { throw JSONError.invalid("duplicate key") }
                skipWS()
                try expect(":")
                skipWS()
                out[k] = try value(depth: depth + 1)
                skipWS()
                guard i < bytes.count else { throw JSONError.invalid("unexpected end") }
                if bytes[i] == UInt8(ascii: ",") { i += 1; continue }
                if bytes[i] == UInt8(ascii: "}") { i += 1; return .object(out) }
                throw JSONError.invalid("object")
            }
        }

        mutating func array(depth: Int) throws -> JSONValue {
            i += 1
            var out: [JSONValue] = []
            skipWS()
            if i < bytes.count, bytes[i] == UInt8(ascii: "]") { i += 1; return .array(out) }
            while true {
                skipWS()
                out.append(try value(depth: depth + 1))
                skipWS()
                guard i < bytes.count else { throw JSONError.invalid("unexpected end") }
                if bytes[i] == UInt8(ascii: ",") { i += 1; continue }
                if bytes[i] == UInt8(ascii: "]") { i += 1; return .array(out) }
                throw JSONError.invalid("array")
            }
        }

        mutating func integer() throws -> Int64 {
            let start = i
            if i < bytes.count, bytes[i] == UInt8(ascii: "-") { i += 1 }
            let digitsStart = i
            while i < bytes.count, bytes[i] >= 0x30, bytes[i] <= 0x39 { i += 1 }
            let digits = i - digitsStart
            guard digits > 0, digits <= 16 else { throw JSONError.invalid("number") }
            if digits > 1, bytes[digitsStart] == 0x30 { throw JSONError.invalid("leading zero") }
            if i < bytes.count, [UInt8(ascii: "."), UInt8(ascii: "e"), UInt8(ascii: "E")].contains(bytes[i]) {
                throw JSONError.invalid("only integers are supported")
            }
            guard let s = String(bytes: bytes[start..<i], encoding: .utf8), let v = Int64(s),
                  v <= JSONParser.maxSafeInteger, v >= -JSONParser.maxSafeInteger
            else { throw JSONError.invalid("number out of range") }
            return v
        }

        mutating func hex4() throws -> UInt16 {
            guard i + 4 <= bytes.count, let s = String(bytes: bytes[i..<i + 4], encoding: .ascii),
                  s.utf8.allSatisfy({ $0 < 0x80 && ($0 >= 0x30 && $0 <= 0x39 || $0 >= 0x41 && $0 <= 0x46 || $0 >= 0x61 && $0 <= 0x66) }),
                  let v = UInt16(s, radix: 16)
            else { throw JSONError.invalid("escape") }
            i += 4
            return v
        }

        mutating func string() throws -> String {
            i += 1
            var units: [UInt16] = []
            var raw: [UInt8] = []
            func flushRaw() throws {
                if raw.isEmpty { return }
                guard let s = String(bytes: raw, encoding: .utf8) else { throw JSONError.invalid("utf-8") }
                units.append(contentsOf: s.utf16)
                raw.removeAll()
            }
            while true {
                guard i < bytes.count else { throw JSONError.invalid("unterminated string") }
                let c = bytes[i]
                if c == UInt8(ascii: "\"") { i += 1; break }
                if c < 0x20 { throw JSONError.invalid("control character in string") }
                if c != UInt8(ascii: "\\") { raw.append(c); i += 1; continue }
                try flushRaw()
                i += 1
                guard i < bytes.count else { throw JSONError.invalid("escape") }
                let e = bytes[i]
                i += 1
                switch e {
                case UInt8(ascii: "\""): units.append(0x22)
                case UInt8(ascii: "\\"): units.append(0x5c)
                case UInt8(ascii: "/"): units.append(0x2f)
                case UInt8(ascii: "b"): units.append(0x08)
                case UInt8(ascii: "f"): units.append(0x0c)
                case UInt8(ascii: "n"): units.append(0x0a)
                case UInt8(ascii: "r"): units.append(0x0d)
                case UInt8(ascii: "t"): units.append(0x09)
                case UInt8(ascii: "u"): units.append(try hex4())
                default: throw JSONError.invalid("escape")
                }
            }
            try flushRaw()
            // Lone surrogates can't be represented (and are never in a statement): refuse.
            var k = 0
            while k < units.count {
                let u = units[k]
                if u >= 0xd800, u <= 0xdbff {
                    guard k + 1 < units.count, units[k + 1] >= 0xdc00, units[k + 1] <= 0xdfff else {
                        throw JSONError.invalid("lone surrogate")
                    }
                    k += 2
                } else if u >= 0xdc00, u <= 0xdfff {
                    throw JSONError.invalid("lone surrogate")
                } else {
                    k += 1
                }
            }
            return String(decoding: units, as: UTF16.self)
        }
    }
}

/// JSON text exactly as the TypeScript side's `canonicalJson` produces it: object keys
/// sorted by UTF-16 code units (JavaScript's default sort), no whitespace, strings escaped
/// the way `JSON.stringify` escapes them.
public enum CanonicalJSON {
    public static func encode(_ v: JSONValue) -> String {
        var out = ""
        write(v, into: &out)
        return out
    }

    static func write(_ v: JSONValue, into out: inout String) {
        switch v {
        case .null: out += "null"
        case .bool(let b): out += b ? "true" : "false"
        case .int(let i): out += String(i)
        case .string(let s): out += quote(s)
        case .array(let a):
            out += "["
            for (n, x) in a.enumerated() {
                if n > 0 { out += "," }
                write(x, into: &out)
            }
            out += "]"
        case .object(let o):
            out += "{"
            for (n, k) in o.keys.sorted(by: utf16Less).enumerated() {
                if n > 0 { out += "," }
                out += quote(k)
                out += ":"
                write(o[k]!, into: &out)
            }
            out += "}"
        }
    }

    /// JSON.stringify's string quoting (ECMA-262 QuoteJSONString).
    public static func quote(_ s: String) -> String {
        var out = "\""
        for u in s.unicodeScalars {
            switch u.value {
            case 0x22: out += "\\\""
            case 0x5c: out += "\\\\"
            case 0x08: out += "\\b"
            case 0x0c: out += "\\f"
            case 0x0a: out += "\\n"
            case 0x0d: out += "\\r"
            case 0x09: out += "\\t"
            case 0..<0x20: out += String(format: "\\u%04x", u.value)
            default: out.unicodeScalars.append(u)
            }
        }
        out += "\""
        return out
    }

    static func utf16Less(_ a: String, _ b: String) -> Bool {
        a.utf16.lexicographicallyPrecedes(b.utf16)
    }
}
