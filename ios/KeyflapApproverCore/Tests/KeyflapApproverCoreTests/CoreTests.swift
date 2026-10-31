import Foundation
import XCTest
@testable import KeyflapApproverCore

final class PrimitivesTests: XCTestCase {
    func testSHA256KnownAnswers() {
        XCTAssertEqual(SHA256Digest.hash("").hexString, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        XCTAssertEqual(SHA256Digest.hash("abc").hexString, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        XCTAssertEqual(
            SHA256Digest.hash("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq").hexString,
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        )
        XCTAssertEqual(
            SHA256Digest.hash(String(repeating: "a", count: 1000)).hexString,
            "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"
        )
    }

    func testBase64URL() {
        XCTAssertEqual(Base64URL.encode(Data([0xfb, 0xff, 0xfe])), "-__-")
        XCTAssertEqual(Base64URL.decode("-__-"), Data([0xfb, 0xff, 0xfe]))
        XCTAssertNil(Base64URL.decode("ab=="))
        XCTAssertNil(Base64URL.decode("a+b/"))
        XCTAssertNil(Base64URL.decode("abcde"))
    }

    func testJSONParserIsStrict() {
        for bad in [
            #"{"a":1,"a":2}"#, #"{"a":1.5}"#, #"{"a":1e3}"#, #"{"a":01}"#, #"{"a":9007199254740992}"#,
            #"{"a":"\ud800"}"#, "{\"a\":\"x\u{01}\"}", #"{"a":1} x"#, #"{"a":}"#, #"[1,]"#, #"{"a":tru}"#,
            String(repeating: "[", count: 40) + String(repeating: "]", count: 40),
        ] {
            XCTAssertThrowsError(try JSONParser.parse(bad), bad)
        }
        XCTAssertEqual(try JSONParser.parse(#" {"a" : [1, -2, true, null, "é😀\/"]} "#), .object([
            "a": .array([.int(1), .int(-2), .bool(true), .null, .string("é😀/")]),
        ]))
    }

    func testCanonicalQuotingFollowsJSONStringify() {
        XCTAssertEqual(CanonicalJSON.quote("a\"b\\c/d"), #""a\"b\\c/d""#)
        XCTAssertEqual(CanonicalJSON.quote("\u{08}\u{0c}\n\r\t\u{01}\u{1f}\u{7f}"), "\"\\b\\f\\n\\r\\t\\u0001\\u001f\u{7f}\"")
        XCTAssertEqual(CanonicalJSON.quote("é😀\u{2028}"), "\"é😀\u{2028}\"")
        // JavaScript sorts keys by UTF-16 code units: U+1F600 (D83D…) before U+FFFF.
        XCTAssertEqual(
            CanonicalJSON.encode(.object(["\u{FFFF}": .int(1), "😀": .int(2), "b": .int(3), "B": .int(4)])),
            "{\"B\":4,\"b\":3,\"😀\":2,\"\u{FFFF}\":1}"
        )
    }
}

final class StatementCheckTests: XCTestCase {
    let origin = "https://broker.tail1234.ts.net:8766"
    let now: Int64 = 1_760_300_010_000

    func display(
        type: String = "passkey", action: String = "sign-in", allowForMs: Int64? = nil, site: String = "https://github.com"
    ) -> Display {
        Display(intentText: "sign in to github", intentAt: 1, verifiedOrigin: site, agentName: "claude",
                credentialType: type, action: action, allowForMs: allowForMs)
    }

    func request(_ d: Display, id: String = "r1") -> PendingRequest {
        PendingRequest(id: id, createdAt: now - 1000, expiresAt: now + 100_000, kind: .credential(d))
    }

    func statement(_ over: [String: JSONValue] = [:], drop: [String] = []) throws -> ApprovalStatement {
        var o: [String: JSONValue] = [
            "v": .int(1), "requestId": .string("r1"), "kind": .string("webauthn.get"),
            "verifiedOrigin": .string("https://github.com"), "rpId": .string("github.com"),
            "credentialId": .string("cred"), "intentHash": .string("aW50"), "clientDataHash": .string("Y2Q"),
            "userVerified": .bool(true), "issuedAt": .int(now - 500), "expiresAt": .int(now + 59_500),
        ]
        for (k, v) in over { o[k] = v }
        for k in drop { o.removeValue(forKey: k) }
        return try ApprovalStatement(json: .object(o))
    }

    func check(_ s: ApprovalStatement, _ r: PendingRequest, descriptor: String? = nil) throws {
        try StatementCheck.verify(s, for: r, descriptor: descriptor, brokerOrigin: origin, now: now)
    }

    func testAcceptsWhatWasShown() throws {
        try check(try statement(), request(display()))
        try check(try statement(["kind": .string("webauthn.create"), "credentialId": .null]), request(display(action: "register")))
        try check(try statement(["rpId": .string("github.com"), "verifiedOrigin": .string("https://login.github.com")]),
                  request(display(site: "https://login.github.com")))
        let scope = ApproverEncoding.sha256B64url("aab-fill-v1\npassword,totp")
        try check(try statement(["kind": .string("fill"), "clientDataHash": .string(scope)]), request(display(type: "password+totp")))
        try check(try statement(["strong": .bool(true)]), request(display()))
    }

    func testRefusesMismatches() throws {
        let r = request(display())
        let cases: [(String, ApprovalStatement, PendingRequest)] = [
            ("other site", try statement(["verifiedOrigin": .string("https://evil.com"), "rpId": .string("evil.com")]), r),
            ("rpId not covering the site", try statement(["rpId": .string("hub.com")]), r),
            ("other request", try statement(["requestId": .string("r2")]), r),
            ("no UV", try statement(["userVerified": .bool(false)]), r),
            ("registration shown as sign-in", try statement(["kind": .string("webauthn.create"), "credentialId": .null]), r),
            ("fill shown as passkey", try statement(["kind": .string("fill")]), r),
            ("wrong fill scope", try statement(["kind": .string("fill"), "clientDataHash": .string(ApproverEncoding.sha256B64url("aab-fill-v1\npassword,totp"))]), request(display(type: "password"))),
            ("approver.add for a sign-in", try statement(["kind": .string("approver.add")]), r),
            ("expired", try statement(["issuedAt": .int(now - 70_000), "expiresAt": .int(now - 10_000)]), r),
            ("issued in the future", try statement(["issuedAt": .int(now + 40_000), "expiresAt": .int(now + 90_000)]), r),
            ("lifetime over 5 minutes", try statement(["expiresAt": .int(now + 400_000)]), r),
            ("strong lifetime over 60 s", try statement(["strong": .bool(true), "expiresAt": .int(now + 61_000)]), r),
            ("grant not shown", try statement(["grant": .object(["agentId": .string("a"), "until": .int(now + 1_000_000)])]), r),
            ("grant shown but not signed", try statement(), request(display(allowForMs: 1_800_000))),
            ("grant window differs", try statement(["grant": .object(["agentId": .string("a"), "until": .int(now - 500 + 3_600_000)])]), request(display(allowForMs: 1_800_000))),
            ("grant on a strong statement", try statement(["strong": .bool(true), "grant": .object(["agentId": .string("a"), "until": .int(now - 500 + 1_800_000)])]), request(display(allowForMs: 1_800_000))),
        ]
        for (name, s, req) in cases {
            XCTAssertThrowsError(try check(s, req), name)
        }
        // A matching grant passes.
        try check(try statement(["grant": .object(["agentId": .string("a"), "until": .int(now - 500 + 1_800_000)])]),
                  request(display(allowForMs: 1_800_000)))
    }

    func testRefusesStatementsWithUnknownTerms() {
        XCTAssertThrowsError(try statement(["scope": .string("everything")])) { e in
            XCTAssertEqual(e as? StatementError, .unknownField("scope"))
        }
        // Sessions plan P3: "Keep me signed in" is offered on the web approver only; the app
        // never showed the box, so it refuses to sign a statement that carries it.
        XCTAssertThrowsError(try statement(["keepSignedIn": .object(["site": .string("bank.example")])])) { e in
            XCTAssertEqual(e as? StatementError, .unknownField("keepSignedIn"))
        }
        XCTAssertThrowsError(try statement(["strong": .bool(false)]))
        XCTAssertThrowsError(try statement(["grant": .object(["agentId": .string("a"), "until": .int(1), "x": .int(1)])]))
        XCTAssertThrowsError(try statement(["v": .int(2)]))
        XCTAssertThrowsError(try statement(drop: ["rpId"]))
    }

    func testPairRequestNeedsTheDescriptorAndCheckCode() throws {
        let descriptor = ApproverEncoding.nativeApproverDescriptor(keyId: "kid", x: "xx", y: "yy", origin: origin)
        let code = ApproverEncoding.checkCode(descriptor: descriptor)
        let r = PendingRequest(id: "r1", createdAt: now, expiresAt: now + 100_000,
                               kind: .pair(PairView(requestedAt: now, check: code, newDevice: "ios-app")))
        let hash = ApproverEncoding.sha256B64url(descriptor)
        let good = try statement(["kind": .string("approver.add"), "verifiedOrigin": .string(origin),
                                  "rpId": .string("broker.tail1234.ts.net"), "credentialId": .string("kid"),
                                  "clientDataHash": .string(hash), "intentHash": .string(hash)])
        try check(good, r, descriptor: descriptor)
        XCTAssertThrowsError(try check(good, r))
        let other = ApproverEncoding.nativeApproverDescriptor(keyId: "kid", x: "xx", y: "zz", origin: origin)
        XCTAssertThrowsError(try check(good, r, descriptor: other))
        let wrongCheck = PendingRequest(id: "r1", createdAt: now, expiresAt: now + 100_000,
                                        kind: .pair(PairView(requestedAt: now, check: "0000-0000-0000", newDevice: "ios-app")))
        XCTAssertThrowsError(try check(good, wrongCheck, descriptor: descriptor))
        XCTAssertThrowsError(try check(try statement(["kind": .string("approver.add"), "verifiedOrigin": .string(origin),
                                                      "credentialId": .string("other"), "clientDataHash": .string(hash)]),
                                       r, descriptor: descriptor))
    }

    func testHostWithinRpId() {
        XCTAssertTrue(StatementCheck.host("github.com", isWithin: "github.com"))
        XCTAssertTrue(StatementCheck.host("a.github.com", isWithin: "github.com"))
        XCTAssertFalse(StatementCheck.host("notgithub.com", isWithin: "github.com"))
        XCTAssertFalse(StatementCheck.host("github.com", isWithin: ""))
        XCTAssertFalse(StatementCheck.host("github.com", isWithin: "GitHub.com"))
    }
}

final class PairingAndFormattingTests: XCTestCase {
    func testPairingLink() throws {
        let code = String(repeating: "A", count: 42) + "_"
        let l = try PairingLink.parse(" https://Broker.Tail1234.ts.net:8766/pair#\(code) \n")
        XCTAssertEqual(l, PairingLink(origin: "https://broker.tail1234.ts.net:8766", code: code))
        XCTAssertEqual(try PairingLink.parse("https://b.example:443/pair#\(code)").origin, "https://b.example")
        XCTAssertThrowsError(try PairingLink.parse("http://b.example/pair#\(code)")) { XCTAssertEqual($0 as? PairingLink.ParseError, .notHTTPS) }
        XCTAssertEqual(try PairingLink.parse("http://approver.localhost:9/pair#\(code)", allowInsecureLocalhost: true).origin, "http://approver.localhost:9")
        XCTAssertThrowsError(try PairingLink.parse("https://b.example/other#\(code)"))
        XCTAssertThrowsError(try PairingLink.parse("https://b.example/pair?x=1#\(code)"))
        XCTAssertThrowsError(try PairingLink.parse("https://u:p@b.example/pair#\(code)"))
        XCTAssertThrowsError(try PairingLink.parse("https://b.example/pair#short"))
        XCTAssertThrowsError(try PairingLink.parse("https://b.example/pair#\(String(repeating: "A", count: 42))+"))
        XCTAssertThrowsError(try PairingLink.parse("https://bröker.example/pair#\(code)"))
        XCTAssertThrowsError(try PairingLink.parse("not a link"))
    }

    func testFormattingMatchesTheBrokerWording() {
        XCTAssertEqual(Formatting.duration(ms: 45_000), "45 seconds")
        XCTAssertEqual(Formatting.duration(ms: 1_000), "1 second")
        XCTAssertEqual(Formatting.duration(ms: 30 * 60_000), "30 minutes")
        XCTAssertEqual(Formatting.duration(ms: 60 * 60_000), "1 hour")
        XCTAssertEqual(Formatting.duration(ms: 90 * 60_000), "1 hour 30 minutes")
        XCTAssertEqual(Formatting.duration(ms: 12 * 60 * 60_000), "12 hours")
        XCTAssertEqual(Formatting.allowForText(ms: 30 * 60_000),
                       "approving also lets this agent sign in here again without asking, for 30 minutes")
        XCTAssertEqual(Formatting.clean("a\u{202E}b\u{1b}[31mc\nd\u{2066}"), "a\u{FFFD}b\u{FFFD}[31mc\nd\u{FFFD}")
        XCTAssertEqual(Formatting.siteHost("https://GitHub.com"), "github.com")
        XCTAssertEqual(Formatting.siteHost("http://rp.localhost:3000"), "rp.localhost:3000")
        XCTAssertEqual(Formatting.countdown(ms: 65_000), "1:05")
        XCTAssertEqual(Formatting.countdown(ms: -5), "0:00")
        XCTAssertEqual(Formatting.extraLines(["zeta": .int(3), "alpha": .string("x\u{202E}y")]), ["alpha: x\u{FFFD}y", "zeta: 3"])
    }
}

/// The API client against a scripted transport.
final class BrokerClientTests: XCTestCase {
    final class Fake: HTTPTransport, @unchecked Sendable {
        var seen: [HTTPRequest] = []
        var replies: [(Int, String)] = []
        func send(_ request: HTTPRequest) async throws -> HTTPResponse {
            seen.append(request)
            let (status, body) = replies.removeFirst()
            return HTTPResponse(status: status, body: Data(body.utf8))
        }
    }

    let origin = "https://broker.example:8766"
    let token = String(repeating: "t", count: 43)

    func testStateChallengeDecide() async throws {
        let fake = Fake()
        let c = BrokerClient(origin: origin, deviceToken: token, transport: fake)
        fake.replies = [(200, """
        {"now":1000,"pending":[{"id":"r1","createdAt":900,"expiresAt":120900,"kind":"credential",
          "display":{"intentText":"hi","intentAt":1,"verifiedOrigin":"https://github.com","agentName":"claude",
          "credentialType":"passkey","action":"sign-in","allowForMs":1800000,"futureField":"shown"}},
          {"id":"p1","createdAt":950,"expiresAt":120950,"kind":"pair","requestedAt":950,"check":"ABCD-EF01-2345","newDevice":"ios-app"},
          {"id":"z1","createdAt":960,"kind":"teleport"}],
         "device":{"id":"dev_1","keyId":"kid"},"apns":{"configured":true,"registered":false}}
        """)]
        let st = try await c.state()
        XCTAssertEqual(st.now, 1000)
        XCTAssertEqual(st.pending.count, 3)
        XCTAssertEqual(st.pending[0].display?.allowForMs, 1_800_000)
        XCTAssertEqual(st.pending[0].display?.extra, ["futureField": .string("shown")])
        XCTAssertEqual(st.pending[1].kind, .pair(PairView(requestedAt: 950, check: "ABCD-EF01-2345", newDevice: "ios-app")))
        XCTAssertEqual(st.pending[2].kind, .unknown("teleport"))
        XCTAssertEqual(st.keyId, "kid")
        XCTAssertTrue(st.apnsConfigured)
        XCTAssertEqual(fake.seen[0].headers["authorization"], "Bearer \(token)")
        XCTAssertEqual(fake.seen[0].url.absoluteString, "\(origin)/api/native/state")

        fake.replies = [(200, """
        {"statement":{"v":1,"requestId":"r1","kind":"webauthn.get","verifiedOrigin":"https://github.com","rpId":"github.com",
          "credentialId":"c","intentHash":"i","clientDataHash":"d","userVerified":true,"issuedAt":1,"expiresAt":2},"descriptor":null}
        """), (200, #"{"ok":true}"#), (404, #"{"error":"no_such_request"}"#), (401, #"{"error":"not_paired"}"#)]
        let ch = try await c.challenge(id: "r1")
        XCTAssertEqual(ch.statement.requestId, "r1")
        XCTAssertNil(ch.descriptor)
        try await c.approve(id: "r1", signature: Data([1, 2, 3]))
        let body = try JSONParser.parse(XCTUnwrap(fake.seen.last?.body))
        XCTAssertEqual(body, .object(["id": .string("r1"), "decision": .string("approve"), "signature": .string("AQID")]))
        do { try await c.deny(id: "r1"); XCTFail() } catch { XCTAssertEqual(error as? BrokerError, .gone) }
        do { _ = try await c.state(); XCTFail() } catch { XCTAssertEqual(error as? BrokerError, .notPaired) }
    }

    func testPairing() async throws {
        let fake = Fake()
        let c = BrokerClient(origin: origin, deviceToken: nil, transport: fake)
        fake.replies = [
            (200, #"{"status":"paired","deviceToken":"\#(token)","keyId":"kid"}"#),
            (202, #"{"status":"waiting","check":"ABCD-EF01-2345","keyId":"kid"}"#),
            (200, #"{"status":"waiting"}"#),
            (200, #"{"status":"paired","deviceToken":"\#(token)"}"#),
            (403, #"{"error":"bad_code"}"#),
            (200, #"{"status":"paired","deviceToken":"short"}"#),
        ]
        let r1 = try await c.pair(code: "c", x: "x", y: "y", proof: Data([9]))
        XCTAssertEqual(r1, .paired(deviceToken: token, keyId: "kid"))
        XCTAssertNil(fake.seen[0].headers["authorization"])
        let sent = try JSONParser.parse(XCTUnwrap(fake.seen[0].body))
        XCTAssertEqual(sent["userVerification"], .string("biometry"))
        XCTAssertEqual(sent["proof"], .string("CQ"))
        let r2 = try await c.pair(code: "c", x: "x", y: "y", proof: Data([9]))
        XCTAssertEqual(r2, .waiting(check: "ABCD-EF01-2345", keyId: "kid"))
        let w = try await c.pairStatus(code: "c")
        XCTAssertEqual(w, .waiting)
        let p = try await c.pairStatus(code: "c")
        XCTAssertEqual(p, .paired(deviceToken: token))
        do { _ = try await c.pair(code: "c", x: "x", y: "y", proof: Data()); XCTFail() } catch {
            XCTAssertEqual(error as? BrokerError, .server(status: 403, code: "bad_code"))
            XCTAssertTrue("\(error)".contains("invalid or expired"))
        }
        do { _ = try await c.pair(code: "c", x: "x", y: "y", proof: Data()); XCTFail() } catch {
            XCTAssertEqual(error as? BrokerError, .badResponse)
        }
    }
}
