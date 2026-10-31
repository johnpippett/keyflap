import Crypto
import Foundation
import XCTest
@testable import KeyflapApproverCore

/// Byte-for-byte agreement with the broker's TypeScript encoders (fixture written by
/// packages/signer/test/native-vectors.test.ts), and the reverse fixture: a key, pairing
/// proof and approval made by this Swift code, which the TypeScript tests verify.
final class VectorTests: XCTestCase {
    static let fixtures = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        .appendingPathComponent("Fixtures")

    func tsVectors() throws -> JSONValue {
        try JSONParser.parse(Data(contentsOf: Self.fixtures.appendingPathComponent("ts-vectors.json")))
    }

    func testStatementSigningBytesMatchTypeScript() throws {
        guard case .array(let items)? = try tsVectors()["statements"] else { return XCTFail("no statements") }
        XCTAssertGreaterThanOrEqual(items.count, 7)
        for item in items {
            let name = item["name"]?.stringValue ?? "?"
            let s = try ApprovalStatement(json: XCTUnwrap(item["statement"]))
            let want = try XCTUnwrap(Data(base64Encoded: XCTUnwrap(item["nativeSigningBytes"]?.stringValue)))
            XCTAssertEqual(s.nativeSigningBytes, want, name)
            XCTAssertEqual(Base64URL.encode(KeyflapApproverCore.SHA256Digest.hash(s.nativeSigningBytes)), item["nativeSigningSha256"]?.stringValue, name)
            let ed = try XCTUnwrap(Data(base64Encoded: XCTUnwrap(item["ed25519SigningBytes"]?.stringValue)))
            XCTAssertEqual(Data(("aab-approval-v1\n" + s.canonicalJSON).utf8), ed, name)
        }
    }

    func testGenericCanonicalEncodingMatchesTypeScript() throws {
        guard case .array(let items)? = try tsVectors()["generic"] else { return XCTFail("no generic") }
        for item in items {
            XCTAssertEqual(CanonicalJSON.encode(try XCTUnwrap(item["value"])), item["canonical"]?.stringValue)
        }
    }

    func testFillScopesMatchTypeScript() throws {
        guard case .array(let items)? = try tsVectors()["fillScopes"] else { return XCTFail("no fillScopes") }
        XCTAssertEqual(items.count, 3)
        for item in items {
            let scope = try XCTUnwrap(ApproverEncoding.fillScope(XCTUnwrap(item["credentialType"]?.stringValue)))
            XCTAssertEqual(scope, item["scope"]?.stringValue)
            XCTAssertEqual(ApproverEncoding.sha256B64url(scope), item["hash"]?.stringValue)
        }
    }

    func testNativeKeyDescriptorAndCheckCodeMatchTypeScript() throws {
        let n = try XCTUnwrap(try tsVectors()["native"])
        let x = try XCTUnwrap(n["x"]?.stringValue), y = try XCTUnwrap(n["y"]?.stringValue)
        let keyId = ApproverEncoding.keyId(x: try XCTUnwrap(Base64URL.decode(x)), y: try XCTUnwrap(Base64URL.decode(y)))
        XCTAssertEqual(keyId, n["keyId"]?.stringValue)
        let origin = try XCTUnwrap(n["origin"]?.stringValue)
        let descriptor = ApproverEncoding.nativeApproverDescriptor(keyId: keyId, x: x, y: y, origin: origin)
        XCTAssertEqual(descriptor, n["descriptor"]?.stringValue)
        XCTAssertEqual(ApproverEncoding.sha256B64url(descriptor), n["descriptorSha256"]?.stringValue)
        XCTAssertEqual(ApproverEncoding.checkCode(descriptor: descriptor), n["checkCode"]?.stringValue)
        XCTAssertEqual(ApproverEncoding.descriptorKeyId(descriptor), keyId)
        XCTAssertEqual(ApproverEncoding.descriptorOrigin(descriptor), origin)
        XCTAssertEqual(
            ApproverEncoding.pairingProofBytes(descriptor: descriptor),
            Data(base64Encoded: try XCTUnwrap(n["pairingProofBytes"]?.stringValue))
        )
        let p = try XCTUnwrap(try tsVectors()["passkeyDescriptor"])
        let pd = try XCTUnwrap(p["descriptor"]?.stringValue)
        XCTAssertEqual(ApproverEncoding.checkCode(descriptor: pd), p["checkCode"]?.stringValue)
        XCTAssertEqual(ApproverEncoding.descriptorKeyId(pd), p["credentialId"]?.stringValue)
        XCTAssertEqual(ApproverEncoding.descriptorOrigin(pd), p["origin"]?.stringValue)
    }

    /// The TypeScript side's DER signatures verify here (CryptoKit's API, via swift-crypto).
    func testTypeScriptSignaturesVerify() throws {
        let v = try tsVectors()
        let n = try XCTUnwrap(v["native"])
        let raw = try XCTUnwrap(Base64URL.decode(XCTUnwrap(n["x"]?.stringValue))) + XCTUnwrap(Base64URL.decode(XCTUnwrap(n["y"]?.stringValue)))
        let pub = try P256.Signing.PublicKey(rawRepresentation: raw)
        let sigs = try XCTUnwrap(v["signatures"])
        guard case .array(let items)? = v["statements"] else { return XCTFail() }
        let s0 = try ApprovalStatement(json: XCTUnwrap(items.first?["statement"]))
        let der = try P256.Signing.ECDSASignature(derRepresentation: XCTUnwrap(Base64URL.decode(XCTUnwrap(sigs["statementDer"]?.stringValue))))
        XCTAssertTrue(pub.isValidSignature(der, for: s0.nativeSigningBytes))
        let proof = try P256.Signing.ECDSASignature(derRepresentation: XCTUnwrap(Base64URL.decode(XCTUnwrap(sigs["proofDer"]?.stringValue))))
        let descriptor = try XCTUnwrap(n["descriptor"]?.stringValue)
        XCTAssertTrue(pub.isValidSignature(proof, for: ApproverEncoding.pairingProofBytes(descriptor: descriptor)))
        XCTAssertFalse(pub.isValidSignature(der, for: Data("other".utf8)))
    }

    /// Writes swift-vectors.json with WRITE_VECTORS=1; always checks the committed one.
    func testSwiftVectors() throws {
        let file = Self.fixtures.appendingPathComponent("swift-vectors.json")
        if ProcessInfo.processInfo.environment["WRITE_VECTORS"] == "1" {
            let key = P256.Signing.PrivateKey()
            let raw = key.publicKey.rawRepresentation
            let x = Base64URL.encode(raw.prefix(32)), y = Base64URL.encode(raw.suffix(32))
            let keyId = ApproverEncoding.keyId(x: raw.prefix(32), y: raw.suffix(32))
            let origin = "https://broker.tail1234.ts.net:8766"
            let descriptor = ApproverEncoding.nativeApproverDescriptor(keyId: keyId, x: x, y: y, origin: origin)
            let proof = try key.signature(for: ApproverEncoding.pairingProofBytes(descriptor: descriptor))
            let statement = try ApprovalStatement(jsonText: """
            {"v":1,"requestId":"swift-\u{00e9}-\\"quoted\\"","kind":"fill","verifiedOrigin":"https://login.example.com",
             "rpId":"example.com","credentialId":"pw_123","intentHash":"aW50ZW50","clientDataHash":"\(ApproverEncoding.sha256B64url("aab-fill-v1\npassword"))",
             "userVerified":true,"issuedAt":1760300000000,"expiresAt":1760300060000,
             "grant":{"until":1760301800000,"agentId":"agt_1"}}
            """)
            let sig = try key.signature(for: statement.nativeSigningBytes)
            let out: JSONValue = .object([
                "comment": .string("Generated by ios/KeyflapApproverCore VectorTests (WRITE_VECTORS=1). Test-only key, discarded."),
                "x": .string(x), "y": .string(y), "keyId": .string(keyId), "origin": .string(origin),
                "descriptor": .string(descriptor),
                "checkCode": .string(ApproverEncoding.checkCode(descriptor: descriptor)),
                "proof": .string(Base64URL.encode(proof.derRepresentation)),
                "statement": statement.json,
                "nativeSigningBytes": .string(statement.nativeSigningBytes.base64EncodedString()),
                "signature": .string(Base64URL.encode(sig.derRepresentation)),
            ])
            try Data((CanonicalJSON.encode(out) + "\n").utf8).write(to: file)
        }
        let v = try JSONParser.parse(Data(contentsOf: file))
        let x = try XCTUnwrap(Base64URL.decode(XCTUnwrap(v["x"]?.stringValue)))
        let y = try XCTUnwrap(Base64URL.decode(XCTUnwrap(v["y"]?.stringValue)))
        let pub = try P256.Signing.PublicKey(rawRepresentation: x + y)
        let s = try ApprovalStatement(json: XCTUnwrap(v["statement"]))
        XCTAssertEqual(s.nativeSigningBytes.base64EncodedString(), v["nativeSigningBytes"]?.stringValue)
        let sig = try P256.Signing.ECDSASignature(derRepresentation: XCTUnwrap(Base64URL.decode(XCTUnwrap(v["signature"]?.stringValue))))
        XCTAssertTrue(pub.isValidSignature(sig, for: s.nativeSigningBytes))
        let descriptor = try XCTUnwrap(v["descriptor"]?.stringValue)
        let proof = try P256.Signing.ECDSASignature(derRepresentation: XCTUnwrap(Base64URL.decode(XCTUnwrap(v["proof"]?.stringValue))))
        XCTAssertTrue(pub.isValidSignature(proof, for: ApproverEncoding.pairingProofBytes(descriptor: descriptor)))
    }
}
