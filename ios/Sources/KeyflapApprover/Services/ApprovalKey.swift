import CryptoKit
import Foundation
import LocalAuthentication
import KeyflapApproverCore
import Security

/// The approval key: a P-256 key generated inside the Secure Enclave, one per paired
/// broker. It never leaves the chip; the app keeps only its opaque `dataRepresentation`
/// (usable on this device's Secure Enclave alone) in the Keychain.
///
/// Access control `.privateKeyUsage` + `.biometryCurrentSet`: every signature needs a
/// successful Face ID / Touch ID match with the biometrics enrolled when the key was made
/// (enrolling a new face or finger invalidates the key; no passcode fallback). The app
/// tells the broker so at pairing (`userVerification: "biometry"`), which is why the
/// broker's signer accepts these signatures as user-verified (invariant 6).
enum ApprovalKey {
    enum KeyError: LocalizedError {
        case noSecureEnclave
        case noBiometry(String)
        case accessControl
        case cancelled
        case signingFailed(String)

        var errorDescription: String? {
            switch self {
            case .noSecureEnclave: return "This device has no Secure Enclave."
            case .noBiometry(let why): return "Face ID or Touch ID must be set up to approve sign-ins. \(why)"
            case .accessControl: return "Couldn't create the approval key's access control."
            case .cancelled: return "Face ID was cancelled."
            case .signingFailed(let why):
                return "The approval key didn't sign (\(why)). If Face ID or Touch ID enrollment changed, the key is retired: unpair and pair again."
            }
        }
    }

    /// Fails unless biometrics are enrolled: the key would be unusable otherwise.
    static func checkBiometry() throws {
        let ctx = LAContext()
        var error: NSError?
        guard ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            throw KeyError.noBiometry(error?.localizedDescription ?? "")
        }
    }

    static var biometryName: String {
        let ctx = LAContext()
        _ = ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        switch ctx.biometryType {
        case .faceID: return "Face ID"
        case .touchID: return "Touch ID"
        case .opticID: return "Optic ID"
        default: return "Face ID"
        }
    }

    /// Creates a new key. Making it doesn't prompt; its first use does.
    static func create() throws -> SecureEnclave.P256.Signing.PrivateKey {
        guard SecureEnclave.isAvailable else { throw KeyError.noSecureEnclave }
        try checkBiometry()
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],
            &error
        ) else { throw KeyError.accessControl }
        return try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
    }

    /// The public key as JWK coordinates (b64url), which is how the broker stores it.
    static func publicCoordinates(_ key: SecureEnclave.P256.Signing.PrivateKey) -> (x: String, y: String, keyId: String) {
        let raw = key.publicKey.rawRepresentation
        let x = raw.prefix(32), y = raw.suffix(32)
        return (Base64URL.encode(Data(x)), Base64URL.encode(Data(y)), ApproverEncoding.keyId(x: Data(x), y: Data(y)))
    }

    /// Signs `data` (DER), prompting Face ID with `reason`. A fresh LAContext every time
    /// and no reuse window: each approval is its own biometric check. Blocking; call off
    /// the main thread.
    static func signBlocking(_ data: Data, keyData: Data, reason: String) throws -> Data {
        let ctx = LAContext()
        ctx.localizedReason = reason
        ctx.localizedCancelTitle = "Cancel"
        ctx.touchIDAuthenticationAllowableReuseDuration = 0
        do {
            let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: keyData, authenticationContext: ctx)
            return try key.signature(for: data).derRepresentation
        } catch {
            if isCancel(error) { throw KeyError.cancelled }
            throw KeyError.signingFailed(error.localizedDescription)
        }
    }

    /// A Face ID prompt the user (or the system) dismissed, in whichever error domain the
    /// Secure Enclave reports it: LocalAuthentication, or CryptoTokenKit's "canceled by user".
    private static func isCancel(_ error: Error) -> Bool {
        let e = error as NSError
        if e.domain == LAErrorDomain {
            return [LAError.userCancel.rawValue, LAError.appCancel.rawValue, LAError.systemCancel.rawValue].contains(e.code)
        }
        if e.domain == "CryptoTokenKit" || e.domain == "TKErrorDomain" {
            return e.code == -4 // TKError.Code.canceledByUser
        }
        if let underlying = e.userInfo[NSUnderlyingErrorKey] as? Error { return isCancel(underlying) }
        return false
    }

    static func sign(_ data: Data, keyData: Data, reason: String) async throws -> Data {
        try await Task.detached(priority: .userInitiated) {
            try signBlocking(data, keyData: keyData, reason: reason)
        }.value
    }
}
