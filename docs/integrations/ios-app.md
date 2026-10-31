# Native iOS approver (parked)

> **Parked: not supported.** The supported phone approver is the web page
> ([phone-approver.md](phone-approver.md)), which now also checks what it signs and, in
> service mode, is served by its own service the core can't change. The broker side of
> this app stays built and tested; the app itself has never been compiled for a device.
> Shipping it to others would need an App Store build and a push relay (APNs only accepts
> the signing team's key).

**Keyflap** for iPhone works like Duo Mobile: a notification "Approve sign-in to
github.com?" → open → the request (site, verified origin, agent, your own words,
credential type, time left) → **Approve** with Face ID, or **Deny**. Lock-screen
Approve / Deny actions too.

What sets it apart (ARCHITECTURE 6.4, 12): the approval key is a P-256 key generated
in the iPhone's **Secure Enclave**, and approving *is* signing. The app fetches the
approval statement, checks it against what it shows you, and signs those exact bytes
with that key, which only signs after Face ID. The broker's signer verifies the
signature itself. The app's code doesn't come from the broker (unlike the phone web
page), so a compromised broker core can't make it show one thing and sign another.

Source: `ios/` (Swift; not a pnpm package). Trust model and invariant 6:
IMPLEMENTATION_NOTES.md, "Native iOS approver (Phase C)".

## What works with which Apple account

| | No Apple account | Free Apple ID | Apple Developer Program ($99/yr) |
|---|---|---|---|
| Run on your iPhone | no | yes, via xtool's password login (private Apple APIs); re-install every 7 days | yes |
| Approvals (Face ID, Secure Enclave) | – | yes, while the app is open (it polls every 2 s) | yes |
| Push notifications + lock-screen actions | – | **no** (free provisioning can't carry `aps-environment`) | yes |
| TestFlight / CI uploads | – | no | yes |

Nothing runs on a device without at least a free Apple ID. With a free Apple ID, switch
`entitlementsPath` in `ios/xtool.yml` to `KeyflapApprover-free.entitlements` (no push).
The broker side needs nothing from Apple unless you want push.

## Setup (paid program)

1. **Enroll** in the Apple Developer Program (developer.apple.com/programs/enroll).
   Note your **Team ID** (Membership details; 10 characters).

2. **Pick the bundle id.** The repo ships the placeholder `com.example.KeyflapApprover`:
   replace it with one you own in `ios/xtool.yml`, `ios/xcode/project.yml` and
   `ios/ci/testflight.yml` (or the `IOS_BUNDLE_ID` variable), and pass the same id to the
   broker as `--apns-bundle-id` (it is the APNs topic). Register it:
   Certificates, Identifiers & Profiles → Identifiers → + → App IDs → App, with the
   **Push Notifications** capability. (xtool can register the App ID itself; enabling Push
   there is what matters.)

3. **App Store Connect API key** (xtool login, and the TestFlight workflow): App Store
   Connect → Users and Access → Integrations → App Store Connect API → Team Keys → +,
   role **App Manager**. Download `AuthKey_<KEYID>.p8` (only once) and note the **Key
   ID** and **Issuer ID**.

4. **APNs auth key** (the broker's pushes): Certificates, Identifiers & Profiles → Keys
   → +, enable **Apple Push Notifications service (APNs)**, download `AuthKey_<KEYID>.p8`
   and note its **Key ID**. Keep it with the broker's data (e.g. `~/.keyflap/apns/`, 0600):
   it can send notifications to your app and nothing else.

5. **Xcode .xip**: download Xcode from https://developer.apple.com/download/all/?q=Xcode
   (needs your Apple ID in the browser). Keep the path, e.g. `~/Downloads/Xcode_26.xip`.

6. **Install xtool and usbmuxd** (Arch, no Mac needed):

   ```sh
   # usbmuxd talks to the iPhone over USB
   sudo pacman -S usbmuxd libimobiledevice     # or: yay -S usbmuxd-git
   sudo systemctl enable --now usbmuxd

   # Swift toolchain (xtool builds with SwiftPM): swiftly, or the AUR package
   curl -O https://download.swift.org/swiftly/linux/swiftly-$(uname -m).tar.gz
   tar zxf swiftly-$(uname -m).tar.gz && ./swiftly init     # then: swiftly install latest
   # (alternative: yay -S swift-bin)

   # xtool itself (AppImage)
   curl -fL "https://github.com/xtool-org/xtool/releases/latest/download/xtool-$(uname -m).AppImage" -o ~/.local/bin/xtool
   chmod +x ~/.local/bin/xtool
   xtool --help
   ```

   Prefer containers? xtool ships a `Dockerfile`/`docker-compose.yml` in its repo; the
   device connection still needs the host's usbmuxd socket
   (`-v /var/run/usbmuxd:/var/run/usbmuxd`).

7. **`xtool setup`**: choose **API Key** login, give it the key from step 3 (Issuer ID,
   Key ID, the .p8), then the path of the Xcode .xip. It builds an iOS SDK for SwiftPM
   (`swift sdk list` shows `darwin`).

8. **Prepare the iPhone**: plug it in by USB, tap **Trust** and enter the passcode.
   Settings → Privacy & Security → **Developer Mode** → on (the phone restarts; confirm).
   `xtool devices` should list it. Face ID must be set up.

9. **Build and install**:

   ```sh
   cd ios
   xtool dev            # builds, signs with your team, installs and launches
   ```

   Debug builds use the APNs **sandbox**.

10. **Run the broker with push** (phone mode, as in `phone-approver.md`):

    ```sh
    keyflap daemon --unprotected --approver phone \
      --approver-origin https://broker.example.ts.net:8766 \
      --apns-key ~/.keyflap/apns/AuthKey_ABCDE12345.p8 --apns-key-id ABCDE12345 \
      --apns-team-id TEAM123456 --apns-bundle-id com.example.KeyflapApprover \
      --apns-sandbox            # for xtool dev (debug) builds; omit for TestFlight builds
    ```

    `--apns-generic` keeps the site's name out of the notification text (see Privacy).

    In service mode, give the same `--apns-*` options to `install.sh` instead (the key
    is sealed as a systemd credential); `sudo keyflap approver pair` shows the pairing QR.

11. **Pair**: with no phone paired (or with `--pair`), the daemon prints the one-time
    link and, on a terminal, a QR code (`keyflap approver qr` shows it again; in service mode
    `sudo keyflap approver pair`). In the app:
    **Pair with a broker** → scan (or paste the link) → Face ID. If a phone is already
    paired, that phone gets an "Add another phone?" request with a check code; approve it
    only if the new iPhone shows the same code.

The iPhone must reach the approver origin: the same tailnet as the broker
(`tailscale serve`, as for the web approver) or your own certificate. The app only talks
https (a valid certificate; no self-signed ones).

## TestFlight via GitHub Actions

`ios/ci/testflight.yml` archives a Release build, signs it with automatic signing through
the App Store Connect API key, and uploads it to TestFlight. It does nothing until it is
configured:

1. Create the app record in App Store Connect (My Apps → + → New App, your bundle id).
2. Repository secrets: `ASC_KEY_ID`, `ASC_ISSUER_ID`, `ASC_KEY_P8` (the .p8 file's text),
   `APPLE_TEAM_ID`; optional repository variable `IOS_BUNDLE_ID`.
3. Copy the workflows into place (pushing workflow files needs a token with the
   `workflow` scope, e.g. `gh auth refresh -s workflow`):

   ```sh
   cp ios/ci/ios.yml .github/workflows/ios.yml
   cp ios/ci/testflight.yml .github/workflows/ios-testflight.yml
   ```

4. Actions → iOS TestFlight → Run workflow. TestFlight builds are production APNs builds:
   run the broker **without** `--apns-sandbox` for them.

`ios/ci/ios.yml` is the PR check: on changes under `ios/` only, one macOS job (≤ 15 min)
runs the core tests on the host and builds the app for the iOS Simulator without
signing (XcodeGen project in `ios/xcode/`).

## Building and testing without a Mac

- The platform-independent core (`ios/KeyflapApproverCore`: statement encoding, checks,
  pairing links, API client, formatting; Foundation only) builds and tests on Linux:

  ```sh
  podman run --rm -v "$PWD/ios:/src:Z" -w /src/KeyflapApproverCore docker.io/library/swift:6.2 swift test
  ```

- Cross-language fixtures (`ios/KeyflapApproverCore/Fixtures/`): `ts-vectors.json` is
  written by `packages/signer/test/native-vectors.test.ts` (`UPDATE_VECTORS=1`); the Swift
  tests check their encoder against it byte for byte and verify its signatures.
  `swift-vectors.json` is written by the Swift tests (`-e WRITE_VECTORS=1` on the command
  above); the TypeScript test checks that the signer accepts its key, pairing proof and
  approval signature.
- The app target (SwiftUI, CryptoKit Secure Enclave, LocalAuthentication, AVFoundation,
  UserNotifications) only compiles against the iOS SDK: xtool locally (needs the .xip),
  or the macOS workflow.
- App icon: `ios/scripts/make-icon.sh` renders `ios/AppHost/AppIcon.svg`.

## Privacy and what goes where

- **APNs payload**: the request id and, unless `--apns-generic`, the verified site's host
  ("Approve sign-in to github.com?"). Never your words, the agent's name, or anything
  secret. Apple relays it in the clear (TLS to Apple), so Apple learns which sites you sign
  in to and when; `--apns-generic` sends "Open Keyflap to review the request." instead.
  The app fetches details from the broker over its paired connection.
- **On the iPhone**: the Secure Enclave key (never exportable), the broker's bearer token
  for this phone (Keychain, this device only, readable after first unlock so a lock-screen
  Deny works), the list of paired brokers and a local activity history (app container,
  file protection). Nothing is synced.
- **On the broker**: the app key's public half in the signer's key store; the bearer
  token's hash and the APNs device token in `approver/devices.json` (0600).

## Lock-screen actions

- **Approve** opens the app (`.foreground`, `.authenticationRequired`) on the request
  sheet with all its details, then starts Face ID for the signature. It never approves
  from the notification text alone.
- **Deny** works without unlocking: denial needs no key and fails closed. Anyone holding
  your locked phone could deny a request (a denial of service, never a sign-in).

## Unpairing and lost phones

In the app: Settings → swipe the broker → Unpair (its key is deleted from the iPhone; the
broker drops it too unless it was the last phone). A lost phone: on the broker,
`keyflap approver list` (the app's keys show as `ios-app`) and `keyflap approver remove <id>`
with the daemon stopped, as for passkey phones.
