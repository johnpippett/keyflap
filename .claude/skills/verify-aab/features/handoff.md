# Human handoff on the phone (`handoff`)

A site answers the agent's sign-in with a human check; the agent calls `browser_handoff`; the owner opens the live view on their paired phone, confirms once with Face ID, taps "I'm human" in the picture and taps Done; the agent continues signed in (SESSIONS_PLAN section 3, P3). When the check stands in front of the sign-in page instead (P3b, like huggingface.co), the owner approves ONE card, "Human check, then sign in to <host>?", the live view opens with no second Face ID, and after Done the agent's `auth_login` signs in with no further prompt. Here the phone is simulated inside the sandbox.

## Sub-features

- `ho-pair` the daemon restarts with `--approver phone` on a free loopback port (`http://approver.localhost:<port>`); a simulated phone pairs through the one-time link with a UV passkey.
- `ho-approve` the handoff test site's (`waf.hc.localhost`, AWS WAF mode) password sign-in is approved on the phone card (the words and the verified origin are on it) and answers `{"status":"challenge"}`.
- `ho-open` `browser_handoff` opens one handoff (`handoff.requested` once); while it is open every other tool of the agent fails with "a human check is in progress on your page; call browser_handoff to wait for it".
- `ho-link` the approvals page shows "Human check waiting on <host>, open live view" as a link, never pixels or an approve control.
- `ho-start` `/handoff` shows the broker's labels (host, agent, your words) and starts the live view with exactly one WebAuthn call (the Face ID start), no approve control.
- `ho-zoom` on a 390×844 phone screen: a two-finger pinch on the picture zooms to 3×, a two-finger drag pans (the transform changes, the scale doesn't), and the zoomed view shows a sharp region frame from the core (`clip=` on the frame request); no gesture reaches the site (`handoff.ended` counts exactly one click, no drags or scrolls). **Fit** resets it.
- `ho-tap` a one-finger tap on "I'm human" where the zoomed picture draws it passes the check (the tap went through the zoom to the right page point); Done ends it and `browser_handoff` answers `{"status":"done"}`.
- `ho-continue` the agent's next snapshot shows `Signed in as alice`, `humanCheck: false`.
- `ho-audit` `handoff.ended {outcome: "done", inputs: {clicks: 1, ...}}`, no image content in what the agent received, no secret leaks, the chain verifies.
- `ho-combined-card` (P3b) on `gate.hc.localhost` (AWS WAF in front of `/password/login`, `challengeAt: 'login-page'`) the snapshot shows `humanCheck: true` and no form; `browser_handoff` puts ONE approval card on `/`: "Human check, then sign in to <host>?", the words, the verified origin, the agent, `password (sign-in)`, "One sign-in within 7 minutes"; no live-view link next to it; `handoff.requested {withSignIn: true}`.
- `ho-combined-live` approving it (one Face ID) takes the phone to `/handoff`, where the live view opens with no further WebAuthn call and the broker's "signs in once without asking again" note; no approve control there.
- `ho-combined-signin` (one-handed zoom: **+** twice, a two-finger drag to the page's top left) tap "I'm human", Done -> `done`; `auth_login` -> `{"status":"success"}` with no new approval; exactly one `approval` event and one WebAuthn call for the whole flow; `grant.created`, `handoff.started {via: "approval"}`, `grant.armed`, `grant.used {singleUse: true}`; no leaks; the chain verifies.

## How to get to it (user POV)

- The user runs `keyflap daemon --approver phone --approver-origin https://<host>` and pairs their phone; when the agent hits a human check, the phone says "Human check on <site>"; tapping it opens `/handoff`, one Face ID, then the picture; tap through the check, then Done.
- With the terminal approver `browser_handoff` answers `unsupported` (`not_available`).

## Driving it with verify-aab

Preconditions:

- `scripts/doctor.sh` printed `RESULT doctor PASS`.
- **Run it last in a launch.** Pairing a phone latches the sandbox key store to phone mode, so the terminal approver (the FIFO the other features answer) can no longer approve. Relaunch for other features.
- The handoff RPs from `rp-server.mjs` (`waf.hc.localhost`, key `hc`, check after the password; `gate.hc.localhost`, key `gate`, check in front of the sign-in page; both on the second JSON line of `logs/rp.out`) are up. While the daemon is stopped for the switch, `drive.sh` stores a password-only item for `hc.localhost` (alice, the fixture password), which both use.

- **Run all of it.** `scripts/drive.sh handoff`. Exit code `0`. `drive.sh` writes `$RUN/daemon.args` (`--approver phone --approver-origin http://approver.localhost:<free port> --approver-listen 127.0.0.1:<port>`) and calls `restart_daemon` (our daemon pid only, same data dir), then `drive.mjs handoff`.
- **The simulated phone.** `drive.mjs` launches its own headless Chromium inside the sandbox env (never the managed browser), adds a CDP virtual authenticator (UV, automatic presence), reads the one-time link from `<data dir>/approver/pairing-url`, pairs, approves the sign-in card, then opens `/handoff` from the approvals page's link (the sandbox has no push service, so it follows the link instead of a notification).
- **Zoom and pan.** The phone context has `hasTouch`; pinch and two-finger drags are CDP `Input.dispatchTouchEvent` calls on the *phone's* page (its own browser, never the managed one), with both fingers inside the picture. The tap is then a one-finger touch at the point where the transformed picture draws the button.
- **The tap.** The live view is a picture, so a tap is a point: the phone renders the test RP's own challenge page (`packages/test-rp/src/pages.ts`) in a scratch tab at 1280×720 to find where "I'm human" is, and clicks that point on the live image. This is the one place the skill uses coordinates; the agent itself still never does.
- **The combined flow (P3b)** runs after the plain one, under a new intent: the plain one signed in on `waf.hc.localhost` under its own intent, which is why that check stayed a plain handoff (a check after the password never asks twice).
- **Proof.** `<evidence dir>/handoff/`: `phone-approval-card.txt`, `held-tool-error.txt`, `phone-handoff-link.txt`, `phone-live-view-labels.txt`, `phone-zoom.txt` (the view after the pinch and the pan), `phone-zoomed-{light,dark}.png`, `phone-zoomed-after-tap-{light,dark}.png`, `phone-combined-zoomed-{light,dark}.png`, `phone-live-view.png` and `phone-after-tap.png` (viewport screenshots of the *phone's* page, a separate browser; each also as `-light.png` / `-dark.png` at a 390×844 phone size, and `phone-handoff-link-{light,dark}.png` for the approvals page's link card), `snapshot-after-handoff.txt`; for P3b `combined-snapshot-check.txt`, `phone-combined-card.txt`, `phone-combined-live-view-labels.txt`, `phone-combined-live-view.png`, `phone-combined-after-tap.png`, `combined-snapshot-after.txt`, `audit-combined.json`; `steps.jsonl`, `audit-tail.json`, `audit-verify.txt`.

## Gotchas

- Why a separate, password-only site: a fill of password + TOTP verifies the phone's one assertion once per released field, and the signer requires the approver's sign counter to grow when it is non-zero. Chromium's virtual authenticator counts up, so the second field (the TOTP) is refused and the fill ends `denied` (`internal_error`). Phones' synced passkeys report 0, so real phones aren't affected; it is a pre-existing M4 behaviour, noted in the run's report, not something this skill works around in product code.

- Run `scripts/doctor.sh` after it if you look further: the daemon pid, MCP port and `approverOrigin` changed (`state.json`); doctor also checks the approver port is our daemon's loopback listener and not 8766.
- Push notifications (Web Push payload, APNs) are not exercised here: no push service is reachable from the sandbox, by design. `packages/core/test/handoff-phone.e2e.test.ts` and `packages/approver/test/handoff-server.test.ts` cover them with a local push stand-in.
- Never use the user's real phone, Tailscale or a real push service for this. The real-phone flow stays in `needs-approval.md`.
