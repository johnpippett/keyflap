# Phone approver

> This web page is the supported phone approver. The native iPhone app
> ([ios-app.md](ios-app.md)) is parked: built and tested on the broker side, not shipped.

Approve logins on your phone with Face ID, a fingerprint, or your device PIN. The
approval *is* a WebAuthn assertion by a passkey on your phone; the broker's signer
checks that assertion itself before it signs anything or releases a password. Nothing
on the broker machine can produce an approval on its own.

The page signs only what it shows: before Face ID it checks the request against the card
(site, sign-in or registration, credential type, any allow-for window or "Keep me signed
in"), and it computes what it signs itself. If something doesn't match, it denies the
request and says so. In service mode the page is served by its own service, so the broker
core can't change it either (design:
[APPROVER_INTEGRITY_PLAN.md](../APPROVER_INTEGRITY_PLAN.md)).

High-risk sites (government, email and identity providers, payments and banking; see
`packages/signer/src/risk.ts`, plus anything you pass with `--high-risk`) can only be
approved this way. The terminal approver denies them.

## What you need

- A phone browser that supports passkeys with user verification (iOS 16+ Safari,
  Android Chrome).
- An **HTTPS origin** your phone can reach that points at the broker machine. WebAuthn
  needs a secure origin with a real hostname; a LAN IP or a self-signed certificate won't
  work. The broker does not run or use any relay of its own.

The simplest private option is [Tailscale](https://tailscale.com) on both devices, with
MagicDNS and HTTPS certificates turned on. On a Mac use the standalone Tailscale app from
tailscale.com/download: the full install can't watch the App Store app's setting and refuses
it.

With the one-command install, `sudo keyflap setup` does all of this: it runs `tailscale serve`
and pairs your phone. The commands below are for dev mode.

```sh
# On the broker machine (tailnet name e.g. tail1234.ts.net, machine "broker"):
tailscale serve --bg --https=8766 http://127.0.0.1:8766
keyflap daemon --unprotected --approver phone --approver-origin https://broker.tail1234.ts.net:8766
```

On a Mac the Tailscale command is `/Applications/Tailscale.app/Contents/MacOS/Tailscale` when
`tailscale` is not on your `PATH`.

### The approval address is watched

Whoever can change that `tailscale serve` setting decides what answers at
`https://broker.tail1234.ts.net:8766`. On a Mac that is any local user; on Linux it is root, or
the user named by `tailscale set --operator`. An agent running as that user could point the
address at a page of its own, and your phone would take it for the approver. Keyflap can't lock
Tailscale, so its signer watches the setting instead. With a `.ts.net` origin it reads the
setting (what `tailscale serve status --json` prints) every 2 seconds, and every 250 ms while an
approval or a pairing waits. It expects exactly one thing: the origin's host and port proxied to
the approver's listener, HTTPS on, nothing else on that port, no Funnel. Nothing at all served
at that host and port is not a change: Tailscale reports that for a few seconds while it starts,
and with no page there, nothing can fake the approver.

When the setting points anywhere else, the signer latches. It removes every paired phone and
refuses approvals and pairing. The broker cancels every pending approval, signs every phone out,
sends each phone with notifications on a push titled **Approval address changed**, and writes
`approver.address_tripped` to the audit log. The page says "The approval address on your Mac
was changed. Don't approve anything until you've checked it at your Mac." (or "computer"). A
restart does not clear the latch; it is kept in the encrypted key store.

To recover, fix the setting at the computer, then clear the latch and pair your phone again.
When only the proxy target was changed, the `serve --bg` line is enough. Otherwise start from
`tailscale serve reset`, which clears every serve setting on the computer (put back any others
you had). On Linux in service mode, run the `tailscale` lines with `sudo`.

```sh
tailscale serve reset
tailscale serve --bg --https=8766 http://127.0.0.1:8766
sudo keyflap approver pair                                  # service mode
keyflap approver pair --approver-origin https://broker.tail1234.ts.net:8766   # dev mode, daemon stopped
```

`approver pair` reads the setting again first. While it is still wrong, it prints the setting it
saw and the fix instead of a pairing link. `sudo keyflap status` shows the address on its
`Address:` line and `sudo keyflap doctor` as the check `approver-address`. In dev mode the
daemon prints a change in its terminal. After a change they say
when it was changed and what was there, that phones were signed out to be safe, and either
"It is right again now" (then only pairing is left) or what is there now.

Before you pair again, delete the Keyflap icon from the phone's home screen and clear the
website data for the approval address (Settings > Apps > Safari > Advanced > Website Data). A
page that answered at the address while it was changed could have left a script behind.

When the signer cannot read the setting (Tailscale stopped or restarting, the CLI missing or
changed), or Tailscale is not connected yet, approvals pause instead: nothing is approved, no
new request reaches your phone and no phone can pair, and they resume by themselves on the next
good read, with your phones kept. Nothing served at the address while Tailscale is connected is
a change, as above: anything else on the computer could answer there.
When Tailscale restarts (an update, a reboot, the app relaunched), the pause usually lasts a few
seconds. For the first 30 seconds of a pause like that (once every 10 minutes), an approval
waiting on your phone stays there and no warning is shown; if you tap Approve before Tailscale answers, the page says "Not
approved: Keyflap can't check the approval address right now. Try again in a moment." After 30
seconds, or for a cause a restart doesn't explain, waiting approvals are cancelled and the page
says "Keyflap can't check the approval address on your Mac right now. Approvals are off until it
can." In service mode the signer runs only a `tailscale` that only root can change. On
a Mac with the standalone Tailscale app it runs no command: it asks Tailscale's own service on
`127.0.0.1`, with a token the installer lets it read
([service-mode.md](service-mode.md), "How the signer reads Tailscale's setting"). The
App Store Tailscale app can't be read this way.

The watch is a tripwire, not a lock. A change that is undone within one poll, timed to your
phone's request, is not caught. The broker tells the signer when an approval waits, so a broker
that is itself compromised can keep the signer at the 2-second poll. The warning reaches only
phones that turned notifications on. Only a `.ts.net` origin is watched: with another front
(your own certificate or proxy), `keyflap doctor` says that Keyflap can't watch it. An address
that only Keyflap controls is the next roadmap item.

`--unprotected` is the same-user development mode (the broker runs as your OS user;
design: [ISOLATION_PLAN.md](../ISOLATION_PLAN.md)). In service mode the approver options are installer flags
(`install.sh --approver-origin … [--approver-listen …] [--tls-cert … --tls-key …]`; see
[service-mode.md](service-mode.md)); the page and its TLS then live in the approver service
(`keyflap-approver`, on a Mac `com.keyflap.approver`), not the core.

`tailscale serve` terminates TLS with a real certificate and forwards to the approver's
loopback listener (default `127.0.0.1:8766`). Without `--tls-cert/--tls-key` the
approver refuses to listen anywhere but loopback, so it can only be reached through such
a proxy. With your own certificate instead:

```sh
keyflap daemon --unprotected --approver phone --approver-origin https://phone.example.net:8766 \
  --approver-listen 0.0.0.0:8766 --tls-cert cert.pem --tls-key key.pem
```

## Pairing

With no phone paired, the daemon prints a one-time link (valid 10 minutes) to its log and
writes it to `<data-dir>/approver/pairing-url` (0600). Open it on the phone and tap
**Pair this phone**; the phone creates a passkey for the approver page (user verification
required). The first phone is trusted on first use, so treat the link like a password:
whoever opens it first becomes your approver. In service mode the link is never logged;
`sudo keyflap approver pair` starts pairing and prints it.

On a terminal the link is also shown as a QR code: point the iPhone camera at it and it
opens in Safari. **On iOS, pair in Safari first, then Share → Add to Home Screen.** iOS
keeps Safari's cookies (where the pairing lives) apart from each home-screen app and copies
them only when the app is added, so an app added before pairing stays unpaired. The page
says so: in Safari it shows "Add to Home Screen" once paired, and an unpaired home-screen
app tells you to delete it and redo the steps from Safari. `keyflap approver qr` shows the
open link's QR code again.

iOS copies the home-screen icon once, when you add the page, and never updates it. After a
Keyflap update that changes the icon, delete the home-screen app and add it again from
Safari (the pairing stays: it lives in Safari). The page versions its icon links by content
(`?v=<hash>`), so Safari itself always fetches a changed icon.

To add another phone, start the daemon with `--pair` (service mode:
`sudo keyflap approver pair`). The new phone registers and shows a
check code; an **already-paired phone must approve adding it**, and its request card shows
the same code. Approve only if the codes match. The signer refuses the new key without
that approval.

Tap **Notify me about new requests** on the phone to get push notifications (on iOS,
add the page to your home screen first). Notifications say only "Approval requested";
the details are fetched over the paired connection when you open the page. Human-check
notifications say "Human check on <site>" and open the live view directly.

## Approving

Each request shows only: your own words (the live intent), the verified site origin, the
agent's name, and the credential type. Requests are cards you can swipe: drag the card right
(or tap the blue check under it) to approve, which runs the passkey prompt on the phone; drag it
left (or tap the cross) to deny. A swipe right never approves by itself: the page checks the
request and your phone asks for Face ID, a fingerprint or the device PIN, and the card leaves
only after that succeeds. If you cancel, the card stays and says "Not approved". With an
`allow-for` rule (24 hours at most), the card says that approving also lets this agent sign in
there again without asking, for that long. When several
requests wait, up to two more show behind the first. Unanswered requests deny after two minutes
(the broker's own timeout is shorter).

### Keep me signed in (high-risk sites)

The broker saves each agent's browser state across restarts, except for high-risk sites
(banks, email, identity providers, your `--high-risk` list, and sites you set to
`keyflap policy set <site> --ask-strong`). For a sign-in to one of
those, the card shows a checkbox **Keep me signed in on <site>**, unticked. Tick it before
you approve to keep that agent's session for that site saved across broker restarts. The
ticked box is part of what your Face ID signs (the signer checks the signature over it),
and the broker records the opt-in only after the signer accepted that approval. Nothing
the agent sends can set it. Undo it with `keyflap sessions unkeep <site> --agent ID`. The iOS
app doesn't offer the box yet (use `keyflap sessions keep` there).

## Human checks (handoff)

When a site answers the agent with a human check (a CAPTCHA, "confirm you are human") and
the agent calls `browser_handoff`, you take over that one page from your phone. The broker
never solves or clicks a check itself.

1. A notification says **Human check on <site>** (the site is the verified host; with Web
   Push the payload is encrypted, so the push service doesn't see it). Tap it.
2. It opens the live view (`/handoff`, a separate page with a steel LIVE header and no
   blue, never the approvals page). It shows your words, the site and the agent's name,
   then asks for Face ID once to start (if your browser wants a tap first, tap **Start
   live view**).
3. The picture is the agent's page, refreshed a few times a second. Tap it to click; use
   the scroll buttons, drag for sliders, the text box and the named keys (Enter, Tab, ⌫,
   Esc, arrows) to type. To see a small check better, pinch (or tap **+**) to zoom and
   move the view with two fingers; **Fit** shows the whole page again. One finger always
   taps and drags on the site, zoomed or not. Text into password or one-time-code fields is refused ("Use the
   broker's sign-in for passwords"). The agent can see the page after you tap Done, with
   what you typed redacted; don't type passwords here.
4. Tap **Done** (or **Cancel**). The agent continues. A finished handoff starts the site's
   session timer (`--session-ttl`) and saves the browser state.

Rules: only when a human check is detected and you asked for something in the last 10
minutes; one per agent at a time (at most two overall); at most three notifications per
agent per 10 minutes, and none within 30 s of one you cancelled or let expire; it ends
after 5 minutes, or when the page closes or leaves the site. While it is open the broker
denies every sign-in for that agent (`handoff_open`), so no approval card for it can
appear while you look at the website's pixels. Only the phone that started the live view
gets the picture. The approvals page shows an open handoff as a link ("Human check waiting
on <site>"). The iOS app shows the notification but has no live view yet; open the web
page for it.

### Check and sign-in with one approval

When the check stands in front of a sign-in the broker could do for that agent right now
(it holds one password or passkey for the site, your policy for it is the default `ask` or
`allow-for`, the site isn't high-risk, and nothing has been signed in for this request yet),
you approve once instead of twice:

1. The notification is the ordinary **Approval requested**; it opens the approvals page.
2. The card reads **Human check, then sign in to <site>?**, with your words, the site, the
   agent, the credential, and "One sign-in within 7 minutes, without asking again.
   Approving opens a live view of the website on this phone."
3. **Approve** (swipe right or tap the check; one Face ID). The phone goes straight to the live view; there is no second
   Face ID. The live view adds: "You approved this human check and one sign-in: after you
   tap Done, the agent signs in once without asking again."
4. Solve the check, tap **Done**. The agent signs in with no further prompt.

What that approval allows: one sign-in, by that agent, at that exact site, with that
credential, within 7 minutes, and only after you tapped Done. **Cancel**, letting it expire,
the page leaving the site or closing, or revoking the agent throws it away; the next sign-in
asks as usual. Denying the card (swipe left or tap the cross) cancels the human check. Only the phone that approved
gets the live view. The iOS app doesn't show these cards (it has no live view yet).

Everything else is the plain flow above: a high-risk site, `--ask-strong` or `--deny`
sites, a site with several or no credentials, or a check that appears after the password
(you already approved that sign-in) get the "Human check on <site>" notification, the Face
ID start on the live view, and (if needed) a separate sign-in approval afterwards.

## Losing a phone

In dev mode, stop the daemon, then:

```sh
keyflap approver list             # passkey ids the signer trusts
keyflap approver remove <id>      # that phone can no longer approve; its cookie stops working
```

The approver checks every request's phone against the signer's list, so a removed phone's
cookie stops working at once, also in service mode with the services running: it can no
longer see cards, deny, subscribe to push or drive a live view (any live view it controls
ends).

Only this offline command can remove your last phone (the running daemon can't, so a
broker bug can't swap your phone for a key of its own). With no phone left, the next
`keyflap daemon --approver phone` offers pairing again. In service mode, run
`sudo keyflap approver list` and `sudo keyflap approver remove <id>` while the services run; see
[service-mode.md](service-mode.md#using-it).

## Where things live

In dev mode, all under the data dir (default `~/.keyflap`, 0700), which your agent's OS user
could read; [service mode](service-mode.md) keeps them under service accounts instead
(`/var/lib/keyflap/signer` and `/var/lib/keyflap/core`, on a Mac `/Library/Keyflap/data/signer`
and `/Library/Keyflap/data/core`).

| Path | Holds |
|---|---|
| `signer/keys.enc.json` | trusted approver passkeys (public keys), encrypted with the rest of the store |
| `approver/devices.json` | hashes of paired devices' cookies, their push subscriptions |
| `approver/vapid.json` | the push signing key (it can only send notifications) |
| `approver/pairing-url` | the current one-time pairing link, while one is open |

None of these can approve anything. In phone mode the daemon creates no
`approver-key.json`, and once a phone is paired the signer ignores Ed25519 approver keys
even if one is configured.
