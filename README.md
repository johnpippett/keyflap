<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/assets/keyflap-logo-on-dark.svg">
    <img src=".github/assets/keyflap-logo-on-light.svg" alt="Keyflap" width="313">
  </picture>
</p>

<h3 align="center">Your AI agent signs in. It never sees your password.</h3>

<p align="center">
  <a href="docs/GETTING_STARTED.md">Get started</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="#roadmap">Roadmap</a> ·
  <a href="docs/ARCHITECTURE.md">Design</a> ·
  <a href="SECURITY.md">Security</a>
</p>

---

Keyflap signs AI agents into websites for you. It uses your passkeys, your passwords and
your one-time codes. The agent does not get these secrets. The agent gets only one of two
results: **signed in** or **denied**.

Each sign-in starts with a request that you typed. Before Keyflap signs in, your phone shows
the request and the real website. You approve with Face ID or your fingerprint.

> [!WARNING]
> **Keyflap is early alpha software.** It uses real credentials on real accounts. Nobody
> outside the project has audited it, and it has no warranty. Use test accounts first. Do
> not connect an account that you cannot lose. Read [SECURITY.md](SECURITY.md) before you
> use it.

## The problem

An AI agent that uses a browser must sign in to do useful work. Usually you have two bad
options:

- **Give the agent your password.** The agent can then leak it, log it or use it on a
  fake website.
- **Sign in yourself each time.** This stops the agent until you return.

Keyflap gives a third option. The agent asks, you approve, and Keyflap does the sign-in.
The secret stays with Keyflap.

## How it works

1. **You make a request.** You tell your agent: "Sign me in to GitHub."
   A hook in the agent app sends your exact words to Keyflap. The AI model cannot change
   these words.
2. **The agent goes to the website.** The agent uses a browser that Keyflap controls.
3. **Keyflap finds the real website.** The browser tells Keyflap the address of the page.
   The agent and the page cannot change this address. A fake website gets no credential,
   because no credential matches its address.
4. **Your phone asks you.** The approval card shows your words, the real website and the
   name of the agent. It never shows text from the agent or from the page.
5. **You approve.** You use Face ID, your fingerprint or your device PIN.
6. **Keyflap signs in.** A separate part of Keyflap, the *signer*, checks your approval.
   Then it uses the passkey or types the password and code into the page.
7. **The agent gets the result.** The agent gets "signed in" or "denied". It does not get
   the secret.

```
  You ──"sign me in"──▶ Agent ──▶ Keyflap ──▶ Website
                                     │
                          Your phone: "Approve?"
                                     │  Face ID
                                     ▼
                     Signer checks your approval, then signs in
                                     │
  Agent ◀────────── "signed in" or "denied" (no secret) ────┘
```

If something is wrong or not clear, Keyflap denies the sign-in. An error is a denial. A
timeout is a denial. If you did not make a request, Keyflap denies the sign-in and does not
ask you.

## What you get

| | |
|---|---|
| **Passkeys** | Keyflap adds a passkey to an account and signs in with it. Your other sign-in methods do not change. |
| **Passwords and one-time codes** | Keyflap keeps them in the signer. It types them into the page itself, also the 6-digit code. |
| **Password managers** | Use your logins from [Proton Pass](docs/integrations/proton-pass.md) or [1Password](docs/integrations/1password.md). Keyflap reads a login only after you approve. |
| **Phone approval** | A web page on your phone. No app store is necessary. You swipe a card to approve or deny, and each approval needs Face ID, a fingerprint or a PIN. |
| **Rules for each website** | Deny a website, always ask, ask with Face ID each time, or allow for a set time (24 hours at most) after one approval. Banks, payments, shopping, email, sign-in providers, code hosting, password managers and government websites always need a new approval with Face ID, a fingerprint or a PIN. |
| **Saved sessions** | Keyflap keeps the agent signed in after a restart, and encrypts this data. For high-risk websites, it does this only if you allow it. |
| **Human checks** | Keyflap does not solve CAPTCHAs. When a website shows one, you solve it in a live view on your phone. |
| **Audit log** | Keyflap records each request and each decision in a hash-chained log. `keyflap audit verify` finds changes to the log. |

## Supported agents

- [Claude Code](docs/integrations/claude-code.md)
- [Codex CLI](docs/integrations/codex.md)
- [Hermes Agent](docs/integrations/hermes.md) (gateway direct messages)

Other agents need a hook that sends your exact words to Keyflap.

## Get started

**Install it with your agent.** Paste this into your agent, on the computer where Keyflap
should run:

> Install Keyflap for me. Follow https://github.com/johnpippett/keyflap/blob/main/docs/INSTALL_FOR_AGENTS.md, then give me the one command to run myself.

The agent checks your computer and explains each step. Then it gives you one command, and you
run that command yourself. The agent cannot do it for you, on purpose: it must never set up
its own guardrails.

**Or run the command yourself.** It works on a Mac with Apple silicon and on Linux. First set
up [Tailscale](https://tailscale.com/download) on this computer and on your phone, in the same
tailnet, with MagicDNS and HTTPS certificates turned on. On a Mac, use the standalone app from
tailscale.com/download: the App Store app does not work with Keyflap. Then run this from your
own account, the one your agents run as:

```sh
curl -fsSL https://github.com/johnpippett/keyflap/releases/latest/download/install-keyflap.sh | sudo bash
```

The command asks for your admin password. It downloads Keyflap and checks the download
against fingerprints in its own script. Then it installs Keyflap as separate system users, so
an agent that runs as you cannot read Keyflap's keys, memory or browser. A guided setup
follows in the same window. You scan a code with your phone, pick your agent and connect your
password manager. Later, `sudo keyflap` opens the management console, and the same command
upgrades Keyflap. To install step by step instead, read
[Getting started](docs/GETTING_STARTED.md).

**No admin password on your Mac?** The
[simple install](docs/integrations/simple-mac-install.md) runs Keyflap as you, without `sudo`.
It protects less: an agent that can run commands as you can read Keyflap's files and change
its code.

**See a demo first.** The demo container has Keyflap, a test website and a browser. You
approve in your terminal. You need podman or docker and a clone of this repository.

```sh
demo/run.sh
```

The demo works only with its test website. For the steps, read [demo/README.md](demo/README.md).

**Work on Keyflap.** Contributors run it from a clone, in dev mode. You need pnpm 10 and
Node.js 22.23.4 or newer (the [requirements](docs/GETTING_STARTED.md#requirements) list the
other Node versions):

```sh
git clone https://github.com/johnpippett/keyflap && cd keyflap
pnpm install
pnpm --filter @aab/shim exec playwright install chromium
pnpm keyflap setup --unprotected
```

Dev mode does not keep the agent away from Keyflap's files. Do not use it for real accounts.

## Platforms

| | Status |
|---|---|
| Linux | Supported on x86_64 and aarch64. Service mode needs systemd 250 or newer. |
| macOS | Supported on Apple silicon with macOS 14 or later (tested on macOS 26). Intel Macs are not supported yet. The browser runs without a window on a Mac, so you solve any human check on your phone. |
| Phone | Any phone browser with passkeys: iOS 16+ Safari or Android Chrome. Notifications on an iPhone need iOS 16.4 or later and the page added to the Home Screen. |
| Network | Tailscale on the computer and the phone, with MagicDNS and HTTPS certificates on. On a Mac, the standalone Tailscale app, not the App Store one. Without Tailscale, you need your own HTTPS address with a real certificate that your phone can reach. |

Keyflap runs on your own computer, for one person. It is not a hosted service.

## What Keyflap does not do

- It does not solve CAPTCHAs or hide from bot detection.
- It does not control what the agent does after it signs in.
- It does not send your keys or passwords to a Keyflap server. There is no Keyflap server.

## Roadmap

Keyflap is early alpha. This is what was built most recently, and what comes next. The next
steps are a plan, not a promise: the order and the timing can change. No step will make a
[security rule](docs/ARCHITECTURE.md#5-security-invariants) weaker.

**Built**

- **Mac service mode.** Keyflap runs as separate system users on a Mac, as it does on Linux.
  An agent that runs as you cannot read its keys or memory. The isolation tests check this on
  a real Mac.
- **A simple Mac install.** One installer that does not need `sudo`, for people who want to
  try Keyflap without the full install. It says that it protects less before it installs, and
  again in `keyflap status` and `keyflap doctor`.
- **Setup with help from your agent.** Your agent checks your computer and gives you one
  command. You do the steps that must stay yours: the admin password, pairing your phone,
  giving Keyflap a vault token or a password export, and approving the first sign-in.

**Next, in the coming weeks**

- **An approval address only Keyflap controls.** Today the approval page lives at an address
  that Tailscale serves, and other programs on your computer can change where it points.
  Keyflap watches that setting: when it changes, Keyflap cancels pending approvals, removes your
  paired phone and warns it, and refuses approvals until you fix the setting at the computer and
  pair your phone again. Next, the page gets an address that only Keyflap can answer.
- **An allow-for limit that you can change.** Today an allow-for rule lasts 24 hours at most.
  You will be able to change that limit.
- **A high-risk list that you can edit.** Today the list is built in. You will be able to add
  websites, remove ones, or reset the list, at your own machine, never through the agent.
- **Shared saved logins.** Each agent needs its own approval today. You will be able to let
  all your agents use the same saved login, one website at a time.

**Later**

- **Any private network, with no setup chores.** Tailscale gives the approval page its address
  and certificate for you. With another network, such as WireGuard, you need your own domain
  name and certificate today. Keyflap will set this up for you on any network.
- **A phone app.** For example, to tell you each time a saved login is used. The web page is
  the approver today, and an early iOS app is parked.
- **More agents, password managers and platforms.** Claude Code, Codex CLI, Hermes, Proton
  Pass, 1Password, Linux and Mac are the first ones, not the last.
- **Rules in an app.** You manage them in the command line today.
- **Limits after sign-in.** Rules for what an agent may do once it is signed in.
- **Your everyday browser.** A browser extension, so Keyflap works outside its own browser.
- **Keys in the phone.** The phone's secure hardware holds the keys, and Keyflap only
  passes messages.
- **Standards.** Moving passkeys in and out with the FIDO credential exchange format, and
  following the FIDO agent sign-in standard when it is published.

Want something else? [Open an issue](https://github.com/johnpippett/keyflap/issues).

## Learn more

- [Getting started](docs/GETTING_STARTED.md): all the setup steps and commands
- [Phone approver](docs/integrations/phone-approver.md): pair and use your phone
- [ARCHITECTURE.md](docs/ARCHITECTURE.md): the design, the security rules and the threat model
- [IMPLEMENTATION_NOTES.md](docs/IMPLEMENTATION_NOTES.md): decisions and changes to the design
- [SECURITY.md](SECURITY.md): how to report a vulnerability

## Contributing

Issues and pull requests are welcome. Before you change security code, read
[AGENTS.md](AGENTS.md) and the
[security invariants](docs/ARCHITECTURE.md#5-security-invariants). A change must not make
an invariant weaker. Each invariant has an automated test. For more, read
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

Keyflap uses the [Apache License 2.0](LICENSE). You can use, change and share it, also for
commercial work. It comes "as is", without warranty. The authors are not responsible for
damage that comes from its use (sections 7 and 8 of the license). You are responsible for
how you use it and for the accounts that you connect to it.
