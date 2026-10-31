import { resolve } from 'node:path';
import { type ParseArgsConfig, parseArgs } from 'node:util';
import { defaultDataDir } from './data-dir.ts';
import { type HermesOwner, parseOwner } from './hook-hermes.ts';
import { SYSTEMD_MANAGER, serviceManager } from './service/manager.ts';
import { SERVICE_PATHS } from './service/paths.ts';

export const DEFAULT_MCP_PORT = 8765;
export const DEFAULT_APPROVER_LISTEN = { host: '127.0.0.1', port: 8766 };

export interface PhoneApproverCli {
  origin: string;
  listen: { host: string; port: number };
  tlsCert: string | null;
  tlsKey: string | null;
  pair: boolean;
  apns: ApnsCli | null;
}

export interface ApnsCli {
  keyFile: string;
  keyId: string;
  teamId: string;
  bundleId: string;
  sandbox: boolean;
  generic: boolean;
}

export { defaultDataDir };

export type Command =
  | { kind: 'help' }
  | {
      kind: 'daemon';
      dataDir: string;
      mcpPort: number;
      headed: boolean;
      unprotected: true;
      phone: PhoneApproverCli | null;
      highRisk: string[];
      passwordSource: PasswordSourceCli | null;
      ephemeralBrowser: boolean;
    }
  | { kind: 'approver-list'; dataDir: string; json: boolean }
  | { kind: 'approver-remove'; dataDir: string; id: string }
  | { kind: 'approver-qr'; dataDir: string }
  | { kind: 'approver-pair'; dataDir: string; phone: DevPairPhone | null }
  | {
      kind: 'agent-add';
      dataDir: string;
      name: string;
      mcpPort: number;
      host?: AgentHost;
      owners?: string[];
    }
  | { kind: 'agent-list'; dataDir: string; json: boolean }
  | { kind: 'agent-revoke'; dataDir: string; id: string }
  | { kind: 'password-add'; dataDir: string; site: string; username: string | null; totp: boolean }
  | { kind: 'password-list'; dataDir: string; json: boolean }
  | { kind: 'password-remove'; dataDir: string; id: string }
  | {
      kind: 'password-import';
      dataDir: string;
      file: string;
      sites: string[];
      all: boolean;
      expect: string | null;
    }
  | { kind: 'password-source-trust'; tool: string }
  | {
      kind: 'password-source-add';
      source: 'proton-pass' | '1password';
      vault: string | undefined;
      bin: string | undefined;
      yes: boolean;
    }
  | { kind: 'password-source-remove' }
  | { kind: 'hook-claude-code'; dataDir: string; agentId: string; service: boolean }
  | { kind: 'hook-codex'; dataDir: string; agentId: string; service: boolean }
  | {
      kind: 'hook-hermes';
      dataDir: string;
      agentId: string;
      service: boolean;
      owners: HermesOwner[];
      profile: string | null;
    }
  | { kind: 'mcp-headers'; dataDir: string; agentId: string; service: boolean }
  | {
      kind: 'setup';
      dataDir: string;
      mcpPort: number;
      unprotected: boolean;
      host?: AgentHost;
    }
  | { kind: 'doctor'; dataDir: string; json: boolean; project: string | null }
  | {
      kind: 'policy-set';
      dataDir: string;
      site: string;
      agent: string | null;
      mode: PolicyModeCli | null;
      allowForMs: number | null;
      sessionTtlMs: number | null | undefined;
    }
  | { kind: 'policy-list'; dataDir: string; agent: string | null; json: boolean }
  | { kind: 'policy-remove'; dataDir: string; site: string; agent: string | null }
  | { kind: 'status'; dataDir: string; json: boolean }
  | { kind: 'audit-verify'; dataDir: string }
  | { kind: 'audit-tail'; dataDir: string; limit: number; json: boolean }
  | { kind: 'sessions-list'; dataDir: string; agent: string | null; json: boolean }
  | {
      kind: 'sessions-clear';
      dataDir: string;
      agent: string | null;
      all: boolean;
      site: string | null;
    }
  | { kind: 'sessions-keep'; dataDir: string; site: string; agent: string | null }
  | { kind: 'sessions-unkeep'; dataDir: string; site: string; agent: string | null };

export const AGENT_HOSTS = ['claude-code', 'hermes', 'codex'] as const;
export type AgentHost = (typeof AGENT_HOSTS)[number];

export function agentHost(v: unknown): AgentHost {
  if (typeof v === 'string' && (AGENT_HOSTS as readonly string[]).includes(v)) {
    return v as AgentHost;
  }
  throw new UsageError(`--host must be one of ${AGENT_HOSTS.join(', ')}, got "${String(v)}"`);
}

export type PolicyModeCli = 'deny' | 'ask' | 'ask-strong' | 'allow-for';

export interface PasswordSourceCli {
  kind: 'proton-pass' | '1password';
  bin: string | null;
  vault: string | null;
}

export class UsageError extends Error {}

const MANAGER = serviceManager() ?? SYSTEMD_MANAGER;

export const USAGE = `usage: keyflap <command> [options]

  keyflap setup [--unprotected [--data-dir DIR] [--mcp-port N]] [--host claude-code|hermes|codex]
      Guided, interactive setup (needs a terminal): phone approver origin (Tailscale),
      pairing, an agent and its Claude Code (or --host Hermes / Codex) config (shown and
      confirmed before anything is written), a password or Proton Pass, then keyflap
      doctor. Re-run it any time; it picks up what is done. Service mode:
      sudo keyflap setup. Dev mode: --unprotected.
  keyflap doctor [--json] [--project DIR] [--data-dir DIR]
      Checks the broker, the approver, agents and the Claude Code config (of DIR, default
      the current directory, plus your user settings). Exit 1 if a check fails.

  keyflap daemon --unprotected [--data-dir DIR] [--mcp-port N] [--headed] [--high-risk DOMAIN]...
             [--approver phone --approver-origin URL [--approver-listen HOST:PORT]
              [--tls-cert FILE --tls-key FILE] [--pair]
              [--apns-key FILE --apns-key-id ID --apns-team-id ID --apns-bundle-id ID
               [--apns-sandbox] [--apns-generic]]]
             [--password-source proton-pass [--proton-pass-vault NAME] [--proton-pass-bin PATH]]
             [--password-source 1password [--1password-vault NAME] [--op-bin PATH]]
             [--ephemeral-browser]
      Run the broker as your own OS user: signer, managed browser, intent socket,
      MCP endpoint on 127.0.0.1:N (default ${DEFAULT_MCP_PORT}). Development only: an
      agent with shell access as you can read the broker's files, memory and code
      (docs/ISOLATION_PLAN.md).
      Default approver: this terminal (needs a TTY; it can't verify the user, so
      high-risk sites are always denied).
      --approver phone: approvals on your phone at URL (https). Without --tls-* it
      listens on loopback (default ${DEFAULT_APPROVER_LISTEN.host}:${DEFAULT_APPROVER_LISTEN.port}) behind a TLS proxy such as
      \`tailscale serve\`. With no phone paired yet (or --pair) it prints a one-time
      pairing URL (and, on a terminal, its QR code for the iOS app) to its log and to
      DIR/approver/pairing-url.
      --apns-*: push notifications to the native iOS app through APNs, with your APNs
      auth key (.p8). --apns-sandbox for development builds (xtool dev); --apns-generic
      leaves the site's name out of the notification text Apple relays.
      --high-risk adds a domain that always needs phone approval with user verification.
      --password-source proton-pass: also offer the logins in Proton Pass, read through
      an already logged-in \`pass-cli\` session (only the vault NAME, if given). Each
      login is offered on the registrable domains of its URLs.
      --password-source 1password: the same with 1Password, read through \`op\` as a
      service account: $OP_SERVICE_ACCOUNT_TOKEN must be set (docs/integrations/1password.md).
      Each agent's cookies and site storage are saved (encrypted, DIR/browser-state) and
      restored on the next start; --ephemeral-browser turns that off.
      Key-store passphrase: $KEYFLAP_PASSPHRASE, else prompted (needs a TTY).

  keyflap approver list [--data-dir DIR] [--json]     (needs the daemon stopped)
  keyflap approver remove <id> [--data-dir DIR]       (needs the daemon stopped)
      Phone approvers the signer trusts (passkeys and iOS app keys). Remove a lost
      phone's key here.
  keyflap approver qr [--data-dir DIR]
      Shows the open pairing link as a QR code, for the iOS app to scan.
  keyflap approver pair [--approver-origin URL [--approver-listen HOST:PORT]] [--data-dir DIR]
      Service mode: prints a one-time link to pair a phone. First re-checks the approval
      address; while it is wrong, nothing pairs.
      Dev mode (daemon stopped): with --approver-origin, re-checks the approval address and
      clears a trip. Pairing itself starts with the daemon (keyflap daemon … --pair).

  keyflap agent add <name> [--host claude-code|hermes|codex] [--owner PLATFORM:USER_ID]...
                 [--data-dir DIR] [--mcp-port N]
      Register an agent. Prints its token once, plus the config for that agent host
      (default Claude Code; docs/integrations/{claude-code,hermes,codex}.md).
  keyflap agent list [--data-dir DIR] [--json]
  keyflap agent revoke <id> [--data-dir DIR]

  keyflap password add <site> [--username U] [--totp] [--data-dir DIR]
      Store a password (and TOTP seed) in the signer for <site>'s registrable domain.
      Prompts without echo (or reads stdin lines: password, then TOTP secret or
      otpauth:// URI). Needs the daemon stopped.
  keyflap password list [--data-dir DIR] [--json]
      Native items, plus Proton Pass / 1Password logins the daemon has matched to sites.
  keyflap password remove <id> [--data-dir DIR]      (needs the daemon stopped; native items only)
  keyflap password import <file.csv> [--site S]... [--all] [--expect F] [--data-dir DIR]
      Logins from a password manager's CSV export (Apple Passwords, Google Password
      Manager / Chrome, Firefox, 1Password, Bitwarden). Without --site or --all it only
      lists what the file holds, with a fingerprint; --expect F refuses the file if it
      changed since. Skips logins already stored. Needs the daemon stopped.
  keyflap password-source add <proton-pass|1password> [--vault NAME] [--bin PATH] [--yes]
  keyflap password-source remove
      Service mode (sudo): connect a password manager to the running install, or disconnect
      it. Keyflap uses one at a time; adding a different one replaces the current one after
      you confirm (--yes confirms for a script). Finds pass-cli or op in a root-only place
      (/opt/keyflap/tools/<tool>/, /usr/local/bin, /usr/bin; or --bin), pins it, and asks for
      the token without echo (1Password: the service account token; Proton Pass: a personal
      access token if pass-cli is not logged in). A token on stdin works when there is no
      terminal. Restarts the signer and the core.
  keyflap password-source trust <tool>
      Service mode (sudo): trust a password tool's binary again after it changed (e.g.
      pass-cli after a package update). The signer refuses a changed binary until then.
      Check the new one is genuine first.

  keyflap policy set <site> [--deny | --ask | --ask-strong | --allow-for DUR] [--agent ID]
                 [--session-ttl DUR|off] [--data-dir DIR]
      Per-site rules (section 9). <site> is an origin (https://app.example.com) or a
      domain (example.com: it and its subdomains). Without --agent the rule is for all
      agents. Every matching rule applies and the strictest wins: deny > ask-strong >
      ask > allow-for (shortest). High-risk sites are always ask-strong.
        --deny          never sign in here (the denylist); no prompt, audited
        --ask           approval every time (the default)
        --ask-strong    approval on the phone with user verification, short expiry
        --allow-for DUR after one approval, this agent's sign-ins here need none for
                        DUR (e.g. 30m, max 24h); never on high-risk or ask-strong sites
        --session-ttl DUR  after a broker sign-in, clear the site's cookies and storage
                        in the agent's browser once DUR has passed (off: no TTL)
      Updates an existing rule in place (options not given are kept). Works while the
      daemon runs; it reads rules on every request.
  keyflap policy list [--agent ID] [--json] [--data-dir DIR]
  keyflap policy remove <site> [--agent ID] [--data-dir DIR]

  keyflap status [--json] [--data-dir DIR]
      Agents, credentials, policy rules, the audit chain check and the last entries.
  keyflap audit verify [--data-dir DIR]           (exit 1 if the hash chain is broken)
  keyflap audit tail [--limit N] [--json] [--data-dir DIR]

  keyflap sessions list [--agent ID] [--json] [--data-dir DIR]
      The agents' saved browser sessions: per site, cookie and storage counts, the last
      save and when the session TTL ends it. Never cookie names or values.
  keyflap sessions clear (--agent ID | --all) [--site SITE] [--data-dir DIR]
      End saved and live sessions (one site, or all of them). Dev mode queues it: a running
      daemon applies it within 30 s, else the next start does before restoring anything.
  keyflap sessions keep <site> [--agent ID] [--data-dir DIR]
  keyflap sessions unkeep <site> [--agent ID] [--data-dir DIR]
      "Keep me signed in" for a high-risk site (banks, email, identity providers...), whose
      sessions are otherwise never saved. Without --agent: for every agent.

  keyflap hook claude-code --agent <id> [--data-dir DIR | --service]
      Claude Code UserPromptSubmit hook: forwards the prompt to the intent socket.
      Never writes to stdout and always exits 0. --service: the installed broker's
      socket and your copy of its host token (${SERVICE_PATHS.hookDir}).
  keyflap hook codex --agent <id> [--data-dir DIR | --service]
      Codex CLI UserPromptSubmit hook (docs/integrations/codex.md). Same rules.
  keyflap hook hermes --agent <id> --owner PLATFORM:USER_ID [--owner ...] [--profile NAME]
                     [--data-dir DIR | --service]
      Run by the Hermes keyflap-intent plugin (docs/integrations/hermes.md): records an
      owner's direct message to the Hermes gateway. Same rules.
  keyflap mcp-headers --agent <id> [--data-dir DIR | --service]
      Claude Code MCP headersHelper (written by keyflap setup): prints the agent's
      Authorization header from the token file setup stored. Exit 1 on any problem.

  --data-dir defaults to ~/.keyflap (or ~/.aab, the pre-rename dir, if only that exists).

Service mode (installed with ${MANAGER.installer}; the \`keyflap\` on PATH):
the broker runs as its own users under ${MANAGER.kind}, and admin commands (agent, password,
approver, policy, sessions, status, audit) go to the root-only admin sockets: run them with sudo. \`keyflap daemon\` and
--data-dir are dev-mode only. Details: docs/integrations/service-mode.md.
`;

const dataDirOption: Options = { 'data-dir': { type: 'string' } };

function dataDir(v: string | undefined): string {
  if (v === undefined) return defaultDataDir();
  if (v.length === 0) throw new UsageError('--data-dir must not be empty');
  return resolve(v);
}

export interface DevPairPhone {
  origin: string;
  listen: { host: string; port: number };
}

export function listenAddress(v: string | undefined): { host: string; port: number } {
  if (v === undefined) return { ...DEFAULT_APPROVER_LISTEN };
  const m = /^(\[[0-9a-fA-F:]+\]|[A-Za-z0-9.-]+):(\d{1,5})$/.exec(v);
  const p = Number(m?.[2]);
  if (!m || p > 65535) throw new UsageError(`--approver-listen must be HOST:PORT, got "${v}"`);
  return { host: (m[1] as string).replace(/^\[|\]$/g, ''), port: p };
}

export function approverOrigin(v: string | undefined): string {
  if (!v) throw new UsageError('--approver phone needs --approver-origin URL');
  let url: URL;
  try {
    url = new URL(v);
  } catch {
    throw new UsageError(`--approver-origin is not a URL: "${v}"`);
  }
  const local = url.hostname === 'localhost' || url.hostname.endsWith('.localhost');
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && local)) {
    throw new UsageError('--approver-origin must be https:// (phones need a secure origin)');
  }
  if (url.pathname !== '/' || url.search || url.hash || url.username || url.password) {
    throw new UsageError('--approver-origin must be a bare origin (scheme://host[:port])');
  }
  return url.origin;
}

function port(v: string | undefined, allowZero: boolean): number {
  if (v === undefined) return DEFAULT_MCP_PORT;
  if (!/^\d{1,5}$/.test(v)) throw new UsageError(`--mcp-port must be a port number, got "${v}"`);
  const n = Number(v);
  if (n > 65535 || (n === 0 && !allowZero)) throw new UsageError(`--mcp-port out of range: ${v}`);
  return n;
}

type Options = NonNullable<ParseArgsConfig['options']>;
interface Parsed {
  values: Record<string, string | boolean | (string | boolean)[] | undefined>;
  positionals: string[];
}

function parse(args: string[], options: Options, positionals: number): Parsed {
  let parsed: Parsed;
  try {
    parsed = parseArgs({ args, options, allowPositionals: true, strict: true }) as Parsed;
  } catch (err) {
    throw new UsageError((err as Error).message);
  }
  if (parsed.positionals.length !== positionals) {
    throw new UsageError(
      positionals === 0
        ? `unexpected argument "${parsed.positionals[0]}"`
        : `expected ${positionals} argument(s), got ${parsed.positionals.length}`,
    );
  }
  return parsed;
}

const DURATION_UNITS: Record<string, number> = { s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 };

export function parseDurationArg(v: string, flag: string): number {
  const s = v.trim().toLowerCase();
  if (!/^(\d{1,6}[smhd])+$/.test(s)) {
    throw new UsageError(`--${flag} must be a duration such as 30m, 2h or 1h30m, got "${v}"`);
  }
  let ms = 0;
  for (const m of s.matchAll(/(\d+)([smhd])/g)) {
    ms += Number(m[1]) * (DURATION_UNITS[m[2] as string] as number);
  }
  return ms;
}

function agentOption(v: unknown): string | null {
  if (v === undefined) return null;
  if (typeof v !== 'string' || v.length === 0 || v.length > 128) {
    throw new UsageError('--agent must be an agent id (see keyflap agent list)');
  }
  return v;
}

function parsePolicy(rest: string[]): Command {
  const [sub, ...args] = rest;
  if (sub === 'set') {
    const { values, positionals } = parse(
      args,
      {
        ...dataDirOption,
        agent: { type: 'string' },
        deny: { type: 'boolean' },
        ask: { type: 'boolean' },
        'ask-strong': { type: 'boolean' },
        'allow-for': { type: 'string' },
        'session-ttl': { type: 'string' },
      },
      1,
    );
    const modes = (['deny', 'ask', 'ask-strong', 'allow-for'] as const).filter(
      (m) => values[m] !== undefined,
    );
    if (modes.length > 1) {
      throw new UsageError(
        `give one of --deny, --ask, --ask-strong, --allow-for (got ${modes.length})`,
      );
    }
    const ttl = values['session-ttl'] as string | undefined;
    if (modes.length === 0 && ttl === undefined) {
      throw new UsageError(
        'give a mode (--deny, --ask, --ask-strong, --allow-for DUR) or --session-ttl',
      );
    }
    const allowFor = values['allow-for'] as string | undefined;
    return {
      kind: 'policy-set',
      dataDir: dataDir(values['data-dir'] as string | undefined),
      site: positionals[0] as string,
      agent: agentOption(values.agent),
      mode: modes[0] ?? null,
      allowForMs: allowFor === undefined ? null : parseDurationArg(allowFor, 'allow-for'),
      sessionTtlMs:
        ttl === undefined ? undefined : ttl === 'off' ? null : parseDurationArg(ttl, 'session-ttl'),
    };
  }
  if (sub === 'list') {
    const { values } = parse(
      args,
      { ...dataDirOption, agent: { type: 'string' }, json: { type: 'boolean' } },
      0,
    );
    return {
      kind: 'policy-list',
      dataDir: dataDir(values['data-dir'] as string | undefined),
      agent: agentOption(values.agent),
      json: values.json === true,
    };
  }
  if (sub === 'remove') {
    const { values, positionals } = parse(args, { ...dataDirOption, agent: { type: 'string' } }, 1);
    return {
      kind: 'policy-remove',
      dataDir: dataDir(values['data-dir'] as string | undefined),
      site: positionals[0] as string,
      agent: agentOption(values.agent),
    };
  }
  throw new UsageError(`unknown policy subcommand "${sub ?? ''}" (set, list, remove)`);
}

function parseSessions(rest: string[]): Command {
  const [sub, ...args] = rest;
  if (sub === 'list') {
    const { values } = parse(
      args,
      { ...dataDirOption, agent: { type: 'string' }, json: { type: 'boolean' } },
      0,
    );
    return {
      kind: 'sessions-list',
      dataDir: dataDir(values['data-dir'] as string | undefined),
      agent: agentOption(values.agent),
      json: values.json === true,
    };
  }
  if (sub === 'clear') {
    const { values } = parse(
      args,
      {
        ...dataDirOption,
        agent: { type: 'string' },
        all: { type: 'boolean' },
        site: { type: 'string' },
      },
      0,
    );
    const agent = agentOption(values.agent);
    const all = values.all === true;
    if ((agent === null) === !all) throw new UsageError('give exactly one of --agent ID or --all');
    const site = values.site as string | undefined;
    if (site !== undefined && (site.length === 0 || site.length > 300)) {
      throw new UsageError('--site must be a site such as example.com');
    }
    return {
      kind: 'sessions-clear',
      dataDir: dataDir(values['data-dir'] as string | undefined),
      agent,
      all,
      site: site ?? null,
    };
  }
  if (sub === 'keep' || sub === 'unkeep') {
    const { values, positionals } = parse(args, { ...dataDirOption, agent: { type: 'string' } }, 1);
    return {
      kind: sub === 'keep' ? 'sessions-keep' : 'sessions-unkeep',
      dataDir: dataDir(values['data-dir'] as string | undefined),
      site: positionals[0] as string,
      agent: agentOption(values.agent),
    };
  }
  throw new UsageError(`unknown sessions subcommand "${sub ?? ''}" (list, clear, keep, unkeep)`);
}

function parseAudit(rest: string[]): Command {
  const [sub, ...args] = rest;
  if (sub === 'verify') {
    const { values } = parse(args, dataDirOption, 0);
    return { kind: 'audit-verify', dataDir: dataDir(values['data-dir'] as string | undefined) };
  }
  if (sub === 'tail') {
    const { values } = parse(
      args,
      { ...dataDirOption, limit: { type: 'string' }, json: { type: 'boolean' } },
      0,
    );
    const raw = (values.limit as string | undefined) ?? '20';
    if (!/^\d{1,5}$/.test(raw) || Number(raw) === 0) {
      throw new UsageError(`--limit must be a positive number, got "${raw}"`);
    }
    return {
      kind: 'audit-tail',
      dataDir: dataDir(values['data-dir'] as string | undefined),
      limit: Number(raw),
      json: values.json === true,
    };
  }
  throw new UsageError(`unknown audit subcommand "${sub ?? ''}" (verify, tail)`);
}

export function parseCli(argv: readonly string[]): Command {
  const [cmd, ...rest] = argv;
  if (cmd === undefined || cmd === 'help' || cmd === '--help' || cmd === '-h') {
    return { kind: 'help' };
  }
  if (cmd === 'daemon') {
    const { values } = parse(
      rest,
      {
        ...dataDirOption,
        'mcp-port': { type: 'string' },
        headed: { type: 'boolean' },
        approver: { type: 'string' },
        'approver-origin': { type: 'string' },
        'approver-listen': { type: 'string' },
        'tls-cert': { type: 'string' },
        'tls-key': { type: 'string' },
        pair: { type: 'boolean' },
        'apns-key': { type: 'string' },
        'apns-key-id': { type: 'string' },
        'apns-team-id': { type: 'string' },
        'apns-bundle-id': { type: 'string' },
        'apns-sandbox': { type: 'boolean' },
        'apns-generic': { type: 'boolean' },
        'high-risk': { type: 'string', multiple: true },
        unprotected: { type: 'boolean' },
        'password-source': { type: 'string' },
        'proton-pass-bin': { type: 'string' },
        'proton-pass-vault': { type: 'string' },
        '1password-vault': { type: 'string' },
        'op-bin': { type: 'string' },
        'ephemeral-browser': { type: 'boolean' },
      },
      0,
    );
    if (values.unprotected !== true) {
      throw new UsageError(
        'same-user mode is development only: an agent with shell access as you can read ' +
          "the broker's files, memory and code. Pass --unprotected to run it anyway " +
          '(docs/ISOLATION_PLAN.md)',
      );
    }
    const mode = (values.approver as string | undefined) ?? 'terminal';
    if (mode !== 'terminal' && mode !== 'phone') {
      throw new UsageError(`--approver must be terminal or phone, got "${mode}"`);
    }
    const apnsKeys = ['apns-key', 'apns-key-id', 'apns-team-id', 'apns-bundle-id'];
    const phoneOnly = [
      'approver-origin',
      'approver-listen',
      'tls-cert',
      'tls-key',
      'pair',
      ...apnsKeys,
      'apns-sandbox',
      'apns-generic',
    ];
    if (mode === 'terminal') {
      const stray = phoneOnly.find((k) => values[k] !== undefined);
      if (stray) throw new UsageError(`--${stray} needs --approver phone`);
    }
    const apnsGiven = apnsKeys.filter((k) => values[k] !== undefined);
    if (apnsGiven.length > 0 && apnsGiven.length < apnsKeys.length) {
      const missing = apnsKeys.filter((k) => values[k] === undefined).map((k) => `--${k}`);
      throw new UsageError(`APNs needs ${missing.join(', ')} as well`);
    }
    if (
      apnsGiven.length === 0 &&
      (values['apns-sandbox'] !== undefined || values['apns-generic'] !== undefined)
    ) {
      throw new UsageError(
        '--apns-sandbox / --apns-generic need --apns-key and the other --apns-* options',
      );
    }
    let apns: ApnsCli | null = null;
    if (apnsGiven.length === apnsKeys.length) {
      const keyId = values['apns-key-id'] as string;
      const teamId = values['apns-team-id'] as string;
      const bundleId = values['apns-bundle-id'] as string;
      if (!/^[A-Z0-9]{10}$/.test(keyId))
        throw new UsageError('--apns-key-id must be 10 characters A-Z0-9');
      if (!/^[A-Z0-9]{10}$/.test(teamId))
        throw new UsageError('--apns-team-id must be 10 characters A-Z0-9');
      if (!/^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$/.test(bundleId)) {
        throw new UsageError('--apns-bundle-id must look like com.example.App');
      }
      apns = {
        keyFile: resolve(values['apns-key'] as string),
        keyId,
        teamId,
        bundleId,
        sandbox: values['apns-sandbox'] === true,
        generic: values['apns-generic'] === true,
      };
    }
    const tlsCert = (values['tls-cert'] as string | undefined) ?? null;
    const tlsKey = (values['tls-key'] as string | undefined) ?? null;
    if ((tlsCert === null) !== (tlsKey === null)) {
      throw new UsageError('--tls-cert and --tls-key go together');
    }
    const highRisk = ((values['high-risk'] as string[] | undefined) ?? []).map((d) => {
      const n = d.trim().toLowerCase();
      if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/.test(n)) {
        throw new UsageError(`--high-risk must be a domain, got "${d}"`);
      }
      return n;
    });
    const source = values['password-source'] as string | undefined;
    if (source !== undefined && source !== 'proton-pass' && source !== '1password') {
      throw new UsageError(`--password-source must be proton-pass or 1password, got "${source}"`);
    }
    const sourceFlags: Record<'proton-pass' | '1password', [string, string]> = {
      'proton-pass': ['proton-pass-bin', 'proton-pass-vault'],
      '1password': ['op-bin', '1password-vault'],
    };
    for (const [kind, flags] of Object.entries(sourceFlags)) {
      const given = flags.find((f) => values[f] !== undefined);
      if (given !== undefined && source !== kind) {
        throw new UsageError(`--${given} needs --password-source ${kind}`);
      }
    }
    const [binFlag, vaultFlag] = source === undefined ? ['', ''] : sourceFlags[source];
    const srcBin = source === undefined ? undefined : (values[binFlag] as string | undefined);
    const srcVault = source === undefined ? undefined : (values[vaultFlag] as string | undefined);
    if (srcVault !== undefined && (srcVault.length === 0 || srcVault.length > 200)) {
      throw new UsageError(`--${vaultFlag} must be a vault name`);
    }
    return {
      kind: 'daemon',
      dataDir: dataDir(values['data-dir'] as string | undefined),
      mcpPort: port(values['mcp-port'] as string | undefined, true),
      headed: values.headed === true,
      unprotected: true,
      phone:
        mode === 'phone'
          ? {
              origin: approverOrigin(values['approver-origin'] as string | undefined),
              listen: listenAddress(values['approver-listen'] as string | undefined),
              tlsCert: tlsCert === null ? null : resolve(tlsCert),
              tlsKey: tlsKey === null ? null : resolve(tlsKey),
              pair: values.pair === true,
              apns,
            }
          : null,
      highRisk,
      passwordSource:
        source !== undefined
          ? {
              kind: source,
              bin: srcBin === undefined ? null : resolve(srcBin),
              vault: srcVault ?? null,
            }
          : null,
      ephemeralBrowser: values['ephemeral-browser'] === true,
    };
  }
  if (cmd === 'approver') {
    const [sub, ...args] = rest;
    if (sub === 'pair') {
      const { values } = parse(
        args,
        {
          ...dataDirOption,
          'approver-origin': { type: 'string' },
          'approver-listen': { type: 'string' },
        },
        0,
      );
      const origin = values['approver-origin'] as string | undefined;
      if (origin === undefined && values['approver-listen'] !== undefined) {
        throw new UsageError('--approver-listen needs --approver-origin');
      }
      return {
        kind: 'approver-pair',
        dataDir: dataDir(values['data-dir'] as string | undefined),
        phone:
          origin === undefined
            ? null
            : {
                origin: approverOrigin(origin),
                listen: listenAddress(values['approver-listen'] as string | undefined),
              },
      };
    }
    if (sub === 'list') {
      const { values } = parse(args, { ...dataDirOption, json: { type: 'boolean' } }, 0);
      return {
        kind: 'approver-list',
        dataDir: dataDir(values['data-dir'] as string | undefined),
        json: values.json === true,
      };
    }
    if (sub === 'remove') {
      const { values, positionals } = parse(args, dataDirOption, 1);
      return {
        kind: 'approver-remove',
        dataDir: dataDir(values['data-dir'] as string | undefined),
        id: positionals[0] as string,
      };
    }
    if (sub === 'qr') {
      const { values } = parse(args, dataDirOption, 0);
      return { kind: 'approver-qr', dataDir: dataDir(values['data-dir'] as string | undefined) };
    }
    throw new UsageError(`unknown approver subcommand "${sub ?? ''}" (list, remove, pair, qr)`);
  }
  if (cmd === 'agent') {
    const [sub, ...args] = rest;
    if (sub === 'add') {
      const { values, positionals } = parse(
        args,
        {
          ...dataDirOption,
          'mcp-port': { type: 'string' },
          host: { type: 'string' },
          owner: { type: 'string', multiple: true },
        },
        1,
      );
      const owners = values.owner as string[] | undefined;
      if (owners !== undefined) {
        if (values.host !== 'hermes') throw new UsageError('--owner needs --host hermes');
        for (const o of owners) {
          try {
            parseOwner(o);
          } catch (err) {
            throw new UsageError((err as Error).message);
          }
        }
      }
      return {
        kind: 'agent-add',
        dataDir: dataDir(values['data-dir'] as string | undefined),
        name: positionals[0] as string,
        mcpPort: port(values['mcp-port'] as string | undefined, false),
        ...(values.host !== undefined ? { host: agentHost(values.host) } : {}),
        ...(owners !== undefined ? { owners } : {}),
      };
    }
    if (sub === 'list') {
      const { values } = parse(args, { ...dataDirOption, json: { type: 'boolean' } }, 0);
      return {
        kind: 'agent-list',
        dataDir: dataDir(values['data-dir'] as string | undefined),
        json: values.json === true,
      };
    }
    if (sub === 'revoke') {
      const { values, positionals } = parse(args, dataDirOption, 1);
      return {
        kind: 'agent-revoke',
        dataDir: dataDir(values['data-dir'] as string | undefined),
        id: positionals[0] as string,
      };
    }
    throw new UsageError(`unknown agent subcommand "${sub ?? ''}" (add, list, revoke)`);
  }
  if (cmd === 'password') {
    const [sub, ...args] = rest;
    if (sub === 'add') {
      const { values, positionals } = parse(
        args,
        { ...dataDirOption, username: { type: 'string' }, totp: { type: 'boolean' } },
        1,
      );
      const username = values.username as string | undefined;
      if (username !== undefined && username.length === 0) {
        throw new UsageError('--username must not be empty');
      }
      return {
        kind: 'password-add',
        dataDir: dataDir(values['data-dir'] as string | undefined),
        site: positionals[0] as string,
        username: username ?? null,
        totp: values.totp === true,
      };
    }
    if (sub === 'list') {
      const { values } = parse(args, { ...dataDirOption, json: { type: 'boolean' } }, 0);
      return {
        kind: 'password-list',
        dataDir: dataDir(values['data-dir'] as string | undefined),
        json: values.json === true,
      };
    }
    if (sub === 'remove') {
      const { values, positionals } = parse(args, dataDirOption, 1);
      return {
        kind: 'password-remove',
        dataDir: dataDir(values['data-dir'] as string | undefined),
        id: positionals[0] as string,
      };
    }
    if (sub === 'import') {
      const { values, positionals } = parse(
        args,
        {
          ...dataDirOption,
          site: { type: 'string', multiple: true },
          all: { type: 'boolean' },
          expect: { type: 'string' },
        },
        1,
      );
      const sites = (values.site as string[] | undefined) ?? [];
      if (values.all === true && sites.length > 0) {
        throw new UsageError('use --site or --all, not both');
      }
      const expect = (values.expect as string | undefined) ?? null;
      if (expect !== null && !/^[0-9a-fA-F]{16}$/.test(expect)) {
        throw new UsageError('--expect takes the 16-character fingerprint the preview prints');
      }
      return {
        kind: 'password-import',
        dataDir: dataDir(values['data-dir'] as string | undefined),
        file: positionals[0] as string,
        sites,
        all: values.all === true,
        expect,
      };
    }
    throw new UsageError(`unknown password subcommand "${sub ?? ''}" (add, list, remove, import)`);
  }
  if (cmd === 'password-source') {
    const [sub, ...args] = rest;
    if (sub === 'trust') {
      const { positionals } = parse(args, {}, 1);
      return { kind: 'password-source-trust', tool: positionals[0] as string };
    }
    if (sub === 'add') {
      const { values, positionals } = parse(
        args,
        { vault: { type: 'string' }, bin: { type: 'string' }, yes: { type: 'boolean' } },
        1,
      );
      const source = positionals[0] as string;
      if (source !== 'proton-pass' && source !== '1password') {
        throw new UsageError(`password-source add takes proton-pass or 1password, got "${source}"`);
      }
      const vault = values.vault as string | undefined;
      if (vault !== undefined && (vault.length === 0 || vault.length > 200)) {
        throw new UsageError('--vault must be a vault name');
      }
      const bin = values.bin as string | undefined;
      if (bin !== undefined && !bin.startsWith('/')) {
        throw new UsageError('--bin must be an absolute path');
      }
      return { kind: 'password-source-add', source, vault, bin, yes: values.yes === true };
    }
    if (sub === 'remove') {
      parse(args, {}, 0);
      return { kind: 'password-source-remove' };
    }
    throw new UsageError(`unknown password-source subcommand "${sub ?? ''}" (add, remove, trust)`);
  }
  if (cmd === 'policy') return parsePolicy(rest);
  if (cmd === 'audit') return parseAudit(rest);
  if (cmd === 'sessions') return parseSessions(rest);
  if (cmd === 'status') {
    const { values } = parse(rest, { ...dataDirOption, json: { type: 'boolean' } }, 0);
    return {
      kind: 'status',
      dataDir: dataDir(values['data-dir'] as string | undefined),
      json: values.json === true,
    };
  }
  if (cmd === 'setup') {
    const { values } = parse(
      rest,
      {
        ...dataDirOption,
        'mcp-port': { type: 'string' },
        unprotected: { type: 'boolean' },
        host: { type: 'string' },
      },
      0,
    );
    return {
      kind: 'setup',
      dataDir: dataDir(values['data-dir'] as string | undefined),
      mcpPort: port(values['mcp-port'] as string | undefined, false),
      unprotected: values.unprotected === true,
      ...(values.host !== undefined ? { host: agentHost(values.host) } : {}),
    };
  }
  if (cmd === 'doctor') {
    const { values } = parse(
      rest,
      { ...dataDirOption, json: { type: 'boolean' }, project: { type: 'string' } },
      0,
    );
    const project = values.project as string | undefined;
    if (project !== undefined && project.length === 0) {
      throw new UsageError('--project must not be empty');
    }
    return {
      kind: 'doctor',
      dataDir: dataDir(values['data-dir'] as string | undefined),
      json: values.json === true,
      project: project === undefined ? null : resolve(project),
    };
  }
  if (cmd === 'mcp-headers') {
    const { values } = parse(
      rest,
      { ...dataDirOption, agent: { type: 'string' }, service: { type: 'boolean' } },
      0,
    );
    const agentId = values.agent as string | undefined;
    if (!agentId) throw new UsageError('--agent <id> is required');
    if (values.service === true && values['data-dir'] !== undefined) {
      throw new UsageError('--service and --data-dir are exclusive');
    }
    return {
      kind: 'mcp-headers',
      dataDir: dataDir(values['data-dir'] as string | undefined),
      agentId,
      service: values.service === true,
    };
  }
  if (cmd === 'hook') {
    const [host, ...args] = rest;
    if (host !== 'claude-code' && host !== 'hermes' && host !== 'codex') {
      throw new UsageError(`unknown hook host "${host ?? ''}" (claude-code, hermes, codex)`);
    }
    const { values } = parse(
      args,
      {
        ...dataDirOption,
        agent: { type: 'string' },
        service: { type: 'boolean' },
        ...(host === 'hermes'
          ? { owner: { type: 'string', multiple: true }, profile: { type: 'string' } }
          : {}),
      },
      0,
    );
    const agentId = values.agent as string | undefined;
    if (!agentId) throw new UsageError('--agent <id> is required');
    if (values.service === true && values['data-dir'] !== undefined) {
      throw new UsageError('--service and --data-dir are exclusive');
    }
    const common = {
      dataDir: dataDir(values['data-dir'] as string | undefined),
      agentId,
      service: values.service === true,
    };
    if (host === 'claude-code') return { kind: 'hook-claude-code', ...common };
    if (host === 'codex') return { kind: 'hook-codex', ...common };
    const raw = (values.owner as string[] | undefined) ?? [];
    if (raw.length === 0) {
      throw new UsageError('hook hermes needs at least one --owner <platform>:<user id>');
    }
    let owners: HermesOwner[];
    try {
      owners = raw.map(parseOwner);
    } catch (err) {
      throw new UsageError((err as Error).message);
    }
    const profile = values.profile as string | undefined;
    if (profile !== undefined && !/^[A-Za-z0-9_.-]{1,64}$/.test(profile)) {
      throw new UsageError('--profile must be a Hermes profile name');
    }
    return { kind: 'hook-hermes', ...common, owners, profile: profile ?? null };
  }
  throw new UsageError(`unknown command "${cmd}"`);
}
