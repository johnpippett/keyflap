import { dirname, join } from 'node:path';
import type { QrCode, TermStyle } from '@aab/approver';
import { type AgentHost, approverOrigin, listenAddress, UsageError } from '../args.ts';
import type { DoctorReport } from '../doctor.ts';
import { formatReport, MIN_NODE_TEXT, nodeIsSupported } from '../doctor.ts';
import { devAgentTokenPath, serviceAgentTokenPath } from '../mcp-headers.ts';
import {
  requireServiceManager,
  SERVICE_NAMES,
  type ServiceName,
  serviceManager,
} from '../service/manager.ts';
import {
  opVaults,
  PasswordSourceError,
  protonLogin,
  protonVaults,
  type SourceKind,
  type ToolRun,
} from '../service/password-source.ts';
import type { ServicePaths } from '../service/paths.ts';
import {
  FULL_INSTALL_COMMAND,
  launchAgentLoaded,
  launchAgentPlist,
  PROTECTS_LESS,
  type SimpleInstall,
  startLaunchAgent,
  stopLaunchAgent,
} from '../simple-install.ts';
import type { Backend, PairResult } from './backend.ts';
import {
  ConfigShapeError,
  type Json,
  jsonDiff,
  type KeyflapClaudeConfig,
  mcpEntry,
  mergeMcp,
  mergeSettings,
  parseJsonFile,
  SERVER_NAME,
  stringify,
} from './claude-config.ts';
import { configureOtherHost, detectHosts, type OtherHost } from './hosts.ts';
import { importExport } from './import-step.ts';
import { connectPasswordSource } from './password-source-flow.ts';
import { choose, confirm, type Prompter } from './prompt.ts';
import { type ApproverChoice, daemonCommand, type SetupState, saveState } from './state.ts';
import type { FileOwner, System } from './system.ts';
import {
  APPROVER_PORT,
  parseTailscaleStatus,
  serveArgs,
  serveState,
  tailscaleCli,
  tailscaleOrigin,
} from './tailscale.ts';
import type { SetupUi } from './ui.ts';
import { lookupUser } from './users.ts';

export interface SetupContext {
  sys: System;
  prompt: Prompter;
  out: (text: string) => void;
  ui: SetupUi;
  style?: TermStyle;
  backend: Backend;
  state: SetupState;
  dataDir: string;
  defaults: { dataDir: string; mcpPort: number };
  paths: ServicePaths | null;
  simple?: SimpleInstall | null;
  qr: (url: string) => { code: QrCode; printed: string };
  pairingTimeoutMs: number;
  chromium: () => { path: string; present: boolean };
  doctor: () => Promise<DoctorReport>;
  secretEnv?: Record<string, string>;
  startDaemon: ((state: SetupState) => Promise<void>) | null;
  daemonStop?: (what: string) => Promise<boolean>;
  host?: AgentHost | null;
  interruptible: <T>(fn: (signal: AbortSignal) => Promise<T>) => Promise<T>;
}

export type StepResult = 'done' | 'skipped' | 'daemon-running';

const quote = (a: string) =>
  /^[A-Za-z0-9_@%+=:,./-]+$/.test(a) ? a : `'${a.replaceAll("'", `'\\''`)}'`;
export const commandLine = (argv: string[]) => argv.map(quote).join(' ');

function save(ctx: SetupContext): void {
  saveState(ctx.sys, ctx.backend.stateDir, ctx.state, ctx.backend.fileOwner);
}

async function offerCommand(
  ctx: SetupContext,
  why: string,
  argv: string[],
  opts: {
    def?: boolean;
    env?: Record<string, string>;
    uid?: number;
    gid?: number;
    cwd?: string;
  } = {},
): Promise<boolean | null> {
  ctx.ui.brief(why, `${why}\n  $ ${commandLine(argv)}\n`);
  if (!(await confirm(ctx.prompt, 'Run it?', opts.def ?? false))) return null;
  const r = await ctx.ui.wait('Running it', () =>
    ctx.sys.exec(argv[0] as string, argv.slice(1), {
      timeoutMs: 60_000,
      ...(opts.env ? { env: opts.env } : {}),
      ...(opts.uid !== undefined ? { uid: opts.uid, gid: opts.gid } : {}),
      ...(opts.cwd ? { cwd: opts.cwd } : {}),
    }),
  );
  if (r.code === 0) return true;
  const msg = (r.stderr || r.stdout || r.error || '').trim().split('\n').slice(0, 3).join(' / ');
  ctx.out(`  failed (exit ${r.code ?? r.error}): ${msg}\n`);
  return false;
}

export async function preflight(ctx: SetupContext): Promise<StepResult> {
  await ctx.ui.step(1, 'Preflight');
  const v = process.versions.node;
  if (!nodeIsSupported(v)) {
    throw new Error(
      `Node ${v} is too old or unsupported: Keyflap needs Node ${MIN_NODE_TEXT} or newer on that line`,
    );
  }
  ctx.out(`  ✓ Node ${v}\n`);
  const c = ctx.chromium();
  if (ctx.simple) {
    if (ctx.sys.exists(ctx.simple.browsers)) {
      ctx.ui.brief('✓ Chromium', `  ✓ Chromium (headless) in ${ctx.simple.browsers}\n`);
    } else {
      ctx.out(`  ✗ No browser in ${ctx.simple.browsers}: run the simple install again\n`);
    }
  } else if (ctx.backend.kind === 'dev') {
    if (c.present) ctx.ui.brief('✓ Chromium', `  ✓ Chromium ${c.path}\n`);
    else {
      ctx.out(
        '  ✗ Chromium missing: run `pnpm --filter @aab/shim exec playwright install chromium`\n',
      );
    }
  }
  if (ctx.backend.kind === 'service') {
    const m = requireServiceManager(ctx.sys.platform);
    const down: ServiceName[] = [];
    await ctx.ui.wait('Checking the Keyflap services', async () => {
      for (const u of SERVICE_NAMES) {
        if (!(await m.active(ctx.sys, u)).active) down.push(u);
      }
    });
    if (down.length > 0) {
      throw new Error(
        `${down.map(m.unit).join(', ')} not active: ${m.statusCommand(down, true)} (and ${m.logsCommand('core')})`,
      );
    }
    ctx.ui.brief(
      '✓ Keyflap is running: signer, core and approver',
      `  ✓ Service mode: ${SERVICE_NAMES.map(m.unit).join(', ')} active\n`,
    );
    ctx.ui.brief(
      `✓ Setting up Claude Code for ${ctx.backend.user.name}`,
      `  ✓ Claude Code user: ${ctx.backend.user.name} (owner of ${ctx.paths?.hookDir})\n`,
    );
    const sudoUid = Number(ctx.sys.env.SUDO_UID);
    if (Number.isInteger(sudoUid) && sudoUid !== ctx.backend.user.uid) {
      const who = (await lookupUser(ctx.sys, { uid: sudoUid }))?.name ?? String(sudoUid);
      ctx.out(
        `  ! You ran sudo as ${who}, but the broker was installed for ${ctx.backend.user.name}: setup configures ${ctx.backend.user.name}'s Claude Code.\n`,
      );
    }
    return 'done';
  }
  const installedManager = serviceManager(ctx.sys.platform);
  if (installedManager && (await installedManager.installed(ctx.sys))) {
    ctx.out(
      `  ! Service mode is installed on this machine. You probably want \`sudo keyflap setup\` instead;\n` +
        `    this run configures a separate same-user ${ctx.simple ? 'broker (the simple install)' : 'dev broker'}.\n`,
    );
  }
  const d = ctx.sys.stat(ctx.dataDir);
  if (!d) {
    ctx.sys.mkdirUser(ctx.dataDir, 0o700, ctx.backend.fileOwner);
    ctx.out(`  ✓ Data dir ${ctx.dataDir} (created, 0700)\n`);
  } else {
    ctx.out(`  ✓ Data dir ${ctx.dataDir}${(d.mode & 0o077) !== 0 ? ' (! not 0700)' : ''}\n`);
  }
  const running = await ctx.backend.daemonRunning();
  ctx.ui.brief(
    running
      ? '✓ The daemon is running (setup asks you to stop it when needed)'
      : '✓ The daemon is not running',
    running
      ? '  ✓ The daemon is running. Pairing and passwords need it stopped (setup will ask).\n'
      : '  ✓ The daemon is not running (good: setup needs the key store for pairing and passwords).\n',
  );
  return 'done';
}

interface TailscaleOffer {
  origin: string;
}

async function confirmRoute(ctx: SetupContext, origin: string): Promise<void> {
  const r = await ctx.ui.wait('Checking that it answers', () =>
    ctx.sys.http(`${origin}/`, { timeoutMs: 5_000 }),
  );
  if (r.status !== null && r.status < 500) {
    ctx.ui.brief(
      `✓ Your phone can now reach ${origin}`,
      `  ✓ Your phone can now reach ${origin}\n`,
    );
  } else if (ctx.backend.kind === 'service') {
    ctx.out(`  ! ${origin} does not answer yet (${r.error ?? `HTTP ${r.status}`}).\n`);
  } else {
    ctx.ui.brief(
      `✓ Tailscale now forwards ${origin} to this computer`,
      `  ✓ Tailscale now forwards ${origin} to this computer; it answers once Keyflap starts.\n`,
    );
  }
}

async function tailscaleRoute(
  ctx: SetupContext,
  wanted: string | null,
): Promise<TailscaleOffer | null> {
  const cli = tailscaleCli(ctx.sys, ctx.backend.kind === 'service');
  if (!cli) {
    ctx.ui.brief(
      'Tailscale is not installed.',
      '  Tailscale: not installed (it is the easy way to get an HTTPS origin: tailscale.com).\n',
    );
    return null;
  }
  const as = cli.asUser ? { uid: ctx.backend.user.uid, gid: ctx.backend.user.gid } : {};
  const st = await ctx.ui.wait('Asking Tailscale', () =>
    ctx.sys.exec(cli.path, ['status', '--json'], { timeoutMs: 10_000, ...as }),
  );
  const info = parseTailscaleStatus(st.code === 0 ? st.stdout : '');
  if (st.code !== 0 && !info.problem) info.problem = 'tailscale status failed';
  if (info.problem || !info.dnsName) {
    ctx.out(`  Tailscale: ${info.problem ?? 'no MagicDNS name'}.\n`);
    return null;
  }
  const origin = tailscaleOrigin(info.dnsName);
  if (wanted !== null && wanted !== origin) return null;
  ctx.ui.brief(
    `✓ Tailscale is running as ${info.dnsName}`,
    `  Tailscale: running as ${info.dnsName}, HTTPS certificates enabled.\n`,
  );
  const ss = await ctx.ui.wait('Asking Tailscale', () =>
    ctx.sys.exec(cli.path, ['serve', 'status', '--json'], {
      timeoutMs: 10_000,
      ...as,
    }),
  );
  const state = serveState(ss.code === 0 ? ss.stdout : '{}', info.dnsName);
  if (state === 'served') {
    ctx.ui.brief(
      `✓ Tailscale already serves ${origin}`,
      `  ✓ tailscale serve already forwards ${origin} to 127.0.0.1:${APPROVER_PORT}.\n`,
    );
    return { origin };
  }
  if (state === 'conflict') {
    ctx.out(
      `  ! Port ${APPROVER_PORT} is already served by tailscale to something else (tailscale serve status).\n`,
    );
    return (await confirm(ctx.prompt, `Use ${origin} anyway?`, false)) ? { origin } : null;
  }
  const ran = await offerCommand(
    ctx,
    `  The phone approver listens on 127.0.0.1:${APPROVER_PORT}; tailscale serve gives it a real certificate at ${origin}:`,
    [cli.path, ...serveArgs()],
    { def: true, ...as },
  );
  if (ran === true) await confirmRoute(ctx, origin);
  if (ran === null) {
    ctx.ui.brief(
      'Not run. You can run it later; the address stays the same.',
      '  Not run. You can run it yourself later; the origin stays the same.\n',
    );
  }
  return { origin };
}

type PhoneChoice = Extract<ApproverChoice, { kind: 'phone' }>;

async function manualOrigin(ctx: SetupContext): Promise<PhoneChoice> {
  ctx.ui.brief(
    'Give an HTTPS address your phone can reach, with a real hostname and certificate.',
    '  Give an HTTPS origin your phone can reach that points at this machine (a real hostname and\n' +
      '  certificate: a LAN IP or a self-signed certificate will not work for passkeys).\n',
  );
  let origin = '';
  for (;;) {
    const v = (await ctx.prompt.ask('Approver origin (https://host:port)')).trim();
    try {
      origin = approverOrigin(v);
      break;
    } catch (err) {
      ctx.out(`  ${err instanceof UsageError ? err.message : 'not an origin'}\n`);
    }
  }
  const local = /^http:\/\//.test(origin);
  let tlsCert: string | null = null;
  let tlsKey: string | null = null;
  if (
    !local &&
    (await confirm(
      ctx.prompt,
      'Does the approver serve TLS itself, with your certificate and key?',
      false,
    ))
  ) {
    for (;;) {
      tlsCert = (await ctx.prompt.ask('Certificate file (PEM)')).trim();
      tlsKey = (await ctx.prompt.ask('Key file (PEM)')).trim();
      if (ctx.sys.exists(tlsCert) && ctx.sys.exists(tlsKey)) break;
      ctx.out('  One of those files does not exist.\n');
    }
  }
  const port = Number(new URL(origin).port) || (local ? 80 : 443);
  const defListen = tlsCert ? `0.0.0.0:${port}` : `127.0.0.1:${APPROVER_PORT}`;
  ctx.out(
    tlsCert
      ? '  The approver listens on this address with your certificate.\n'
      : '  Without a certificate the approver listens on loopback only, behind your TLS proxy.\n',
  );
  let listen = { host: '127.0.0.1', port: APPROVER_PORT };
  for (;;) {
    try {
      listen = listenAddress((await ctx.prompt.ask('Listen address', defListen)).trim());
      break;
    } catch (err) {
      ctx.out(`  ${(err as Error).message}\n`);
    }
  }
  return { kind: 'phone', origin, listen, tlsCert, tlsKey, via: tlsCert ? 'own-tls' : 'proxy' };
}

export async function approverStep(ctx: SetupContext): Promise<StepResult> {
  await ctx.ui.step(2, 'Approval address');
  if (ctx.backend.kind === 'service') return serviceOrigin(ctx);
  const cur = ctx.state.approver;
  if (cur) {
    ctx.out(
      cur.kind === 'phone'
        ? `  Current: phone approvals at ${cur.origin} (listening on ${cur.listen.host}:${cur.listen.port}).\n`
        : '  Current: approvals in the daemon terminal (dev only, no user verification).\n',
    );
    if (await confirm(ctx.prompt, 'Keep it?', true)) {
      if (cur.kind === 'phone' && cur.via === 'tailscale') await tailscaleRoute(ctx, cur.origin);
      return 'skipped';
    }
  }
  const kind = ctx.simple
    ? 'phone'
    : await choose(
        ctx.prompt,
        'Where do you approve sign-ins?',
        [
          ['phone', 'On your phone, with Face ID / fingerprint / device PIN (recommended)'],
          [
            'terminal',
            'In the daemon terminal (dev only: no user verification, high-risk sites denied)',
          ],
        ],
        'phone',
        ctx.out,
      );
  if (kind === 'terminal') {
    ctx.state.approver = { kind: 'terminal' };
    save(ctx);
    return 'done';
  }
  const ts = await tailscaleRoute(ctx, null);
  let choice: PhoneChoice;
  if (ts && (await confirm(ctx.prompt, `Use ${ts.origin} as the approver origin?`, true))) {
    choice = {
      kind: 'phone',
      origin: ts.origin,
      listen: { host: '127.0.0.1', port: APPROVER_PORT },
      tlsCert: null,
      tlsKey: null,
      via: 'tailscale',
    };
  } else {
    choice = await manualOrigin(ctx);
  }
  ctx.state.approver = choice;
  save(ctx);
  ctx.out(`  ✓ Approver origin: ${choice.origin}\n`);
  return 'done';
}

async function serviceOrigin(ctx: SetupContext): Promise<StepResult> {
  const paths = ctx.paths as ServicePaths;
  const cfg = parseJsonFile(ctx.sys.readFile(paths.approverConfig));
  const origin =
    cfg && typeof cfg === 'object' && !Array.isArray(cfg) && typeof cfg.origin === 'string'
      ? cfg.origin
      : null;
  if (!origin) throw new Error(`no approver origin in ${paths.approverConfig}: re-run install.sh`);
  ctx.ui.brief(
    `Your phone approves sign-ins at\n  ${origin}`,
    `  Approver origin (set at install time): ${origin}\n`,
  );
  const r = await ctx.ui.wait('Checking that it answers', () =>
    ctx.sys.http(`${origin}/`, { timeoutMs: 5_000 }),
  );
  if (r.status !== null && r.status < 500) {
    ctx.out('  ✓ It answers over HTTPS from this machine, with a valid certificate.\n');
    return 'done';
  }
  ctx.out(
    `  ✗ Not reachable from this machine (${r.tlsError ? `certificate problem: ${r.error}` : (r.error ?? `HTTP ${r.status}`)}).\n`,
  );
  if (/\.ts\.net$/.test(new URL(origin).hostname)) await tailscaleRoute(ctx, origin);
  else ctx.out('  Check the TLS proxy (or --tls-cert listener) in front of the approver.\n');
  return 'done';
}

export async function waitForDaemonStopped(ctx: SetupContext, what: string): Promise<boolean> {
  if (ctx.backend.kind !== 'dev') return true;
  if (ctx.daemonStop) return ctx.daemonStop(what);
  if (ctx.simple && (await launchAgentLoaded(ctx.sys))) {
    ctx.out(
      `  Keyflap is running in the background and holds the key store; ${what} needs it stopped.\n`,
    );
    if (!(await confirm(ctx.prompt, 'Stop it now? Setup starts it again at the end', true))) {
      return false;
    }
    await stopLaunchAgent(ctx.sys);
    ctx.out('  ✓ Stopped.\n');
  }
  while (await ctx.backend.daemonRunning()) {
    ctx.out(`  The daemon is running and holds the key store; ${what} needs it stopped.\n`);
    const a = (
      await ctx.prompt.ask('Stop it (Ctrl-C in its terminal), then press Enter, or type skip')
    ).trim();
    if (a.toLowerCase() === 'skip') return false;
  }
  return true;
}

export async function pairStep(ctx: SetupContext): Promise<StepResult> {
  await ctx.ui.step(3, 'Pair your phone');
  let origin: string;
  let listen = { host: '127.0.0.1', port: APPROVER_PORT };
  let tls: { cert: string; key: string } | null = null;
  if (ctx.backend.kind === 'dev') {
    const a = ctx.state.approver;
    if (a?.kind !== 'phone') {
      ctx.out('  No phone approver configured: nothing to pair.\n');
      return 'skipped';
    }
    origin = a.origin;
    listen = a.listen;
    tls = a.tlsCert && a.tlsKey ? { cert: a.tlsCert, key: a.tlsKey } : null;
    if (!(await waitForDaemonStopped(ctx, 'pairing'))) return 'skipped';
  } else {
    const cfg = parseJsonFile(ctx.sys.readFile((ctx.paths as ServicePaths).approverConfig));
    origin = (cfg as { origin?: string } | null)?.origin ?? '';
  }
  const n = await ctx.backend.phonesPaired(ctx.backend.kind === 'dev' ? origin : null);
  if (n !== null && n > 0) {
    ctx.ui.brief(
      n === 1 ? '✓ A phone is paired.' : `✓ ${n} phones are paired.`,
      `  ✓ ${n} phone(s) paired.\n`,
    );
    if (
      !(await confirm(
        ctx.prompt,
        'Pair another phone (an already-paired phone must approve it)?',
        false,
      ))
    ) {
      return 'skipped';
    }
  } else if (!(await confirm(ctx.prompt, 'Pair a phone now?', true))) {
    return 'skipped';
  }
  const minutes = Math.round(ctx.pairingTimeoutMs / 60_000);
  await ctx.ui.page('Scan the code');
  const result: PairResult = await ctx.interruptible((signal) =>
    ctx.backend.pair({
      origin,
      listen,
      tls,
      timeoutMs: ctx.pairingTimeoutMs,
      signal,
      onOpen: async (url) => {
        const qr = ctx.qr(url);
        ctx.ui.brief(
          {
            qr: qr.code,
            printed: qr.printed,
            beside: [
              "Point your phone's camera at the code, open the link and tap Pair this phone.",
              '',
              `One use, valid ${minutes} minutes. Treat it like a password: never paste it into an agent session.`,
              '',
              'iPhone: pair in Safari first, then Share > Add to Home Screen.',
              '',
              'Tab shows the link. Ctrl-C stops waiting.',
            ].join('\n'),
          },
          [
            '',
            `  Open this one-time link on your phone (valid ${minutes} minutes, single use) and tap`,
            '  "Pair this phone". Whoever opens it first becomes an approver: treat it like a',
            '  password, and never paste it into an agent session.',
            '',
            `    ${url}`,
            '',
            qr.printed,
            '',
            '  On an iPhone, point the camera at the code to open it in Safari. Pair there first,',
            '  then Share > Add to Home Screen: iOS copies the pairing into the home-screen app',
            '  only when you add it.',
            '',
          ].join('\n'),
          { log: false },
        );
        if (ctx.backend.kind === 'dev') {
          const r = await ctx.ui.wait('Checking the address answers', () =>
            ctx.sys.http(`${origin}/`, { timeoutMs: 5_000 }),
          );
          ctx.out(
            r.status !== null && r.status < 500
              ? `  ✓ ${origin} answers from this machine.\n`
              : `  ! ${origin} does not answer from this machine (${r.tlsError ? `certificate: ${r.error}` : (r.error ?? r.status)}); your phone may not reach it either.\n`,
          );
        }
        ctx.ui.brief('', '  Waiting for your phone… (Ctrl-C to stop waiting)\n', { log: false });
        ctx.ui.status('Waiting for your phone');
      },
    }),
  );
  ctx.ui.status(null);
  await ctx.ui.page(result === 'paired' ? 'Paired' : 'Not paired', 'replace');
  if (result === 'paired') {
    ctx.out('  ✓ Phone paired. Tap "Notify me about new requests" on it for push notifications.\n');
    return 'done';
  }
  const again = ctx.backend.kind === 'service' ? 'sudo keyflap setup' : 'keyflap setup';
  ctx.out(
    result === 'timeout'
      ? `  ✗ Not paired within ${minutes} minutes. Run ${again} again for a new link.\n`
      : `  Stopped waiting; the link no longer works. Run ${again} again to pair.\n`,
  );
  return 'skipped';
}

export type ClaudeAction =
  | {
      kind: 'file';
      path: string;
      before: string | null;
      after: string;
      diff: string[];
      notes: string[];
    }
  | { kind: 'command'; argv: string[]; cwd: string; describe: string; mayFail?: boolean };

export interface ClaudePlanInput {
  sys: System;
  scope: 'project' | 'user';
  project: string;
  home: string;
  cfg: KeyflapClaudeConfig;
  claudeCli: string | null;
  cliHasEntry: boolean;
  owner: FileOwner;
}

function fileAction(
  sys: System,
  path: string,
  owner: FileOwner,
  merge: (doc: Json | undefined) => { doc: Json; notes: string[] },
): ClaudeAction {
  const text = sys.readUserFile(path, owner);
  const parsed = parseJsonFile(text);
  if (parsed === null) {
    throw new ConfigShapeError(`${path} is not plain JSON (comments?); merge it by hand`);
  }
  const { doc, notes } = merge(parsed);
  return {
    kind: 'file',
    path,
    before: text,
    after: stringify(doc),
    diff: jsonDiff(parsed, doc as { [k: string]: Json }),
    notes,
  };
}

export function planClaudeConfig(i: ClaudePlanInput): ClaudeAction[] {
  const actions: ClaudeAction[] = [];
  const entry = mcpEntry(i.cfg);
  if (i.claudeCli) {
    const scope = i.scope === 'project' ? 'local' : 'user';
    if (i.cliHasEntry) {
      actions.push({
        kind: 'command',
        argv: [i.claudeCli, 'mcp', 'remove', SERVER_NAME, '-s', scope],
        cwd: i.project,
        describe: `remove the existing "${SERVER_NAME}" MCP server (${scope} scope), to replace it`,
        mayFail: true,
      });
    }
    actions.push({
      kind: 'command',
      argv: [i.claudeCli, 'mcp', 'add-json', SERVER_NAME, JSON.stringify(entry), '-s', scope],
      cwd: i.project,
      describe:
        scope === 'local'
          ? `add the MCP server for this project, private to you (~/.claude.json, project ${i.project})`
          : 'add the MCP server for all your projects (~/.claude.json)',
    });
  } else if (i.scope === 'project') {
    actions.push(
      fileAction(i.sys, join(i.project, '.mcp.json'), i.owner, (d) => mergeMcp(d, entry)),
    );
  } else {
    actions.push(
      fileAction(i.sys, join(i.home, '.claude.json'), i.owner, (d) => mergeMcp(d, entry)),
    );
  }
  const settings =
    i.scope === 'project'
      ? join(i.project, '.claude', 'settings.local.json')
      : join(i.home, '.claude', 'settings.json');
  actions.push(fileAction(i.sys, settings, i.owner, (d) => mergeSettings(d, i.cfg)));
  return actions;
}

export function describePlan(actions: ClaudeAction[], stamp: string): string {
  const lines: string[] = [];
  for (const a of actions) {
    if (a.kind === 'command') {
      lines.push(`  • ${a.describe}:`, `      $ ${commandLine(a.argv)}`);
      continue;
    }
    if (a.diff.length === 0) {
      lines.push(`  • ${a.path}: already up to date`);
      continue;
    }
    lines.push(
      `  • ${a.path}: ${a.before === null ? 'new file' : `modified (backup: ${a.path}.keyflap-backup-${stamp})`}`,
    );
    for (const n of a.notes) lines.push(`      note: ${n}`);
    for (const d of a.diff) lines.push(`      ${d}`);
  }
  return `${lines.join('\n')}\n`;
}

export function backupStamp(now: number): string {
  return new Date(now)
    .toISOString()
    .replace(/[-:]/g, '')
    .replace(/\.\d+Z$/, 'Z');
}

export async function applyPlan(
  sys: System,
  actions: ClaudeAction[],
  o: { stamp: string; owner: FileOwner; out: (t: string) => void },
): Promise<boolean> {
  let ok = true;
  for (const a of actions) {
    if (a.kind === 'file') {
      if (a.diff.length === 0) continue;
      try {
        const now = sys.readUserFile(a.path, o.owner);
        if (now !== a.before) {
          o.out(`  ✗ ${a.path} changed since the preview; not written. Re-run keyflap setup.\n`);
          ok = false;
          continue;
        }
        sys.mkdirUser(dirname(a.path), 0o755, o.owner);
        let mode = 0o644;
        if (a.before !== null) {
          mode = (sys.userFileMode(a.path, o.owner) ?? mode) & 0o777;
          sys.writeUserFile(`${a.path}.keyflap-backup-${o.stamp}`, a.before, mode, o.owner, {
            exclusive: true,
          });
        }
        sys.writeUserFile(a.path, a.after, mode, o.owner);
      } catch (err) {
        ok = false;
        o.out(`  ✗ ${a.path} not written: ${(err as Error).message}\n`);
        continue;
      }
      o.out(`  ✓ wrote ${a.path}\n`);
    } else {
      const r = await sys.exec(a.argv[0] as string, a.argv.slice(1), {
        cwd: a.cwd,
        timeoutMs: 60_000,
      });
      if (r.code === 0) o.out(`  ✓ ${a.describe}\n`);
      else if (!a.mayFail) {
        ok = false;
        o.out(
          `  ✗ ${commandLine(a.argv.slice(0, 3))} failed: ${(r.stderr || r.error || '').trim().split('\n')[0]}\n`,
        );
      }
    }
  }
  return ok;
}

async function claudeCliFor(
  ctx: SetupContext,
  project: string,
): Promise<{ bin: string | null; has: boolean }> {
  if (ctx.backend.kind !== 'dev') return { bin: null, has: false };
  const bin = ctx.sys.which('claude');
  if (!bin) return { bin: null, has: false };
  const help = await ctx.sys.exec(bin, ['mcp', 'add-json', '--help'], { timeoutMs: 15_000 });
  if (help.code !== 0 || !/--scope/.test(help.stdout + help.stderr))
    return { bin: null, has: false };
  const get = await ctx.sys.exec(bin, ['mcp', 'get', SERVER_NAME], {
    cwd: project,
    timeoutMs: 15_000,
  });
  return { bin, has: get.code === 0 };
}

const tilde = (path: string, home: string) =>
  path === home || path.startsWith(`${home}/`) ? `~${path.slice(home.length)}` : path;

export function summarizePlan(actions: ClaudeAction[], home: string): string {
  const lines: string[] = [];
  for (const a of actions) {
    if (a.kind === 'command') {
      if (!a.mayFail) lines.push(`• ${a.describe.replace(/ \(.*\)$/, '')}`);
      continue;
    }
    const where = tilde(a.path, home);
    if (a.diff.length === 0) lines.push(`• ${where}  already up to date`);
    else lines.push(`• ${where}  ${a.before === null ? 'new file' : 'changed, backup kept'}`);
    for (const n of a.notes) lines.push(`  ${n}`);
  }
  return lines.join('\n');
}

async function previewAndApply(
  ctx: SetupContext,
  actions: ClaudeAction[],
  what: string,
  label: string,
  lead: string,
): Promise<boolean | null> {
  const stamp = backupStamp(ctx.sys.now());
  const home = ctx.backend.user.home;
  ctx.ui.brief(
    `${lead}\n\n${summarizePlan(actions, home)}\n\nTab shows every change.`,
    `\n  These changes make ${what}:\n${describePlan(actions, stamp)}`,
  );
  if (!(await confirm(ctx.prompt, 'Apply these changes?', false))) {
    ctx.out('  Nothing written.\n');
    return null;
  }
  let written = '';
  const ok = await applyPlan(ctx.sys, actions, {
    stamp,
    owner: ctx.backend.fileOwner,
    out: (t) => {
      written += t;
    },
  });
  if (ok) {
    await ctx.ui.page('Written', 'replace');
    ctx.ui.brief(`✓ ${label} is set up for Keyflap. Backups of changed files are kept.`, written);
  } else ctx.out(written);
  return ok;
}

const HOST_LABEL: Record<AgentHost, string> = {
  'claude-code': 'Claude Code',
  hermes: 'Hermes Agent',
  codex: 'Codex',
};

const HOST_ORDER: readonly AgentHost[] = ['claude-code', 'codex', 'hermes'];

function recordedAgents(state: SetupState, host: AgentHost): string[] {
  return host === 'claude-code'
    ? state.claudeCode.map((t) => t.agentId)
    : (state.agentHosts ?? []).filter((t) => t.host === host).map((t) => t.agentId);
}

async function pickAgent(
  ctx: SetupContext,
  host: AgentHost,
): Promise<{ id: string; name: string } | null> {
  const label = HOST_LABEL[host];
  const agents = (await ctx.backend.listAgents()).filter((a) => !a.revoked);
  const claimed = new Set(
    HOST_ORDER.filter((h) => h !== host).flatMap((h) => recordedAgents(ctx.state, h)),
  );
  const last = recordedAgents(ctx.state, host).at(-1);
  const defaultName =
    agents.find((a) => a.id === last && ctx.backend.hasAgentToken(a.id))?.name ?? host;
  const choices = agents.filter((a) => !claimed.has(a.id));
  if (choices.length > 0) {
    ctx.ui.brief(
      `Agents: ${choices.map((a) => a.name).join(', ')}`,
      `  Agents: ${choices.map((a) => `${a.name} (${a.id})`).join(', ')}\n`,
    );
  }
  if (!(await confirm(ctx.prompt, `Set up an agent for ${label}?`, true))) return null;
  for (;;) {
    const name = (await ctx.prompt.ask('Agent name', defaultName)).trim();
    if (name === '-' || name === '') return null;
    const existing = agents.find((a) => a.name === name);
    if (existing) {
      if (claimed.has(existing.id)) {
        ctx.out(`  "${name}" already serves another host. Give each host its own agent.\n`);
        continue;
      }
      if (ctx.backend.hasAgentToken(existing.id)) {
        if (await confirm(ctx.prompt, `Use the existing agent "${name}"?`, true)) return existing;
        continue;
      }
      ctx.out(
        `  An active agent "${name}" exists, but its token was shown only once (keyflap agent add), so\n` +
          `  setup can't configure it. Pick another name, or revoke it first (keyflap agent revoke ${existing.id}).\n`,
      );
      continue;
    }
    try {
      const created = await ctx.backend.createAgent(name);
      const path = ctx.backend.storeAgentToken(created.id, created.token);
      ctx.ui.brief(
        `✓ Added agent "${created.name}". Its token stays in a file the model can't read.`,
        `  ✓ Added agent "${created.name}" (id ${created.id}). Its token is stored in ${path}\n` +
          `    (0600, denied to the model) for ${label}; it is not shown.\n`,
      );
      return { id: created.id, name: created.name };
    } catch (err) {
      ctx.out(`  ✗ ${(err as Error).message}\n`);
    }
  }
}

async function otherHostStep(ctx: SetupContext, host: OtherHost): Promise<StepResult> {
  const label = HOST_LABEL[host];
  const agent = await pickAgent(ctx, host);
  if (!agent) return 'skipped';
  if (!(await confirm(ctx.prompt, `Write the ${label} config for this agent?`, true))) {
    ctx.out(
      `  Skipped. \`keyflap agent add <name> --host ${host}\` prints the config to merge by hand.\n`,
    );
    return 'skipped';
  }
  const tokenPath = ctx.paths
    ? serviceAgentTokenPath(ctx.paths.hookDir, agent.id)
    : devAgentTokenPath(ctx.dataDir, agent.id);
  const r = await configureOtherHost(ctx, host, agent, tokenPath, (actions, what) =>
    previewAndApply(ctx, actions, what, label, `These files change for ${label}:`),
  );
  if (r === null) return 'skipped';
  ctx.state.agentHosts = [
    ...(ctx.state.agentHosts ?? []).filter((t) => !(t.host === host && t.dir === r.dir)),
    { host, agentId: agent.id, dir: r.dir },
  ];
  save(ctx);
  return r.ok ? 'done' : 'skipped';
}

function hostsToSetUp(ctx: SetupContext): AgentHost[] {
  if (ctx.host) return [ctx.host];
  const found = detectHosts(ctx.sys, ctx.backend.user.home);
  return HOST_ORDER.filter((h) => h === 'claude-code' || found.includes(h));
}

export async function agentStep(ctx: SetupContext): Promise<StepResult> {
  const hosts = hostsToSetUp(ctx);
  const many = hosts.length > 1;
  await ctx.ui.step(4, many ? 'Agents' : `Agent and ${HOST_LABEL[hosts[0] ?? 'claude-code']}`);
  let done = false;
  for (const [i, host] of hosts.entries()) {
    if (many) {
      const title = `${HOST_LABEL[host]} (${i + 1} of ${hosts.length})`;
      await ctx.ui.page(title, i === 0 ? 'replace' : 'keep-until-read');
    }
    const r = host === 'claude-code' ? await claudeCodeStep(ctx) : await otherHostStep(ctx, host);
    done = done || r === 'done';
  }
  return done ? 'done' : 'skipped';
}

async function claudeCodeStep(ctx: SetupContext): Promise<StepResult> {
  const agent = await pickAgent(ctx, 'claude-code');
  if (!agent) return 'skipped';
  if (!(await confirm(ctx.prompt, 'Write the Claude Code config for this agent?', true))) {
    ctx.out(
      '  Skipped. `keyflap agent add` prints the config to merge by hand (docs/integrations/claude-code.md).\n',
    );
    return 'skipped';
  }
  const scope = await choose(
    ctx.prompt,
    'Which Claude Code config?',
    [
      ['project', 'One project (its MCP config and its .claude/settings.local.json)'],
      ['user', 'All your projects (~/.claude.json and ~/.claude/settings.json)'],
    ],
    ctx.sys.cwd === ctx.backend.user.home || ctx.sys.cwd === '/' ? 'user' : 'project',
    ctx.out,
  );
  let project = ctx.sys.cwd;
  if (scope === 'project') {
    for (;;) {
      project = (await ctx.prompt.ask('Project directory', ctx.sys.cwd)).trim();
      if (project.startsWith('/') && ctx.sys.stat(project)?.isDirectory) break;
      ctx.out('  Give the absolute path of an existing directory.\n');
    }
  }
  const cfg: KeyflapClaudeConfig = {
    mcpUrl: `http://127.0.0.1:${await ctx.backend.mcpPort()}/mcp`,
    headersCommand: ctx.backend.headersCommand(agent.id),
    hookCommand: ctx.backend.hookCommand(agent.id),
    denyDir: ctx.backend.denyDir,
    home: ctx.backend.user.home,
  };
  const cli = await claudeCliFor(ctx, project);
  let actions: ClaudeAction[];
  try {
    actions = planClaudeConfig({
      sys: ctx.sys,
      scope,
      project,
      home: ctx.backend.user.home,
      cfg,
      claudeCli: cli.bin,
      cliHasEntry: cli.has,
      owner: ctx.backend.fileOwner,
    });
  } catch (err) {
    ctx.out(`  ✗ ${(err as Error).message}\n`);
    return 'skipped';
  }
  const ok = await previewAndApply(
    ctx,
    actions,
    `Claude Code use agent "${agent.name}"`,
    'Claude Code',
    'Claude Code gets the keyflap MCP server, the hook and the sandbox rules:',
  );
  if (ok === null) return 'skipped';
  ctx.state.claudeCode = [
    ...ctx.state.claudeCode.filter(
      (t) => !(t.scope === scope && (scope === 'user' || t.project === project)),
    ),
    { agentId: agent.id, scope, project: scope === 'project' ? project : null },
  ];
  save(ctx);
  ctx.ui.brief(
    [
      scope === 'project'
        ? 'Restart Claude Code in that project. /mcp should list keyflap as connected, and /sandbox as active.'
        : "Restart Claude Code, in the terminal and the desktop app's Code tab. /mcp should list keyflap as connected, and /sandbox as active.",
      '',
      'Never approve an edit the model proposes to .claude/settings*.json or .mcp.json.',
    ].join('\n'),
    [
      '',
      `  Start (or restart) Claude Code${scope === 'project' ? ` in ${project}` : ''} and run /mcp: the "keyflap" server`,
      '  should be connected. Check /sandbox: the sandbox must be active (Linux: bubblewrap + socat; macOS: built in).',
      '  Do not approve edits to .claude/settings*.json or .mcp.json that the model proposes.',
      '',
    ].join('\n'),
  );
  return ok ? 'done' : 'skipped';
}

export async function addPassword(ctx: SetupContext): Promise<void> {
  if (!(await waitForDaemonStopped(ctx, 'storing a password'))) return;
  let site = '';
  while (site === '')
    site = (await ctx.prompt.ask('Site (e.g. example.com or https://app.example.com)')).trim();
  const username = (await ctx.prompt.ask('Username (blank: none)')).trim();
  const totp = await confirm(ctx.prompt, 'Does the site ask for a one-time code (TOTP)?', false);
  const password = await ctx.prompt.secret('Password (not shown)');
  if (password === '') {
    ctx.out('  Empty password: nothing stored.\n');
    return;
  }
  const seed = totp ? await ctx.prompt.secret('TOTP secret or otpauth:// URI (not shown)') : null;
  const added = await ctx.backend.addPassword({
    site,
    username: username === '' ? null : username,
    password,
    totp: seed === null || seed.trim() === '' ? null : seed,
  });
  ctx.out(
    `  ✓ Added a password${seed ? ' + TOTP' : ''} for ${added.domain}${username ? ` (username ${username})` : ''}, id ${added.id}.\n`,
  );
}

async function connectInService(ctx: SetupContext, kind: SourceKind): Promise<boolean> {
  const host = {
    sys: ctx.sys,
    paths: ctx.paths as ServicePaths,
    m: requireServiceManager(ctx.sys.platform),
  };
  try {
    return await connectPasswordSource(
      host,
      { prompt: ctx.prompt, out: ctx.out, wait: (label, work) => ctx.ui.wait(label, work) },
      { kind, interactive: true, yes: false, confirmConnect: true },
    );
  } catch (err) {
    if (!(err instanceof PasswordSourceError)) throw err;
    ctx.out(`✗ ${err.message}${err.fix ? `\n  fix: ${err.fix}` : ''}\n`);
    return false;
  }
}

async function passLogin(ctx: SetupContext, run: ToolRun): Promise<boolean> {
  ctx.ui.brief(
    'pass-cli is not logged in. Setup can log it in with a personal access token: it is never shown, saved or put on a command line.',
    '  pass-cli is not logged in. Setup can log it in with a personal access token: it is read\n' +
      '  without echo and handed to `pass-cli login` in its environment\n' +
      '  (PROTON_PASS_PERSONAL_ACCESS_TOKEN), never on a command line (docs/integrations/proton-pass.md).\n',
  );
  if (!(await confirm(ctx.prompt, 'Log in now?', false))) return false;
  const token = await ctx.prompt.secret('Personal access token (not shown)');
  if (token.trim() === '') return false;
  if (!(await protonLogin(ctx.sys, run, token.trim()))) {
    ctx.out('  ✗ pass-cli login failed.\n');
    return false;
  }
  ctx.out('  ✓ Logged in.\n');
  return true;
}

export async function protonPass(ctx: SetupContext): Promise<boolean> {
  if (ctx.backend.kind === 'service') return connectInService(ctx, 'proton-pass');
  if (ctx.state.passwordSource?.kind === '1password') {
    ctx.out('  1Password is set up; Keyflap uses one password source at a time.\n');
    if (!(await confirm(ctx.prompt, 'Switch to Proton Pass?', false))) return false;
  }
  let bin = ctx.sys.which('pass-cli');
  if (!bin) {
    const p = (await ctx.prompt.ask('pass-cli is not on PATH. Its path (blank to skip)')).trim();
    if (p === '' || !ctx.sys.exists(p)) return false;
    bin = p;
  }
  const run: ToolRun = { bin, env: {}, cleanEnv: false };
  let v = await protonVaults(ctx.sys, run);
  if (v === null && (await passLogin(ctx, run))) v = await protonVaults(ctx.sys, run);
  if (v === null) {
    ctx.out('  Not logged in; Proton Pass not set up. See docs/integrations/proton-pass.md.\n');
    return false;
  }
  ctx.out(
    `  Vaults: ${v.length === 0 ? '(none)' : v.join(', ')}. A vault of its own for your agents is safest.\n`,
  );
  let vault: string | null = null;
  for (;;) {
    const a = (
      await ctx.prompt.ask('Vault to use (blank: every vault)', v.length === 1 ? v[0] : '')
    ).trim();
    if (a === '' || v.includes(a)) {
      vault = a === '' ? null : a;
      break;
    }
    ctx.out('  No such vault.\n');
  }
  ctx.state.passwordSource = {
    kind: 'proton-pass',
    vault,
    bin: bin === ctx.sys.which('pass-cli') ? null : bin,
  };
  save(ctx);
  ctx.out('  ✓ The daemon will offer these logins (--password-source proton-pass).\n');
  return true;
}

function opEnv(token: string, home: string): Record<string, string> {
  return {
    HOME: home,
    PATH: '/usr/bin:/bin:/usr/local/bin',
    OP_SERVICE_ACCOUNT_TOKEN: token,
    OP_CACHE: 'false',
    OP_BIOMETRIC_UNLOCK_ENABLED: 'false',
  };
}

export async function onePassword(ctx: SetupContext): Promise<boolean> {
  if (ctx.simple) {
    ctx.out(
      '  1Password needs the full install: the background broker would have to keep the service\n' +
        '  account token in a file any agent running as you could read. Use Proton Pass, an\n' +
        `  export, or the full install: ${FULL_INSTALL_COMMAND}\n`,
    );
    return false;
  }
  if (ctx.backend.kind === 'service') return connectInService(ctx, '1password');
  if (ctx.state.passwordSource?.kind === 'proton-pass') {
    ctx.out('  Proton Pass is set up; Keyflap uses one password source at a time.\n');
    if (!(await confirm(ctx.prompt, 'Switch to 1Password?', false))) return false;
  }
  let bin = ctx.sys.which('op');
  if (!bin) {
    const p = (
      await ctx.prompt.ask('op (the 1Password CLI) is not on PATH. Its path (blank to skip)')
    ).trim();
    if (p === '' || !ctx.sys.exists(p)) {
      ctx.out('  Install op from 1Password first (docs/integrations/1password.md).\n');
      return false;
    }
    bin = p;
  }
  ctx.ui.brief(
    'Keyflap signs in to 1Password as a service account with read access to a vault of its own. Its token is checked here and never saved.',
    '  Keyflap signs in to 1Password as a service account, limited to the vaults you grant it.\n' +
      '  Make one for your agents (1Password.com > Developer > Service accounts) with read access\n' +
      '  to a vault of its own. Its token is checked here and never saved.\n',
  );
  const fromEnv = process.env.OP_SERVICE_ACCOUNT_TOKEN?.trim() ?? '';
  const token =
    fromEnv !== '' &&
    (await confirm(ctx.prompt, 'Use the token in OP_SERVICE_ACCOUNT_TOKEN?', true))
      ? fromEnv
      : (await ctx.prompt.secret('Service account token (not shown)')).trim();
  if (token === '') return false;
  const v = await opVaults(ctx.sys, {
    bin,
    env: opEnv(token, process.env.HOME ?? '/tmp'),
    cleanEnv: true,
  });
  if (v === null) {
    ctx.out(
      '  ✗ op could not list vaults with that token (wrong or expired token, or no network).\n',
    );
    return false;
  }
  ctx.out(
    `  Vaults: ${v.length === 0 ? '(none)' : v.join(', ')}. A vault of its own for your agents is safest.\n`,
  );
  let vault: string | null = null;
  for (;;) {
    const a = (
      await ctx.prompt.ask('Vault to use (blank: every vault)', v.length === 1 ? v[0] : '')
    ).trim();
    if (a === '' || v.includes(a)) {
      vault = a === '' ? null : a;
      break;
    }
    ctx.out('  No such vault.\n');
  }
  ctx.state.passwordSource = {
    kind: '1password',
    vault,
    bin: bin === ctx.sys.which('op') ? null : bin,
  };
  save(ctx);
  if (ctx.secretEnv) ctx.secretEnv.OP_SERVICE_ACCOUNT_TOKEN = token;
  ctx.ui.brief(
    '✓ The daemon will offer these logins.\n\nGive it the token on its command line only. Never export it or put it in a shell profile: agents started from that shell could read the vault.',
    '  ✓ The daemon will offer these logins (--password-source 1password). It reads the token\n' +
      '    from OP_SERVICE_ACCOUNT_TOKEN each time it starts: keep it in your password manager\n' +
      '    and give it to the daemon command only (OP_SERVICE_ACCOUNT_TOKEN=… keyflap daemon).\n' +
      '    Never export it or put it in a shell profile: agents started from that shell would\n' +
      '    inherit it and could read the vault themselves (docs/integrations/1password.md).\n',
  );
  return true;
}

type CredentialChoice = 'password' | 'import' | 'proton-pass' | '1password' | 'skip';

const CREDENTIAL_PAGES: Record<Exclude<CredentialChoice, 'skip'>, string> = {
  password: 'One password',
  import: 'Import an export',
  'proton-pass': 'Proton Pass',
  '1password': '1Password',
};

function installedSource(ctx: SetupContext): 'proton-pass' | '1password' | null {
  if (!ctx.paths) return null;
  const core = parseJsonFile(ctx.sys.readFile(ctx.paths.coreConfig)) as {
    passwordSource?: { kind?: unknown } | null;
  } | null;
  const kind = core?.passwordSource?.kind;
  return kind === 'proton-pass' || kind === '1password' ? kind : null;
}

export function firstCredentialChoice(ctx: SetupContext, stored: number | null): CredentialChoice {
  if (ctx.backend.kind !== 'service') return 'skip';
  return installedSource(ctx) ?? (stored === 0 ? 'import' : 'skip');
}

export async function credentialsStep(ctx: SetupContext): Promise<StepResult> {
  await ctx.ui.step(5, 'Credentials');
  let count: number | null = null;
  try {
    count = (await ctx.backend.storedLogins()).length;
  } catch {}
  const pp = ctx.state.passwordSource;
  const source = pp
    ? `${pp.kind === '1password' ? '1Password' : 'Proton Pass'}${pp.vault ? ` (vault ${pp.vault})` : ''}`
    : null;
  ctx.ui.brief(
    [
      'Passkeys need nothing here: the agent registers them.',
      count ? `${count} password${count === 1 ? '' : 's'} stored.` : '',
      source ? `Password source: ${source}.` : '',
    ]
      .filter(Boolean)
      .join(' '),
    `  ${count ?? '?'} password item(s) stored${source ? `; ${source}` : ''}. Passkeys need nothing here: the agent registers them.\n`,
  );
  for (let added = false; ; added = true) {
    if (added) await ctx.ui.page('Another one');
    const what = await choose<CredentialChoice>(
      ctx.prompt,
      added ? 'Add another credential?' : 'Add a credential?',
      [
        ['password', 'A password (and TOTP) for one site, stored in the signer'],
        ['proton-pass', 'Proton Pass: use the logins in a vault (via pass-cli)'],
        ['1password', '1Password: use the logins in a vault (via op, a service account)'],
        [
          'import',
          'Import an export: Apple Passwords, Chrome, Firefox, 1Password or Bitwarden (CSV)',
        ],
        ['skip', 'Nothing (now)'],
      ],
      added ? 'skip' : firstCredentialChoice(ctx, count),
      ctx.out,
    );
    if (what === 'skip') return 'done';
    await ctx.ui.page(CREDENTIAL_PAGES[what]);
    try {
      if (what === 'password') {
        await addPassword(ctx);
        continue;
      }
      if (what === 'import') {
        await importExport(ctx);
        continue;
      }
      if (await (what === '1password' ? onePassword(ctx) : protonPass(ctx))) return 'done';
    } catch (err) {
      ctx.out(`  ✗ ${(err as Error).message}\n`);
    }
  }
}

export function walkthrough(mode: 'dev' | 'service' | 'simple'): string {
  if (mode === 'simple') {
    return `
Try it: restart Claude Code (/mcp should list "keyflap" as connected), then ask for a sign-in
to a site you have a login for, in your password source or stored in step 5 of setup:

  > Sign in to <site>

Your phone shows your words, the site, the agent and the credential type; approve with Face ID.
If the site puts up a human check, your phone offers a live view: solve it there, tap Done.

Every sign-in needs a message from you in the last 10 minutes; the approval shows your words.
`;
  }
  if (mode === 'service') {
    return `
Try it: restart Claude Code in the project you configured (/mcp should list "keyflap" as
connected), then ask for a sign-in to a site you have a login for, in your password source or
stored with sudo keyflap password add <site>:

  > Sign in to <site>

Your phone shows your words, the site, the agent and the credential type; approve with Face ID.
If the site puts up a human check, your phone offers a live view: solve it there, tap Done.

Every sign-in needs a message from you in the last 10 minutes; the approval shows your words.
`;
  }
  const pw = 'keyflap password add rp.localhost --username alice --totp      (daemon stopped)';
  return `
Try it with the bundled test site (in a checkout of this repo, another terminal):

  pnpm test-rp                       # the test relying party on http://localhost:3000

In Claude Code, in the project you configured:

  > Go to http://localhost:3000, sign up as bob, and add a passkey.

  Approve the request, then ask it to sign out and sign back in with the passkey.

Password + TOTP (the test RP's seeded login; passwords are bound to a registrable domain, so
use the same server as rp.localhost; or store it in step 5 of keyflap setup):

  ${pw}
  # password: correct horse battery staple   TOTP secret: JBSWY3DPEHPK3PXP

  > Go to http://rp.localhost:3000/password/login and sign in with my password.

Every sign-in needs a message from you in the last 10 minutes; the approval shows your words.
`;
}

export function doctorSummary(r: DoctorReport): string {
  const fails = r.checks.filter((c) => c.status === 'fail');
  const warns = r.checks.filter((c) => c.status === 'warn');
  const lines = [
    fails.length > 0
      ? `✗ ${fails.length} check${fails.length === 1 ? '' : 's'} failed.`
      : `✓ All ${r.checks.length} checks passed${warns.length > 0 ? `, ${warns.length} warning${warns.length === 1 ? '' : 's'}` : ''}.`,
  ];
  for (const c of [...fails, ...warns]) {
    lines.push(`${c.status === 'fail' ? '✗' : '!'} ${c.id}: ${c.detail}`);
    if (c.fix) lines.push(`  fix: ${c.fix}`);
  }
  return lines.join('\n');
}

async function healthCheck(ctx: SetupContext): Promise<void> {
  const report = await ctx.ui.wait('Running the health check', () => ctx.doctor());
  ctx.ui.brief(doctorSummary(report), `\n${formatReport(report, ctx.style)}`);
}

export function shortWalkthrough(mode: 'dev' | 'service' | 'simple'): string {
  if (mode === 'dev') {
    return [
      'Try it on the bundled test site: run pnpm test-rp in a checkout, then ask Claude Code',
      '',
      '  > Go to http://localhost:3000, sign up as bob, and add a passkey.',
      '',
      'Tab shows the password + TOTP walkthrough too.',
    ].join('\n');
  }
  return [
    'Try it: restart Claude Code and ask',
    '',
    '  > Sign in to <site>',
    '',
    'Your phone shows your words, the site and the agent. Approve with Face ID.',
  ].join('\n');
}

async function finishSimple(ctx: SetupContext, simple: SimpleInstall): Promise<StepResult> {
  ctx.state.headed = false;
  save(ctx);
  if (ctx.state.approver?.kind !== 'phone') {
    ctx.out('  No phone approver yet: run setup again to choose one. Nothing was started.\n');
  } else if (
    await confirm(ctx.prompt, 'Run Keyflap in the background now, and every time you log in?', true)
  ) {
    const p = ctx.state.passwordSource;
    const cmd = p ? (p.kind === '1password' ? 'op' : 'pass-cli') : null;
    const state =
      p && !p.bin && cmd
        ? { ...ctx.state, passwordSource: { ...p, bin: ctx.sys.which(cmd) } }
        : ctx.state;
    const args = daemonCommand(state, {
      dataDir: ctx.dataDir,
      defaultDataDir: ctx.defaults.dataDir,
      defaultMcpPort: ctx.defaults.mcpPort,
    }).slice(1);
    await startLaunchAgent(ctx.sys, simple, launchAgentPlist(simple, args));
    ctx.out(`  ✓ Started (${simple.plist}). Its log: ${simple.log}\n`);
    const deadline = ctx.sys.now() + 90_000;
    while (!(await ctx.backend.daemonRunning()) && ctx.sys.now() < deadline) {
      await ctx.sys.sleep(1_000);
    }
  }
  await healthCheck(ctx);
  ctx.ui.brief(shortWalkthrough('simple'), walkthrough('simple'));
  ctx.out(
    [
      '',
      PROTECTS_LESS,
      `  The keyflap command: '${simple.wrapper}'`,
      `  To remove it:        '${simple.uninstaller}'   (--purge also deletes your keys)`,
      `  The full install:    ${FULL_INSTALL_COMMAND}`,
      '',
    ].join('\n'),
  );
  return 'done';
}

export function setUpHosts(state: SetupState, home: string): string[] {
  const claude = state.claudeCode.map((t) =>
    t.scope === 'user'
      ? 'Claude Code, all projects (terminal and desktop app)'
      : `Claude Code, ${tilde(t.project ?? '', home)}`,
  );
  const others = (['codex', 'hermes'] as const)
    .filter((h) => (state.agentHosts ?? []).some((t) => t.host === h))
    .map((h) => HOST_LABEL[h]);
  return [...new Set([...claude, ...others])];
}

function showSetUpHosts(ctx: SetupContext): void {
  const hosts = setUpHosts(ctx.state, ctx.backend.user.home);
  if (hosts.length === 0) return;
  const text = ['Set up for Keyflap:', ...hosts.map((h) => `  ✓ ${h}`)].join('\n');
  ctx.ui.brief(text, `\n${text.replace(/^/gm, '  ')}\n`);
}

export async function finishStep(ctx: SetupContext): Promise<StepResult> {
  await ctx.ui.step(6, 'Finish');
  showSetUpHosts(ctx);
  if (ctx.simple && ctx.backend.kind === 'dev') return finishSimple(ctx, ctx.simple);
  if (ctx.backend.kind === 'dev') {
    const hasDisplay =
      ctx.sys.platform === 'darwin'
        ? !ctx.sys.env.SSH_CONNECTION
        : Boolean(ctx.sys.env.DISPLAY || ctx.sys.env.WAYLAND_DISPLAY);
    ctx.state.headed = await confirm(
      ctx.prompt,
      "Show the managed browser window (--headed)? Many sites' bot walls block headless Chromium",
      ctx.state.headed ?? hasDisplay,
    );
    save(ctx);
    const cmd = daemonCommand(ctx.state, {
      dataDir: ctx.dataDir,
      defaultDataDir: ctx.defaults.dataDir,
      defaultMcpPort: ctx.defaults.mcpPort,
    });
    ctx.out(`\n  Start the broker with:\n    ${commandLine(cmd)}\n`);
    if (await ctx.backend.daemonRunning()) {
      ctx.out('  (It is running now: restart it with that command to pick up these settings.)\n');
    } else if (
      ctx.startDaemon &&
      (await confirm(ctx.prompt, 'Start it now, in this terminal?', true))
    ) {
      await ctx.startDaemon(ctx.state);
      await healthCheck(ctx);
      ctx.ui.brief(shortWalkthrough('dev'), walkthrough('dev'));
      ctx.out('\nThe daemon keeps running in this terminal. Ctrl-C stops it.\n');
      return 'daemon-running';
    }
  }
  await healthCheck(ctx);
  ctx.ui.brief(shortWalkthrough(ctx.backend.kind), walkthrough(ctx.backend.kind));
  return 'done';
}

export const STEPS = [preflight, approverStep, pairStep, agentStep, credentialsStep, finishStep];
