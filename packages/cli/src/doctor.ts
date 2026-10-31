import { join, resolve, sep } from 'node:path';
import { plainStyle, type TermStyle } from '@aab/approver';
import { type AddressState, addressPhase } from '@aab/signer/approver-address';
import { OP_TOOL, PASS_CLI_TOOL, toolDir } from '@aab/sources';
import { listenTarget, serveFor } from './approver-address.ts';
import { hostChecks } from './doctor-hosts.ts';
import { serviceAddress, serviceAddressWords } from './service/address.ts';
import {
  requireServiceManager,
  SERVICE_NAMES,
  type ServiceManager,
  type ServiceName,
} from './service/manager.ts';
import type { ServicePaths } from './service/paths.ts';
import type { AdminCall, AgentInfo } from './setup/backend.ts';
import {
  type ClaudeFiles,
  type ClaudeInspection,
  denyPaths,
  inspectClaude,
  parseJsonFile,
} from './setup/claude-config.ts';
import type { ApproverChoice, SetupState } from './setup/state.ts';
import type { FileOwner, System } from './setup/system.ts';
import {
  FULL_INSTALL_COMMAND,
  launchAgentLoaded,
  PROTECTS_LESS,
  SIMPLE_LABEL,
  type SimpleInstall,
} from './simple-install.ts';

export type CheckStatus = 'ok' | 'warn' | 'fail' | 'skip';

export interface Check {
  id: string;
  status: CheckStatus;
  detail: string;
  fix?: string;
}

export interface DoctorReport {
  mode: 'dev' | 'service' | 'simple';
  ok: boolean;
  checks: Check[];
}

interface CommonContext {
  sys: System;
  project: string;
  home: string;
  owner: FileOwner | null;
  chromium: () => Promise<{ ok: true } | { ok: false; error: string }>;
  nodeVersion: string;
}

export interface DevDoctorContext extends CommonContext {
  mode: 'dev';
  dataDir: string;
  state: SetupState | null;
  simple?: SimpleInstall | null;
  daemonCommand: string;
  local: {
    agents(): AgentInfo[];
    audit(): { intact: boolean; entries: number; brokenAt: number | null };
    passwords(): number;
  };
}

export interface ServiceDoctorContext extends CommonContext {
  mode: 'service';
  paths: ServicePaths;
  admin: AdminCall;
}

export type DoctorContext = DevDoctorContext | ServiceDoctorContext;

export const MIN_NODE: ReadonlyArray<readonly [number, number, number]> = [
  [22, 23, 4],
  [24, 22, 1],
  [26, 12, 1],
];
export const MIN_NODE_TEXT = MIN_NODE.map((v) => v.join('.')).join(', ');

export function nodeIsSupported(version: string): boolean {
  const [maj = 0, min = 0, patch = 0] = version.replace(/^v/, '').split('.').map(Number);
  const newest = MIN_NODE[MIN_NODE.length - 1];
  if (newest && maj > newest[0]) return true;
  const line = MIN_NODE.find(([m]) => m === maj);
  if (!line) return false;
  return min > line[1] || (min === line[1] && patch >= line[2]);
}

function nodeCheck(version: string): Check {
  return nodeIsSupported(version)
    ? { id: 'node', status: 'ok', detail: `Node ${version}` }
    : {
        id: 'node',
        status: 'fail',
        detail: `Node ${version} is too old or unsupported`,
        fix: `install Node ${MIN_NODE_TEXT} or newer on that line`,
      };
}

const tilde = (path: string, home: string) =>
  path === home ? '~' : path.startsWith(`${home}/`) ? `~${path.slice(home.length)}` : path;

async function approverOriginCheck(
  sys: System,
  origin: string,
  via: string | null,
  serve: string,
): Promise<Check> {
  const r = await sys.http(`${origin}/`, { timeoutMs: 5_000 });
  if (r.status !== null && r.status < 500) {
    return { id: 'approver-origin', status: 'ok', detail: `approver page answers at ${origin}` };
  }
  if (r.tlsError) {
    return {
      id: 'approver-origin',
      status: 'fail',
      detail: `${origin}: certificate not valid (${r.error})`,
      fix:
        via === 'tailscale'
          ? 'enable HTTPS certificates for the tailnet, then re-run tailscale serve'
          : 'use a certificate for this hostname from a public CA (or tailscale serve)',
    };
  }
  return {
    id: 'approver-origin',
    status: 'fail',
    detail: `${origin} unreachable from this machine (${r.status ?? r.error})`,
    fix:
      via === 'tailscale' || /\.ts\.net(:|$)/.test(new URL(origin).host)
        ? serve
        : 'check the TLS proxy / --tls-cert listener in front of the approver',
  };
}

function claudeChecks(
  insp: ClaudeInspection,
  o: {
    activeAgents: AgentInfo[];
    denyDir: string;
    home: string;
    tokenFile: (agentId: string) => string | null;
    sys: System;
    project: string;
  },
): Check[] {
  const checks: Check[] = [];
  const setupFix = 'keyflap setup (agent step), or see docs/integrations/claude-code.md';
  if (insp.unreadable.length > 0) {
    checks.push({
      id: 'claude-files',
      status: 'warn',
      detail: `could not parse ${insp.unreadable.join(', ')} as JSON (comments?)`,
    });
  }
  if (!insp.mcp) {
    checks.push({
      id: 'claude-mcp',
      status: 'fail',
      detail: `no Claude Code MCP server points at this broker (project ${tilde(o.project, o.home)} or user scope)`,
      fix: setupFix,
    });
  } else if (insp.mcp.auth === 'none') {
    checks.push({
      id: 'claude-mcp',
      status: 'fail',
      detail: `MCP entry in ${insp.mcp.where} sends no Authorization header`,
      fix: setupFix,
    });
  } else {
    checks.push({
      id: 'claude-mcp',
      status: 'ok',
      detail: `MCP server in ${insp.mcp.where} (${insp.mcp.auth === 'headersHelper' ? 'token via keyflap mcp-headers' : 'Authorization header'})`,
    });
  }
  const active = new Set(o.activeAgents.filter((a) => !a.revoked).map((a) => a.id));
  const live = insp.hookAgents.filter((id) => active.has(id));
  if (insp.hookViaPnpm) {
    checks.push({
      id: 'claude-hook',
      status: 'fail',
      detail: 'the keyflap hook runs through a package manager, whose banner reaches the model',
      fix: 'use the absolute-path hook command keyflap setup / keyflap agent add prints',
    });
  } else if (live.length === 0) {
    checks.push({
      id: 'claude-hook',
      status: 'fail',
      detail:
        insp.hookAgents.length === 0
          ? 'no UserPromptSubmit hook forwards your prompts (every sign-in would be denied)'
          : 'the keyflap hook names an agent that is revoked or unknown',
      fix: setupFix,
    });
  } else {
    const missing = live.filter((id) => {
      const f = o.tokenFile(id);
      return f !== null && !o.sys.exists(f);
    });
    checks.push(
      insp.mcp?.auth === 'headersHelper' && missing.length === live.length
        ? {
            id: 'claude-hook',
            status: 'fail',
            detail: 'hook ok, but the agent token file for keyflap mcp-headers is missing',
            fix: 'keyflap setup (agent step) stores it again with a new agent',
          }
        : { id: 'claude-hook', status: 'ok', detail: `UserPromptSubmit hook for agent ${live[0]}` },
    );
  }
  const paths = denyPaths(o.denyDir, o.home);
  const gaps: string[] = [];
  if (!insp.denyRead) gaps.push(`sandbox.filesystem.denyRead ${paths.sandbox}`);
  if (!insp.denyWrite) gaps.push(`sandbox.filesystem.denyWrite ${paths.sandbox}`);
  if (!insp.permissionDeny) gaps.push(`permissions.deny Read/Edit(${paths.rule})`);
  if (!insp.sandboxEnabled) gaps.push('sandbox.enabled true');
  if (!insp.failIfUnavailable) gaps.push('sandbox.failIfUnavailable true');
  if (insp.allowUnsandboxedCommands) gaps.push('sandbox.allowUnsandboxedCommands false');
  checks.push(
    gaps.length === 0
      ? {
          id: 'claude-deny',
          status: 'ok',
          detail: `the model is denied ${tilde(o.denyDir, o.home)} (sandbox + permission rules)`,
        }
      : {
          id: 'claude-deny',
          status: 'fail',
          detail: `!! THE MODEL CAN READ ${tilde(o.denyDir, o.home)} (host token): missing ${gaps.join('; ')}`,
          fix: setupFix,
        },
  );
  return checks;
}

export type UserRead = (path: string) => string | null;

export function userReader(sys: System, owner: FileOwner | null, refused: string[]): UserRead {
  return (path) => {
    if (owner === null) return null;
    try {
      return sys.readUserFile(path, owner);
    } catch (err) {
      refused.push((err as Error).message);
      return null;
    }
  };
}

function refusedCheck(refused: string[]): Check[] {
  return refused.length === 0
    ? []
    : [
        {
          id: 'user-files',
          status: 'fail',
          detail: `not read: ${refused.join('; ')}`,
          fix: 'replace each link with a regular file of yours, then re-run keyflap doctor',
        },
      ];
}

function readClaudeFiles(read: UserRead, home: string, project: string): ClaudeFiles {
  const j = (p: string) => parseJsonFile(read(p));
  return {
    userSettings: j(join(home, '.claude', 'settings.json')),
    projectSettings: j(join(project, '.claude', 'settings.json')),
    localSettings: j(join(project, '.claude', 'settings.local.json')),
    userState: j(join(home, '.claude.json')),
    projectMcp: j(join(project, '.mcp.json')),
  };
}

function headedCheck(headed: boolean | null, how: string): Check {
  return headed
    ? { id: 'headed', status: 'ok', detail: 'headed browser' }
    : {
        id: 'headed',
        status: 'warn',
        detail: "headless browser: many sites' bot walls refuse headless Chromium",
        fix: how,
      };
}

export function hookCodeCheck(
  ctx: Pick<DevDoctorContext, 'project' | 'home' | 'state'>,
  checkout = resolve(import.meta.dirname, '..', '..', '..'),
): Check | null {
  const projects = new Set([
    resolve(ctx.project),
    ...(ctx.state?.claudeCode ?? []).flatMap((t) => (t.project ? [resolve(t.project)] : [])),
  ]);
  const within = (a: string, b: string) => a === b || a.startsWith(`${b}${sep}`);
  const hit = [...projects].find((p) => within(checkout, p) || within(p, checkout));
  if (!hit) return null;
  const c = tilde(checkout, ctx.home);
  return {
    id: 'hook-code',
    status: 'warn',
    detail: `the hook and MCP headersHelper run code from ${c} outside the sandbox, and the Claude Code project ${tilde(hit, ctx.home)} can write there: a model could change them and read the host and agent tokens`,
    fix: `run your agents from a project outside ${c} (or use service mode)`,
  };
}

async function devChecks(ctx: DevDoctorContext, read: UserRead): Promise<Check[]> {
  const { sys, dataDir, state } = ctx;
  const simple = ctx.simple ?? null;
  const checks: Check[] = [];
  const d = tilde(dataDir, ctx.home);
  const setup = simple ? `'${simple.wrapper}' setup` : 'keyflap setup --unprotected';
  if (simple) {
    checks.push({
      id: 'mode',
      status: 'ok',
      detail: `simple install (runs as you, in the background), data dir ${d}`,
    });
    checks.push({
      id: 'protection',
      status: 'warn',
      detail: PROTECTS_LESS,
      fix: `'${simple.uninstaller}', then the full install: ${FULL_INSTALL_COMMAND}`,
    });
  } else {
    checks.push({
      id: 'mode',
      status: 'ok',
      detail: `dev mode (same-user, development only), data dir ${d}`,
    });
    const hookCode = hookCodeCheck(ctx);
    if (hookCode) checks.push(hookCode);
  }
  checks.push(nodeCheck(ctx.nodeVersion));
  const ds = sys.stat(dataDir);
  if (!ds?.isDirectory) {
    checks.push({
      id: 'data-dir',
      status: 'fail',
      detail: `${d} does not exist`,
      fix: setup,
    });
    return checks;
  }
  checks.push(
    (ds.mode & 0o077) !== 0 || ds.uid !== sys.uid
      ? {
          id: 'data-dir',
          status: 'fail',
          detail: `${d} is mode ${ds.mode.toString(8)} / uid ${ds.uid}; must be yours, 0700`,
          fix: `chmod 700 ${dataDir}`,
        }
      : { id: 'data-dir', status: 'ok', detail: `${d} (0700)` },
  );

  if (simple) {
    checks.push(
      (await launchAgentLoaded(sys))
        ? {
            id: 'background',
            status: 'ok',
            detail: `LaunchAgent ${SIMPLE_LABEL} loaded: it starts at login and again after a crash`,
          }
        : {
            id: 'background',
            status: 'fail',
            detail: `LaunchAgent ${SIMPLE_LABEL} is not loaded`,
            fix: `${setup} (its last step starts it)`,
          },
    );
  }
  const intentSock = join(dataDir, 'run', 'intent.sock');
  const running = await sys.connectUnix(intentSock);
  checks.push(
    running
      ? { id: 'daemon', status: 'ok', detail: 'daemon reachable (intent socket answers)' }
      : {
          id: 'daemon',
          status: 'fail',
          detail: 'daemon not running (no answer on the intent socket)',
          fix: ctx.daemonCommand,
        },
  );
  if (running) {
    const bad: string[] = [];
    for (const [name, path, mode] of [
      ['intent socket', intentSock, 0o600],
      ['host token', join(dataDir, 'host-token'), 0o600],
    ] as const) {
      const s = sys.stat(path);
      if (!s) bad.push(`${name} missing`);
      else if (s.uid !== sys.uid || (s.mode & 0o077) !== 0) {
        bad.push(`${name} is ${s.mode.toString(8)}/uid ${s.uid} (want ${mode.toString(8)}, yours)`);
      }
    }
    checks.push(
      bad.length === 0
        ? { id: 'sockets', status: 'ok', detail: 'intent socket and host token: yours, 0600' }
        : { id: 'sockets', status: 'fail', detail: bad.join('; '), fix: 'restart the daemon' },
    );
    const signerUp = await sys.connectUnix(join(dataDir, 'run', 'signer.sock'));
    checks.push(
      signerUp
        ? { id: 'signer', status: 'ok', detail: 'signer socket answers' }
        : {
            id: 'signer',
            status: 'fail',
            detail: 'signer socket does not answer',
            fix: 'restart the daemon',
          },
    );
    const port = state?.mcpPort ?? 8765;
    const r = await sys.http(`http://127.0.0.1:${port}/mcp`, { method: 'POST' });
    checks.push(
      r.status === 401
        ? { id: 'mcp', status: 'ok', detail: `MCP endpoint http://127.0.0.1:${port}/mcp answers` }
        : {
            id: 'mcp',
            status: 'fail',
            detail: `MCP endpoint on 127.0.0.1:${port}: ${r.status === null ? (r.error ?? 'no answer') : `unexpected HTTP ${r.status}`}`,
            fix: `is the daemon using --mcp-port ${port}? Re-run keyflap setup to record the port`,
          },
    );
  } else {
    for (const id of ['sockets', 'signer', 'mcp']) {
      checks.push({ id, status: 'skip', detail: 'the daemon is not running' });
    }
  }

  const approver: ApproverChoice | null = state?.approver ?? null;
  if (approver?.kind === 'phone') {
    checks.push(
      running
        ? await approverOriginCheck(
            sys,
            approver.origin,
            approver.via,
            serveFor(
              sys,
              { origin: approver.origin, target: listenTarget(approver.listen) },
              false,
            ),
          )
        : { id: 'approver-origin', status: 'skip', detail: 'the approver starts with the daemon' },
    );
    const text = sys.readFile(join(dataDir, 'approver', 'devices.json'));
    let n = 0;
    try {
      n = text === null ? 0 : ((JSON.parse(text) as { devices?: unknown[] }).devices ?? []).length;
    } catch {
      n = 0;
    }
    checks.push(
      n > 0
        ? { id: 'phone', status: 'ok', detail: `${n} phone(s) paired` }
        : {
            id: 'phone',
            status: 'fail',
            detail: 'no phone paired: every sign-in would be denied',
            fix: `${setup} (pairing step)`,
          },
    );
  } else {
    checks.push({
      id: 'approver-origin',
      status: 'warn',
      detail:
        approver?.kind === 'terminal'
          ? 'terminal approver: no user verification, high-risk sites always denied'
          : 'no approver chosen yet',
      fix: `${setup} (phone approver step)`,
    });
    checks.push({ id: 'phone', status: 'skip', detail: 'no phone approver configured' });
  }

  const agents = ctx.local.agents();
  const active = agents.filter((a) => !a.revoked);
  checks.push(
    active.length > 0
      ? {
          id: 'agents',
          status: 'ok',
          detail: `${active.length} agent(s): ${active.map((a) => a.name).join(', ')}`,
        }
      : {
          id: 'agents',
          status: 'fail',
          detail: 'no agents',
          fix: `${setup} (agent step)`,
        },
  );
  const insp = inspectClaude(readClaudeFiles(read, ctx.home, ctx.project), {
    project: ctx.project,
    mcpPort: state?.mcpPort ?? 8765,
    denyDir: dataDir,
    home: ctx.home,
  });
  checks.push(
    ...claudeChecks(insp, {
      activeAgents: agents,
      denyDir: dataDir,
      home: ctx.home,
      sys,
      project: ctx.project,
      tokenFile: (id) => join(dataDir, 'agents', `${id}.token`),
    }),
  );

  const c = await ctx.chromium();
  checks.push(
    c.ok
      ? { id: 'chromium', status: 'ok', detail: 'Chromium launches' }
      : {
          id: 'chromium',
          status: 'fail',
          detail: `Chromium does not launch: ${c.error}`,
          fix: simple
            ? `run the simple install again: ${simple.browsers} is missing or damaged`
            : 'pnpm --filter @aab/shim exec playwright install chromium',
        },
  );
  checks.push(
    simple
      ? {
          id: 'headed',
          status: 'ok',
          detail:
            'headless: the simple install shows no browser window; human checks go to your phone',
        }
      : headedCheck(state?.headed ?? null, 'keyflap daemon … --headed (or keyflap setup)'),
  );

  const a = ctx.local.audit();
  checks.push(
    a.intact
      ? { id: 'audit', status: 'ok', detail: `audit hash chain intact (${a.entries} entries)` }
      : {
          id: 'audit',
          status: 'fail',
          detail: `audit hash chain BROKEN at seq ${a.brokenAt}`,
          fix: 'keyflap audit tail; see docs/ARCHITECTURE.md section 10',
        },
  );
  const pw = ctx.local.passwords();
  const pp = state?.passwordSource;
  checks.push(
    pw > 0 || pp
      ? {
          id: 'passwords',
          status: 'ok',
          detail: [
            pw > 0 ? `${pw} password item(s)` : '',
            pp ? `${sourceName(pp.kind)} source` : '',
          ]
            .filter(Boolean)
            .join(', '),
        }
      : {
          id: 'passwords',
          status: 'warn',
          detail: 'no passwords and no password source (passkeys only)',
          fix: simple ? setup : 'keyflap password add <site> (daemon stopped), or keyflap setup',
        },
  );
  return checks;
}

export const ADDRESS_UNWATCHED = "Keyflap can't watch this address: it isn't a Tailscale name";

export function approverAddressCheck(
  state: AddressState | undefined,
  o: { sys: System; m: ServiceManager; paths: ServicePaths },
): Check {
  const id = 'approver-address';
  if (!state) return { id, status: 'skip', detail: 'the signer did not answer' };
  const w = serviceAddressWords(state, o);
  switch (addressPhase(state, Date.now())) {
    case 'ok':
      return { id, status: 'ok', detail: `approval address ${w.line}` };
    case 'holding':
      return { id, status: 'warn', detail: `approval address ${w.line}`, fix: w.fix ?? '' };
    case 'latched':
    case 'paused':
      return { id, status: 'fail', detail: `approval address ${w.line}`, fix: w.fix ?? '' };
    case 'unwatched':
      return {
        id,
        status: 'warn',
        detail: ADDRESS_UNWATCHED,
        fix: `to have it watched, serve the approver with tailscale serve and re-run ${o.m.installer} with its https://<name>.ts.net:8766 origin`,
      };
  }
}

export function passwordToolCheck(
  sys: System,
  paths: ServicePaths,
  kind: 'proton-pass' | '1password' = 'proton-pass',
): Check {
  const cfg = parseJsonFile(sys.readFile(paths.signerConfig)) as {
    sources?: Record<string, { bin?: unknown; sha256?: unknown } | undefined>;
  } | null;
  const t =
    kind === '1password'
      ? { key: 'onePassword', spec: OP_TOOL, name: '1Password' }
      : { key: 'protonPass', spec: PASS_CLI_TOOL, name: 'Proton Pass' };
  const pp = cfg?.sources?.[t.key];
  if (typeof pp?.bin !== 'string') {
    return {
      id: 'password-tool',
      status: 'fail',
      detail: `${t.name} is on but ${paths.signerConfig} names no ${t.spec.command}`,
      fix: `sudo keyflap password-source add ${kind}`,
    };
  }
  const pin = typeof pp.sha256 === 'string' ? pp.sha256 : undefined;
  const r = sys.checkTool(pp.bin, t.spec, pin);
  if (!r.ok) {
    return {
      id: 'password-tool',
      status: 'fail',
      detail: `the signer refuses to run ${pp.bin}: ${r.detail}`,
      fix: r.fix,
    };
  }
  return pin
    ? { id: 'password-tool', status: 'ok', detail: `${pp.bin}: root-only path, pinned SHA-256` }
    : {
        id: 'password-tool',
        status: 'warn',
        detail: `${pp.bin}: root-only path, but no SHA-256 pinned (any root-made change runs)`,
        fix: `sudo keyflap password-source trust ${t.spec.command}`,
      };
}

async function serviceChecks(ctx: ServiceDoctorContext, read: UserRead): Promise<Check[]> {
  const { sys, paths, admin } = ctx;
  const m = requireServiceManager(sys.platform);
  const checks: Check[] = [{ id: 'mode', status: 'ok', detail: `service mode (${m.kind})` }];
  checks.push(nodeCheck(ctx.nodeVersion));
  const inactive: ServiceName[] = [];
  const inactiveDetail: string[] = [];
  for (const u of SERVICE_NAMES) {
    const r = await m.active(sys, u);
    if (!r.active) {
      inactive.push(u);
      inactiveDetail.push(`${m.unit(u)} ${r.state}`);
    }
  }
  checks.push(
    inactive.length === 0
      ? { id: 'units', status: 'ok', detail: `${SERVICE_NAMES.map(m.unit).join(', ')} active` }
      : {
          id: 'units',
          status: 'fail',
          detail: inactiveDetail.join('; '),
          fix: `${m.statusCommand(['core', 'signer', 'approver'], true)}; ${m.logsCommand('core')}`,
        },
  );
  const root = sys.uid === 0;
  if (!root) {
    checks.push({
      id: 'root',
      status: 'warn',
      detail: 'not root: the admin-socket checks are skipped',
      fix: 'sudo keyflap doctor',
    });
  }
  const hook = sys.stat(paths.hookDir);
  const owner = hook?.uid ?? -1;
  const sockets: [string, string, number, (s: { uid: number; mode: number }) => boolean][] = [
    ['intent socket', paths.intentSocket, 0o600, (s) => s.uid === owner && s.mode === 0o600],
    ['core admin socket', paths.adminSocket, 0o600, (s) => s.uid === 0 && s.mode === 0o600],
    ['signer admin socket', paths.signerAdminSocket, 0o600, (s) => s.uid === 0 && s.mode === 0o600],
  ];
  const bad: string[] = [];
  for (const [name, path, , ok] of sockets) {
    const s = sys.stat(path);
    if (!s) bad.push(`${name} missing (${path})`);
    else if (!s.isSocket || !ok(s)) bad.push(`${name} is ${s.mode.toString(8)}/uid ${s.uid}`);
  }
  checks.push(
    bad.length === 0
      ? {
          id: 'sockets',
          status: 'ok',
          detail: 'intent (yours, 0600) and admin (root, 0600) sockets',
        }
      : {
          id: 'sockets',
          status: 'fail',
          detail: bad.join('; '),
          fix: m.socketsFix,
        },
  );
  const call = async <T>(socket: string, op: string, params?: Record<string, unknown>) => {
    try {
      return { ok: true as const, v: await admin<T>(socket, op, params) };
    } catch (err) {
      return { ok: false as const, error: (err as Error).message };
    }
  };
  let mcpPort = 8765;
  let agents: AgentInfo[] = [];
  if (root) {
    const sig = await call<{ approvers: number; address?: AddressState }>(
      paths.signerAdminSocket,
      'status',
    );
    checks.push(
      sig.ok
        ? { id: 'signer', status: 'ok', detail: 'signer answers on its admin socket' }
        : {
            id: 'signer',
            status: 'fail',
            detail: `signer: ${sig.error}`,
            fix: m.logsCommand('signer'),
          },
    );
    checks.push(
      approverAddressCheck(sig.ok ? (sig.v.address ?? { kind: 'unwatched' }) : undefined, {
        sys,
        m,
        paths,
      }),
    );
    const core = await call<{ mcpUrl: string | null; signer: string }>(paths.adminSocket, 'status');
    if (core.ok && core.v.mcpUrl) mcpPort = Number(new URL(core.v.mcpUrl).port) || 8765;
    if (core.ok && core.v.signer !== 'ok') {
      checks.push({
        id: 'core-signer',
        status: 'fail',
        detail: `the core cannot reach the signer (${core.v.signer})`,
        fix: m
          .restartCommands(['signer', 'core'])
          .map((argv) => `sudo ${argv.join(' ')}`)
          .join('; '),
      });
    }
    const n = sig.ok ? sig.v.approvers : 0;
    checks.push(
      n > 0
        ? { id: 'phone', status: 'ok', detail: `${n} phone(s) paired` }
        : {
            id: 'phone',
            status: 'fail',
            detail: 'no phone paired: every sign-in would be denied',
            fix: 'sudo keyflap setup (or sudo keyflap approver pair)',
          },
    );
    const al = await call<{ agents: { id: string; name: string; revokedAt: number | null }[] }>(
      paths.adminSocket,
      'agent.list',
    );
    agents = al.ok
      ? al.v.agents.map((a) => ({ id: a.id, name: a.name, revoked: a.revokedAt !== null }))
      : [];
    const active = agents.filter((a) => !a.revoked);
    checks.push(
      active.length > 0
        ? {
            id: 'agents',
            status: 'ok',
            detail: `${active.length} agent(s): ${active.map((a) => a.name).join(', ')}`,
          }
        : {
            id: 'agents',
            status: 'fail',
            detail: 'no agents',
            fix: 'sudo keyflap setup (agent step)',
          },
    );
  } else {
    for (const id of ['signer', 'approver-address', 'phone', 'agents']) {
      checks.push({ id, status: 'skip', detail: 'needs root (sudo keyflap doctor)' });
    }
  }
  const r = await sys.http(`http://127.0.0.1:${mcpPort}/mcp`, { method: 'POST' });
  checks.push(
    r.status === 401
      ? { id: 'mcp', status: 'ok', detail: `MCP endpoint http://127.0.0.1:${mcpPort}/mcp answers` }
      : {
          id: 'mcp',
          status: 'fail',
          detail: `MCP endpoint on 127.0.0.1:${mcpPort}: ${r.status ?? r.error}`,
          fix: m.logsCommand('core'),
        },
  );
  const front = parseJsonFile(sys.readFile(paths.approverConfig));
  const coreCfg = parseJsonFile(sys.readFile(paths.coreConfig));
  const origin =
    front && typeof front === 'object' && !Array.isArray(front) && typeof front.origin === 'string'
      ? front.origin
      : null;
  checks.push(
    origin
      ? await approverOriginCheck(
          sys,
          origin,
          null,
          serveFor(
            sys,
            serviceAddress(sys, paths) ?? { origin, target: 'http://127.0.0.1:8766' },
            true,
          ),
        )
      : {
          id: 'approver-origin',
          status: 'fail',
          detail: `no approver origin in ${paths.approverConfig}`,
          fix: 'sudo install.sh … --approver-origin https://HOST:8766',
        },
  );
  if (hook && owner >= 0) {
    const insp = inspectClaude(readClaudeFiles(read, ctx.home, ctx.project), {
      project: ctx.project,
      mcpPort,
      denyDir: paths.hookDir,
      home: ctx.home,
    });
    checks.push(
      ...claudeChecks(insp, {
        activeAgents: root
          ? agents
          : insp.hookAgents.map((id) => ({ id, name: id, revoked: false })),
        denyDir: paths.hookDir,
        home: ctx.home,
        sys,
        project: ctx.project,
        tokenFile: (id) => join(paths.hookDir, `agent-${id}.token`),
      }),
    );
  }
  checks.push(
    inactive.includes('core')
      ? { id: 'chromium', status: 'skip', detail: `${m.unit('core')} is not running` }
      : { id: 'chromium', status: 'ok', detail: `${m.unit('core')} runs the managed Chromium` },
  );
  const browser =
    coreCfg && typeof coreCfg === 'object' && !Array.isArray(coreCfg) ? coreCfg.browser : null;
  const xvfb =
    browser !== null &&
    typeof browser === 'object' &&
    !Array.isArray(browser) &&
    browser.mode === 'xvfb';
  checks.push(
    m.kind === 'launchd'
      ? {
          id: 'headed',
          status: 'ok',
          detail:
            'headless browser (full Chromium, new headless mode): a macOS service has no display; human checks go to the live view on your phone',
        }
      : headedCheck(xvfb, 're-run install.sh with --xvfb (headed on a private display)'),
  );
  if (root) {
    const a = await call<{ text: string; intact: boolean }>(paths.adminSocket, 'audit.verify');
    checks.push(
      a.ok && a.v.intact
        ? { id: 'audit', status: 'ok', detail: a.v.text.trim().replace(/\.$/, '') }
        : {
            id: 'audit',
            status: 'fail',
            detail: a.ok ? a.v.text.trim() : `audit: ${a.error}`,
            fix: 'sudo keyflap audit tail',
          },
    );
    const pw = await call<{ passwords: unknown[] }>(paths.adminSocket, 'password.list');
    const pp =
      coreCfg && typeof coreCfg === 'object' && !Array.isArray(coreCfg) && coreCfg.passwordSource;
    const n = pw.ok ? pw.v.passwords.length : 0;
    if (pp) {
      const kind = (pp as { kind?: unknown }).kind === '1password' ? '1password' : 'proton-pass';
      checks.push(passwordToolCheck(sys, paths, kind));
    }
    checks.push(
      n > 0 || pp
        ? {
            id: 'passwords',
            status: 'ok',
            detail: [
              n > 0 ? `${n} password item(s)` : '',
              pp ? `${sourceName((pp as { kind?: unknown }).kind)} source` : '',
            ]
              .filter(Boolean)
              .join(', '),
          }
        : {
            id: 'passwords',
            status: 'warn',
            detail: 'no passwords and no password source (passkeys only)',
            fix: 'sudo keyflap password add <site>, or sudo keyflap setup',
          },
    );
  } else {
    for (const id of ['audit', 'passwords']) {
      checks.push({ id, status: 'skip', detail: 'needs root (sudo keyflap doctor)' });
    }
  }
  return checks;
}

export async function runChecks(ctx: DoctorContext): Promise<DoctorReport> {
  const refused: string[] = [];
  const read = userReader(ctx.sys, ctx.owner, refused);
  const checks = ctx.mode === 'dev' ? await devChecks(ctx, read) : await serviceChecks(ctx, read);
  let agents: AgentInfo[] | null = null;
  if (ctx.mode === 'dev') {
    try {
      agents = ctx.local.agents();
    } catch {
      agents = null;
    }
  }
  checks.push(
    ...hostChecks({
      sys: ctx.sys,
      read,
      home: ctx.home,
      denyDir: ctx.mode === 'dev' ? ctx.dataDir : ctx.paths.hookDir,
      agents,
    }),
  );
  checks.push(...refusedCheck(refused));
  const mode = ctx.mode === 'dev' && ctx.simple ? 'simple' : ctx.mode;
  return { mode, ok: !checks.some((c) => c.status === 'fail'), checks };
}

const MARK: Record<CheckStatus, string> = { ok: '✓', warn: '!', fail: '✗', skip: '-' };

export function formatReport(r: DoctorReport, st: TermStyle = plainStyle): string {
  const mark = (c: CheckStatus) =>
    c === 'ok'
      ? st.ok(MARK.ok)
      : c === 'fail'
        ? st.bad(MARK.fail)
        : c === 'warn'
          ? st.bold(MARK.warn)
          : st.dim(MARK.skip);
  const indent = (c: CheckStatus) => (c === 'fail' && st.level !== 0 ? ' ' : '  ');
  const lines = [
    st.level === 0
      ? `keyflap doctor (${r.mode === 'simple' ? 'simple install' : `${r.mode} mode`})`
      : st.header(`doctor · ${r.mode === 'simple' ? 'simple install' : `${r.mode} mode`}`),
  ];
  for (const c of r.checks) {
    const id = c.id.padEnd(15);
    lines.push(
      `${indent(c.status)}${mark(c.status)}${c.status === 'fail' && st.level !== 0 ? '' : ' '}${
        c.status === 'skip' ? st.dim(`${id} ${c.detail}`) : `${st.bold(id)} ${c.detail}`
      }`,
    );
    if (c.fix && (c.status === 'fail' || c.status === 'warn')) {
      lines.push(`    ${' '.repeat(15)} ${st.dim('fix:')} ${c.fix}`);
    }
  }
  const fails = r.checks.filter((c) => c.status === 'fail').length;
  const warns = r.checks.filter((c) => c.status === 'warn').length;
  lines.push(
    fails === 0
      ? `${st.ok('All checks passed')}${warns > 0 ? ` (${warns} warning${warns === 1 ? '' : 's'})` : ''}.`
      : `${st.bad(`${fails} check${fails === 1 ? '' : 's'} failed.`)}`,
  );
  return `${lines.join('\n')}\n`;
}

function sourceName(kind: unknown): string {
  return kind === '1password' ? '1Password' : kind === 'proton-pass' ? 'Proton Pass' : 'password';
}
