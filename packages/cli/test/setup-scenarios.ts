import { encodeQr, renderQrTerminal } from '@aab/approver';
import type { DoctorReport } from '../src/doctor.ts';
import {
  DARWIN_SERVICE_PATHS,
  LINUX_SERVICE_PATHS,
  type ServicePaths,
} from '../src/service/paths.ts';
import { emptyState, type SetupState, saveState } from '../src/setup/state.ts';
import { planClaudeConfig, type SetupContext } from '../src/setup/steps.ts';
import type { SetupUi } from '../src/setup/ui.ts';
import { AGENT_ID, AGENT_TOKEN, FakeBackend, FakeSystem } from './setup-fakes.ts';

export const SCENARIOS = ['mac-fresh', 'linux-fresh', 'mac-rerun', 'mac-agents'] as const;
export type ScenarioName = (typeof SCENARIOS)[number];
export type Platform = 'darwin' | 'linux';

export interface CannedAnswer {
  q: RegExp;
  a: string;
}

export interface Scenario {
  ctx: SetupContext;
  sys: FakeSystem;
  backend: FakeBackend;
  mode: string;
  answers: CannedAnswer[];
  pairingLink: string;
  secrets: string[];
}

export interface ScenarioOptions {
  ui: SetupUi;
  platform?: Platform;
  delay?: (ms: number, signal?: AbortSignal) => Promise<void>;
}

export const realDelay = (ms: number, signal?: AbortSignal): Promise<void> =>
  new Promise((resolve) => {
    const t = setTimeout(resolve, ms);
    signal?.addEventListener('abort', () => {
      clearTimeout(t);
      resolve();
    });
  });

const noDelay = async () => {};

const APPLE_EXPORT = [
  'Title,URL,Username,Password,Notes,OTPAuth',
  'GitHub,https://github.com/login,sam,preview-gh-pw,,',
  'Linear,https://linear.app/login,sam@example.com,preview-linear-pw,,',
  'Example,https://app.example.com/,sam,preview-ex-pw,,otpauth://totp/x?secret=JBSWY3DPEHPK3PXP',
  '',
].join('\n');

const SITE_PASSWORD = 'preview-site-pw';
const SITE_TOTP = 'KRSXG5CTMVRXEZLUKN2XAZLSKNSWK3TU';
const RERUN_TOKEN = `aab_agent_${'P'.repeat(43)}`;
const CODEX_TOKEN = `aab_agent_${'1'.repeat(43)}`;
const PAIRING_CODE = 'PREVIEW-not-a-real-pairing-code-0000000000';

export function scenarioPlatform(name: ScenarioName, override?: Platform): Platform {
  return override ?? (name.startsWith('mac') ? 'darwin' : 'linux');
}

export function doctorReport(
  platform: Platform,
  fresh: boolean,
  origin: string,
  stored: number,
  codex: boolean,
): DoctorReport {
  const units =
    platform === 'darwin'
      ? 'com.keyflap.signer, com.keyflap.core, com.keyflap.approver active'
      : 'keyflap-signer, keyflap-core, keyflap-approver active';
  const checks: DoctorReport['checks'] = [
    {
      id: 'mode',
      status: 'ok',
      detail: `service mode (${platform === 'darwin' ? 'launchd' : 'systemd'})`,
    },
    { id: 'units', status: 'ok', detail: units },
    { id: 'sockets', status: 'ok', detail: 'intent (yours, 0600) and admin (root, 0600) sockets' },
    { id: 'signer', status: 'ok', detail: 'signer answers on its admin socket' },
    { id: 'mcp', status: 'ok', detail: 'MCP endpoint http://127.0.0.1:8765/mcp answers' },
    { id: 'approver-origin', status: 'ok', detail: `approver page answers at ${origin}` },
    { id: 'phone', status: 'ok', detail: '1 phone(s) paired' },
    {
      id: 'agents',
      status: 'ok',
      detail: codex ? '2 active agents (claude-code, codex)' : '1 active agent (claude-code)',
    },
    { id: 'claude-mcp', status: 'ok', detail: 'keyflap MCP server points at this broker' },
    { id: 'claude-hook', status: 'ok', detail: `UserPromptSubmit hook for agent ${AGENT_ID}` },
    { id: 'claude-deny', status: 'ok', detail: 'the hook dir is denied to the model' },
    ...(codex
      ? ([
          { id: 'codex-hook', status: 'ok', detail: 'UserPromptSubmit hook for agent codex' },
          { id: 'codex-deny', status: 'ok', detail: 'a permission profile denies the data dir' },
        ] as const)
      : []),
    { id: 'chromium', status: 'ok', detail: 'Chromium launches' },
    platform === 'linux'
      ? {
          id: 'headed',
          status: 'warn',
          detail: 'headless Chromium: some sites block it',
          fix: 're-run install.sh with --xvfb',
        }
      : { id: 'headed', status: 'ok', detail: 'headless (by design on a Mac)' },
    { id: 'audit', status: 'ok', detail: `audit hash chain intact (${fresh ? 9 : 41} entries)` },
    { id: 'passwords', status: 'ok', detail: `${stored} password(s) stored` },
  ];
  return { mode: 'service', ok: true, checks };
}

export function scenario(name: ScenarioName, o: ScenarioOptions): Scenario {
  const platform = scenarioPlatform(name, o.platform);
  const delay = o.delay ?? noDelay;
  const fresh = name !== 'mac-rerun';
  const codex = name === 'mac-agents';
  const paths: ServicePaths = platform === 'darwin' ? DARWIN_SERVICE_PATHS : LINUX_SERVICE_PATHS;
  const user =
    platform === 'darwin'
      ? { uid: 501, gid: 20, name: 'sam', home: '/Users/sam' }
      : { uid: 1000, gid: 1000, name: 'sam', home: '/home/sam' };
  const machine = platform === 'darwin' ? 'sams-macbook-pro' : 'devbox';
  const origin = `https://${machine}.tail1a2b3c.ts.net:8766`;
  const pairingLink = `${origin}/pair#${PAIRING_CODE}`;

  const sys = new FakeSystem();
  sys.platform = platform;
  sys.uid = 0;
  sys.gid = 0;
  sys.cwd = user.home;
  sys.env = { SUDO_UID: String(user.uid), HOME: '/var/root' };
  sys.dir(user.home, 0o750, user.uid);
  sys.dir(`${user.home}/Downloads`, 0o700, user.uid);
  if (codex) {
    sys.dir(`${user.home}/.claude`, 0o700, user.uid);
    sys.dir(`${user.home}/.codex`, 0o700, user.uid);
  }
  sys.file(`${user.home}/Downloads/Passwords.csv`, APPLE_EXPORT, 0o600, user.uid);
  for (const d of [paths.coreConfig, paths.signerConfig, paths.approverConfig]) {
    sys.dir(d.slice(0, d.lastIndexOf('/')), 0o755, 0);
  }
  sys.file(paths.approverConfig, JSON.stringify({ origin }), 0o644, 0);
  sys.file(paths.coreConfig, JSON.stringify({ passwordSource: null }), 0o644, 0);
  sys.file(paths.signerConfig, JSON.stringify({ sources: {} }), 0o600, 0);
  sys.dir(paths.hookDir, 0o700, user.uid);
  sys.exec_ = (cmd, args) => {
    if (cmd === 'launchctl' && args[0] === 'print') {
      return { code: 0, stdout: '\tstate = running\n', stderr: '' };
    }
    if (cmd === 'systemctl' && args[0] === 'is-active')
      return { code: 0, stdout: 'active\n', stderr: '' };
    return { code: 1, stdout: '', stderr: 'not available in the preview' };
  };
  sys.http_ = (url) =>
    url.startsWith(origin) ? { status: 200 } : { status: null, error: 'ECONNREFUSED' };
  const exec = sys.exec.bind(sys);
  sys.exec = async (cmd, args, opts) => {
    await delay(350);
    return exec(cmd, args, opts);
  };
  const http = sys.http.bind(sys);
  sys.http = async (url, opts) => {
    await delay(900);
    return http(url, opts);
  };

  const backend = new FakeBackend(sys);
  backend.kind = 'service';
  backend.stateDir = paths.hookDir;
  backend.denyDir = paths.hookDir;
  backend.fileOwner = { uid: user.uid, gid: user.gid };
  backend.user = user;
  backend.hookCommand = (id) => `${paths.wrapper} hook claude-code --agent ${id} --service`;
  backend.headersCommand = (id) => `${paths.wrapper} mcp-headers --agent ${id} --service`;
  backend.storeAgentToken = (agentId, token) => {
    const path = `${paths.hookDir}/agent-${agentId}.token`;
    sys.writeUserFile(path, `${token}\n`, 0o600, backend.fileOwner);
    backend.tokens.add(agentId);
    return path;
  };
  backend.pair = async (p) => {
    backend.pairCalls.push(p);
    await p.onOpen(pairingLink);
    await delay(4_000, p.signal);
    if (p.signal.aborted) return 'aborted';
    backend.paired++;
    return 'paired';
  };

  const state: SetupState = emptyState(8765);
  if (!fresh) {
    backend.paired = 1;
    backend.agents.push({ id: AGENT_ID, name: 'claude-code', revoked: false });
    backend.storeAgentToken(AGENT_ID, RERUN_TOKEN);
    backend.passwords.push(
      { site: 'github.com', username: 'sam', password: 'x', totp: null },
      { site: 'linear.app', username: 'sam@example.com', password: 'x', totp: null },
      { site: 'example.com', username: 'sam', password: 'x', totp: 'x' },
    );
    const actions = planClaudeConfig({
      sys,
      scope: 'user',
      project: user.home,
      home: user.home,
      cfg: {
        mcpUrl: 'http://127.0.0.1:8765/mcp',
        headersCommand: backend.headersCommand(AGENT_ID),
        hookCommand: backend.hookCommand(AGENT_ID),
        denyDir: paths.hookDir,
        home: user.home,
      },
      claudeCli: null,
      cliHasEntry: false,
      owner: backend.fileOwner,
    });
    for (const a of actions) {
      if (a.kind !== 'file') continue;
      sys.mkdirUser(a.path.slice(0, a.path.lastIndexOf('/')), 0o755, backend.fileOwner);
      sys.writeUserFile(a.path, a.after, 0o644, backend.fileOwner);
    }
    state.claudeCode = [{ agentId: AGENT_ID, scope: 'user', project: null }];
    saveState(sys, paths.hookDir, state, backend.fileOwner);
  }

  const ctx: SetupContext = {
    sys,
    prompt: o.ui.prompt,
    out: o.ui.out,
    ui: o.ui,
    backend,
    state,
    dataDir: paths.hookDir,
    defaults: { dataDir: paths.hookDir, mcpPort: 8765 },
    paths,
    simple: null,
    host: null,
    qr: (url) => ({ code: encodeQr(url), printed: renderQrTerminal(encodeQr(url)) }),
    pairingTimeoutMs: 600_000,
    chromium: () => ({ path: '/opt/keyflap/chromium', present: true }),
    doctor: async () => {
      await delay(1_400);
      return doctorReport(platform, fresh, origin, backend.passwords.length, codex);
    },
    secretEnv: {},
    startDaemon: null,
    interruptible: async (fn) => {
      const ac = new AbortController();
      const onInt = () => ac.abort();
      process.on('SIGINT', onInt);
      try {
        return await fn(ac.signal);
      } finally {
        process.off('SIGINT', onInt);
      }
    },
  };

  const answers: CannedAnswer[] = fresh
    ? [
        { q: /^Pair a phone now\?/, a: '' },
        { q: /^Set up an agent for Claude Code\?/, a: '' },
        { q: /^Agent name/, a: '' },
        { q: /^Write the Claude Code config/, a: '' },
        { q: /^Which Claude Code config\?/, a: '' },
        { q: /^Apply these changes\?/, a: 'y' },
        ...(codex
          ? [
              { q: /^Set up an agent for Codex\?/, a: '' },
              { q: /^Agent name/, a: '' },
              { q: /^Write the Codex config/, a: '' },
              { q: /^Apply these changes\?/, a: 'y' },
            ]
          : []),
        ...(platform === 'darwin'
          ? [
              { q: /^Add a credential\?/, a: '' },
              { q: /^Export file/, a: '~/Downloads/Passwords.csv' },
              { q: /^Sites your agents need/, a: '' },
              { q: /^Store 3 logins in Keyflap\?/, a: 'y' },
            ]
          : [
              { q: /^Add a credential\?/, a: '1' },
              { q: /^Site/, a: 'github.com' },
              { q: /^Username/, a: 'sam' },
              { q: /one-time code \(TOTP\)\?/, a: 'y' },
              { q: /^Password/, a: SITE_PASSWORD },
              { q: /^TOTP secret/, a: SITE_TOTP },
            ]),
        { q: /^Add another credential\?/, a: '' },
      ]
    : [
        { q: /^Pair another phone/, a: '' },
        { q: /^Set up an agent for Claude Code\?/, a: '' },
        { q: /^Agent name/, a: '' },
        { q: /^Use the existing agent/, a: '' },
        { q: /^Write the Claude Code config/, a: '' },
        { q: /^Which Claude Code config\?/, a: '' },
        { q: /^Apply these changes\?/, a: 'y' },
        { q: /^Add a credential\?/, a: '' },
      ];

  return {
    ctx,
    sys,
    backend,
    mode: 'service mode',
    answers,
    pairingLink,
    secrets: [
      PAIRING_CODE,
      SITE_PASSWORD,
      SITE_TOTP,
      'preview-gh-pw',
      'preview-linear-pw',
      'preview-ex-pw',
      'JBSWY3DPEHPK3PXP',
      AGENT_TOKEN,
      RERUN_TOKEN,
      CODEX_TOKEN,
    ],
  };
}
