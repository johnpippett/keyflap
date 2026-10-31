import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import type { Attempt } from './probe/attempt.ts';

export interface ExecResult {
  status: number | null;
  stdout: string;
  stderr: string;
}

export interface ExecOpts {
  input?: string;
  timeoutMs?: number;
  check?: boolean;
}

export interface Host {
  exec(cmd: string[], opts?: ExecOpts): ExecResult;
  as(user: string, cmd: string[], opts?: Omit<ExecOpts, 'check'>): ExecResult;
}

export type Os = 'linux' | 'darwin';

export interface Layout {
  os: Os;
  node: string;
  probeDir: string;
  agentUser: string;
  users: { core: string; signer: string; web: string };
  hookDir: string;
  brokerDb: string;
  browserState: string;
  browserProfile: string;
  configDir: string;
  coreConfig: string;
  signerConfig: string;
  keyStore: string;
  kek: string;
  channelKey: string;
  sockets: {
    signer: string;
    signerAdmin: string;
    signerDir: string;
    coreAdmin: string;
    intent: string;
    approverDir: string;
    approverApi: string;
  };
  adminSocketGroup: string;
  unreadable: Record<string, Attempt>;
  present: string[];
  immutable: Record<string, Attempt>;
}

export const REPO = join(import.meta.dirname, '..', '..', '..');
export const PAGE = '/opt/keyflap/app/packages/approver/src/page';
export const NODE = '/opt/keyflap/node/bin/node';

const LINUX: Layout = {
  os: 'linux',
  node: NODE,
  probeDir: '/src/packages/isolation/test/probe',
  agentUser: 'agentuser',
  users: { core: 'keyflap-core', signer: 'keyflap-signer', web: 'keyflap-web' },
  hookDir: '/var/lib/keyflap/hook',
  brokerDb: '/var/lib/keyflap/core/broker.sqlite',
  browserState: '/var/lib/keyflap/core/browser-state',
  browserProfile: '/var/lib/keyflap/core/.config',
  configDir: '/etc/keyflap',
  coreConfig: '/etc/keyflap/core.json',
  signerConfig: '/etc/keyflap/signer.json',
  keyStore: '/var/lib/keyflap/signer/keys.enc.json',
  kek: '/etc/keyflap/credentials/kek.cred',
  channelKey: '/etc/keyflap/credentials/channel-key.cred',
  sockets: {
    signer: '/run/keyflap-signer/signer.sock',
    signerAdmin: '/run/keyflap-signer/admin.sock',
    signerDir: '/run/keyflap-signer',
    coreAdmin: '/run/keyflap/admin.sock',
    intent: '/run/keyflap/intent.sock',
    approverDir: '/run/keyflap-approver',
    approverApi: '/run/keyflap-approver/api.sock',
  },
  adminSocketGroup: 'root',
  unreadable: {
    listDataRoot: { kind: 'list', path: '/var/lib/keyflap' },
    listCore: { kind: 'list', path: '/var/lib/keyflap/core' },
    listSigner: { kind: 'list', path: '/var/lib/keyflap/signer' },
    brokerDb: { kind: 'read', path: '/var/lib/keyflap/core/broker.sqlite' },
    approverState: { kind: 'list', path: '/var/lib/keyflap/core/approver' },
    keyStore: { kind: 'read', path: '/var/lib/keyflap/signer/keys.enc.json' },
    listCredentials: { kind: 'list', path: '/etc/keyflap/credentials' },
    sealedKek: { kind: 'read', path: '/etc/keyflap/credentials/kek.cred' },
    sealedChannelKey: { kind: 'read', path: '/etc/keyflap/credentials/channel-key.cred' },
    kek: { kind: 'read', path: '/run/credentials/keyflap-signer.service/kek' },
    signerChannelKey: {
      kind: 'read',
      path: '/run/credentials/keyflap-signer.service/channel-key',
    },
    coreChannelKey: { kind: 'read', path: '/run/credentials/keyflap-core.service/channel-key' },
    coreHostToken: { kind: 'read', path: '/run/credentials/keyflap-core.service/host-token' },
    xauthority: { kind: 'read', path: '/var/lib/keyflap/core/xvfb/Xauthority' },
  },
  present: [
    '/var/lib/keyflap/core/broker.sqlite',
    '/var/lib/keyflap/signer/keys.enc.json',
    '/etc/keyflap/credentials/kek.cred',
    '/run/credentials/keyflap-signer.service/kek',
    '/run/credentials/keyflap-core.service/host-token',
  ],
  immutable: {
    createInPrefix: { kind: 'create', dir: '/opt/keyflap' },
    createInApp: { kind: 'create', dir: '/opt/keyflap/app/packages/core/src' },
    daemonTs: { kind: 'write', path: '/opt/keyflap/app/packages/core/src/daemon.ts' },
    signerMain: { kind: 'write', path: '/opt/keyflap/app/packages/signer/src/main.ts' },
    nodeBinary: { kind: 'write', path: '/opt/keyflap/node/bin/node' },
    chromium: {
      kind: 'write',
      path: '/opt/keyflap/browsers/chromium-1248/chrome-linux64/chrome',
    },
    wrapper: { kind: 'write', path: '/usr/local/bin/keyflap' },
    coreConfig: { kind: 'write', path: '/etc/keyflap/core.json' },
    signerConfig: { kind: 'write', path: '/etc/keyflap/signer.json' },
    createInEtc: { kind: 'create', dir: '/etc/keyflap' },
    coreUnit: { kind: 'write', path: '/etc/systemd/system/keyflap-core.service' },
    signerUnit: { kind: 'write', path: '/etc/systemd/system/keyflap-signer.service' },
    intentSocketUnit: { kind: 'write', path: '/etc/systemd/system/keyflap-core-intent.socket' },
    createUnit: { kind: 'create', dir: '/etc/systemd/system' },
    tmpfiles: { kind: 'write', path: '/etc/tmpfiles.d/keyflap.conf' },
  },
};

const LIB = '/Library/Keyflap';
const CREDS = `${LIB}/credentials`;
const DATA = `${LIB}/data`;
const LOGS = `${LIB}/log`;
const CHROMIUM_APP =
  '/opt/keyflap/browsers/chromium-1248/chrome-mac-arm64/Google Chrome for Testing.app';

const DARWIN: Layout = {
  os: 'darwin',
  node: NODE,
  probeDir: join(REPO, 'packages/isolation/test/probe'),
  agentUser: '_kfprobe',
  users: { core: '_keyflap-core', signer: '_keyflap-signer', web: '_keyflap-web' },
  hookDir: `${LIB}/hook`,
  brokerDb: `${DATA}/core/broker.sqlite`,
  browserState: `${DATA}/core/browser-state`,
  browserProfile: `${DATA}/core/tmp`,
  configDir: `${LIB}/etc`,
  coreConfig: `${LIB}/etc/core.json`,
  signerConfig: `${LIB}/etc/signer.json`,
  keyStore: `${DATA}/signer/keys.enc.json`,
  kek: `${CREDS}/signer/kek`,
  channelKey: `${CREDS}/signer/channel-key`,
  sockets: {
    signer: `${LIB}/run/signer/signer.sock`,
    signerAdmin: `${LIB}/run/signer/admin.sock`,
    signerDir: `${LIB}/run/signer`,
    coreAdmin: `${LIB}/run/core/admin.sock`,
    intent: `${LIB}/run/core/intent.sock`,
    approverDir: `${LIB}/run/approver`,
    approverApi: `${LIB}/run/approver/api.sock`,
  },
  adminSocketGroup: 'daemon',
  unreadable: {
    listDataRoot: { kind: 'list', path: DATA },
    listCore: { kind: 'list', path: `${DATA}/core` },
    listSigner: { kind: 'list', path: `${DATA}/signer` },
    listApproverData: { kind: 'list', path: `${DATA}/approver` },
    brokerDb: { kind: 'read', path: `${DATA}/core/broker.sqlite` },
    approverState: { kind: 'list', path: `${DATA}/core/approver` },
    keyStore: { kind: 'read', path: `${DATA}/signer/keys.enc.json` },
    coreTmp: { kind: 'list', path: `${DATA}/core/tmp` },
    listCredentials: { kind: 'list', path: CREDS },
    listSignerCredentials: { kind: 'list', path: `${CREDS}/signer` },
    listCoreCredentials: { kind: 'list', path: `${CREDS}/core` },
    listApproverCredentials: { kind: 'list', path: `${CREDS}/approver` },
    kek: { kind: 'read', path: `${CREDS}/signer/kek` },
    signerChannelKey: { kind: 'read', path: `${CREDS}/signer/channel-key` },
    coreChannelKey: { kind: 'read', path: `${CREDS}/core/channel-key` },
    coreHostToken: { kind: 'read', path: `${CREDS}/core/host-token` },
    listLogs: { kind: 'list', path: LOGS },
    listCoreLog: { kind: 'list', path: `${LOGS}/core` },
    listSignerLog: { kind: 'list', path: `${LOGS}/signer` },
    listApproverLog: { kind: 'list', path: `${LOGS}/approver` },
    coreLog: { kind: 'read', path: `${LOGS}/core/core.log` },
    signerLog: { kind: 'read', path: `${LOGS}/signer/signer.log` },
    approverLog: { kind: 'read', path: `${LOGS}/approver/approver.log` },
  },
  present: [
    `${DATA}/core/broker.sqlite`,
    `${DATA}/signer/keys.enc.json`,
    `${CREDS}/signer/kek`,
    `${CREDS}/signer/channel-key`,
    `${CREDS}/core/channel-key`,
    `${CREDS}/core/host-token`,
    `${LOGS}/core/core.log`,
  ],
  immutable: {
    createInPrefix: { kind: 'create', dir: '/opt/keyflap' },
    createInApp: { kind: 'create', dir: '/opt/keyflap/app/packages/core/src' },
    daemonTs: { kind: 'write', path: '/opt/keyflap/app/packages/core/src/daemon.ts' },
    signerMain: { kind: 'write', path: '/opt/keyflap/app/packages/signer/src/main.ts' },
    nodeBinary: { kind: 'write', path: NODE },
    launcher: { kind: 'write', path: '/opt/keyflap/libexec/keyflap-launch' },
    createInLibexec: { kind: 'create', dir: '/opt/keyflap/libexec' },
    createInTools: { kind: 'create', dir: '/opt/keyflap/tools' },
    chromium: {
      kind: 'write',
      path: `${CHROMIUM_APP}/Contents/MacOS/Google Chrome for Testing`,
    },
    wrapper: { kind: 'write', path: '/usr/local/bin/keyflap' },
    createInWrapperDir: { kind: 'create', dir: '/usr/local/bin' },
    coreConfig: { kind: 'write', path: `${LIB}/etc/core.json` },
    signerConfig: { kind: 'write', path: `${LIB}/etc/signer.json` },
    approverConfig: { kind: 'write', path: `${LIB}/etc/approver.json` },
    createInEtc: { kind: 'create', dir: `${LIB}/etc` },
    createInLibrary: { kind: 'create', dir: LIB },
    createInRun: { kind: 'create', dir: `${LIB}/run` },
    createInCoreRun: { kind: 'create', dir: `${LIB}/run/core` },
    corePlist: { kind: 'write', path: '/Library/LaunchDaemons/com.keyflap.core.plist' },
    signerPlist: { kind: 'write', path: '/Library/LaunchDaemons/com.keyflap.signer.plist' },
    approverPlist: { kind: 'write', path: '/Library/LaunchDaemons/com.keyflap.approver.plist' },
    createPlist: { kind: 'create', dir: '/Library/LaunchDaemons' },
  },
};

export const L: Layout = process.platform === 'darwin' ? DARWIN : LINUX;

export const LABELS = {
  core: 'com.keyflap.core',
  signer: 'com.keyflap.signer',
  approver: 'com.keyflap.approver',
} as const;

export function darwinHost(): Host {
  const run = (argv: string[], opts: ExecOpts = {}): ExecResult => {
    const r = spawnSync('sudo', ['-n', ...argv], {
      cwd: '/',
      input: opts.input,
      encoding: 'utf8',
      timeout: opts.timeoutMs ?? 120_000,
      maxBuffer: 64 * 1024 * 1024,
    });
    const res = { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
    if (opts.check && res.status !== 0) {
      throw new Error(`${argv.join(' ')} failed (${res.status}): ${res.stderr || res.stdout}`);
    }
    return res;
  };
  return {
    exec: (cmd, opts) => run(['-H', '--', ...cmd], opts),
    as: (user, cmd, opts) => run(['-H', '-u', user, '--', ...cmd], opts),
  };
}

export function owner(h: Host, path: string): string {
  const fmt =
    L.os === 'darwin' ? ['stat', '-f', '%Su:%Sg %Lp', path] : ['stat', '-c', '%U:%G %a', path];
  return h.exec(fmt, { check: true }).stdout.trim();
}

export function sha256(h: Host, path: string): string {
  const cmd = L.os === 'darwin' ? ['shasum', '-a', '256', path] : ['sha256sum', path];
  return h.exec(cmd, { check: true }).stdout.split(' ')[0] ?? '';
}

export function launchdPid(h: Host, label: string): number {
  const out = h.exec(['launchctl', 'print', `system/${label}`]).stdout;
  return Number(/\n\s*pid = (\d+)/.exec(out)?.[1] ?? 0);
}

export function servicePids(h: Host): { core: number; signer: number; approver: number } {
  if (L.os === 'darwin') {
    return {
      core: launchdPid(h, LABELS.core),
      signer: launchdPid(h, LABELS.signer),
      approver: launchdPid(h, LABELS.approver),
    };
  }
  const mainPid = (unit: string) =>
    Number(
      h
        .exec(['systemctl', 'show', '-p', 'MainPID', '--value', unit], { check: true })
        .stdout.trim(),
    );
  return {
    core: mainPid('keyflap-core.service'),
    signer: mainPid('keyflap-signer.service'),
    approver: mainPid('keyflap-approver.service'),
  };
}

export function waitReady(h: Host, ms = 90_000): void {
  const deadline = Date.now() + ms;
  let last = '';
  while (Date.now() < deadline) {
    const r = h.exec(['/usr/local/bin/keyflap', 'status', '--json'], { timeoutMs: 30_000 });
    last = r.stdout + r.stderr;
    if (r.status === 0 && r.stdout.includes('"signer": "ok"')) return;
    spawnSync('sleep', ['0.5']);
  }
  throw new Error(`keyflap did not become ready: ${last.slice(-2000)}`);
}

export function restartCore(h: Host): void {
  if (L.os === 'darwin') {
    h.exec(['launchctl', 'kickstart', '-k', `system/${LABELS.core}`], {
      check: true,
      timeoutMs: 120_000,
    });
  } else {
    h.exec(['systemctl', 'restart', 'keyflap-core'], { check: true, timeoutMs: 120_000 });
  }
  waitReady(h);
}

export function auditPayloads(h: Host, type: string): Record<string, unknown>[] {
  const query = `SELECT payload_json FROM audit WHERE event_type = '${type}' ORDER BY seq`;
  const script = `const {DatabaseSync}=require('node:sqlite');const db=new DatabaseSync(${JSON.stringify(L.brokerDb)},{readOnly:true});console.log(JSON.stringify(db.prepare(${JSON.stringify(query)}).all().map(r=>JSON.parse(r.payload_json))))`;
  const r = h.exec([NODE, '--disable-warning=ExperimentalWarning', '-e', script], { check: true });
  return JSON.parse(r.stdout) as Record<string, unknown>[];
}

export function auditTail(h: Host, n: number): string {
  const query = `SELECT event_type, payload_json FROM audit ORDER BY seq DESC LIMIT ${n}`;
  const script = `const {DatabaseSync}=require('node:sqlite');const db=new DatabaseSync(${JSON.stringify(L.brokerDb)},{readOnly:true});for(const r of db.prepare(${JSON.stringify(query)}).all().reverse())console.log(r.event_type,r.payload_json)`;
  return h.exec([NODE, '--disable-warning=ExperimentalWarning', '-e', script]).stdout;
}

export function auditEvents(h: Host, types: string[]): string[] {
  const query = `SELECT event_type FROM audit WHERE event_type IN (${types.map((t) => `'${t}'`).join(',')}) ORDER BY seq`;
  const script = `const {DatabaseSync}=require('node:sqlite');const db=new DatabaseSync(${JSON.stringify(L.brokerDb)},{readOnly:true});console.log(JSON.stringify(db.prepare(${JSON.stringify(query)}).all().map(r=>r.event_type)))`;
  const r = h.exec([NODE, '--disable-warning=ExperimentalWarning', '-e', script], { check: true });
  return JSON.parse(r.stdout) as string[];
}
