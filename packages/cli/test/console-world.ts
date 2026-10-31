import { randomUUID } from 'node:crypto';
import { rmSync } from 'node:fs';
import type { Server } from 'node:net';
import { join } from 'node:path';
import { encodeQr, renderQrTerminal, type TermStyle } from '@aab/approver';
import {
  AgentRegistry,
  ALL_AGENTS,
  ALL_AGENTS_OPTIN,
  AuditLog,
  addPasswordItem,
  CredentialRepo,
  type Daemon,
  openDb,
  PersistOptins,
  PolicyStore,
  registerCoreAdminOps,
} from '@aab/core';
import { AdminOps, adminCall, startAdminServer } from '@aab/signer/admin-wire';
import type { AddressState } from '@aab/signer/approver-address';
import { type Dispatch, statusSnapshot } from '../src/console/run.ts';
import { serviceAddressWords } from '../src/service/address.ts';
import { registerCliAdminOps } from '../src/service/admin-cli-ops.ts';
import { runServiceCommand } from '../src/service/cli.ts';
import { requireServiceManager } from '../src/service/manager.ts';
import {
  DARWIN_SERVICE_PATHS,
  LINUX_SERVICE_PATHS,
  type ServicePaths,
} from '../src/service/paths.ts';
import { serviceBackend } from '../src/setup/backend.ts';
import { emptyState } from '../src/setup/state.ts';
import type { SetupContext } from '../src/setup/steps.ts';
import type { SetupUi } from '../src/setup/ui.ts';
import { tmpDir } from './helpers.ts';
import { FakeSystem } from './setup-fakes.ts';
import { doctorReport } from './setup-scenarios.ts';

export type Delay = (ms: number, signal?: AbortSignal) => Promise<void>;

export interface Phone {
  credentialId: string;
  origin: string;
  createdAt: number;
}

export interface World {
  sys: FakeSystem;
  paths: ServicePaths;
  ctx: SetupContext;
  dispatch: Dispatch;
  snapshot: (via?: Dispatch) => ReturnType<typeof statusSnapshot>;
  phones: Phone[];
  address: { state: AddressState };
  agents: AgentRegistry;
  passwords: () => { id: string; domain: string; username: string | null }[];
  policies: PolicyStore;
  optins: PersistOptins;
  clears: { agent: string; site: string | null }[];
  tokens: string[];
  secrets: string[];
  close(): Promise<void>;
}

const NOW = Date.UTC(2026, 9, 30, 9, 0, 0);
const DAY = 86_400_000;

export async function consoleWorld(o: {
  ui: SetupUi;
  style?: TermStyle;
  platform?: 'darwin' | 'linux';
  delay?: Delay;
  passwords?: string[];
}): Promise<World> {
  const platform = o.platform ?? 'darwin';
  const delay: Delay = o.delay ?? (async () => {});
  const dir = tmpDir();
  const base = platform === 'darwin' ? DARWIN_SERVICE_PATHS : LINUX_SERVICE_PATHS;
  const paths: ServicePaths = {
    ...base,
    adminSocket: join(dir, 'core.sock'),
    signerAdminSocket: join(dir, 'signer.sock'),
  };
  const user =
    platform === 'darwin'
      ? { uid: 501, gid: 20, name: 'sam', home: '/Users/sam' }
      : { uid: 1000, gid: 1000, name: 'sam', home: '/home/sam' };
  const machine = platform === 'darwin' ? 'sams-macbook-pro' : 'devbox';
  const origin = `https://${machine}.tail1a2b3c.ts.net:8766`;

  const sys = new FakeSystem();
  sys.platform = platform;
  sys.uid = 0;
  sys.gid = 0;
  sys.cwd = user.home;
  sys.t = NOW;
  sys.env = { SUDO_UID: String(user.uid), HOME: '/var/root' };
  sys.dir(user.home, 0o750, user.uid);
  sys.dir(`${user.home}/Downloads`, 0o700, user.uid);
  for (const d of [paths.coreConfig, paths.signerConfig, paths.approverConfig]) {
    sys.dir(d.slice(0, d.lastIndexOf('/')), 0o755, 0);
  }
  sys.file(paths.approverConfig, JSON.stringify({ origin }), 0o644, 0);
  sys.file(paths.coreConfig, JSON.stringify({ passwordSource: null }), 0o644, 0);
  sys.file(
    paths.signerConfig,
    JSON.stringify({ sources: {}, approverAddress: { origin, target: 'http://127.0.0.1:8766' } }),
    0o600,
    0,
  );
  sys.dir(paths.hookDir, 0o700, user.uid);
  sys.file('/etc/passwd', `sam:x:${user.uid}:${user.gid}::${user.home}:/bin/zsh\n`, 0o644, 0);
  sys.exec_ = (cmd, args) => {
    if (cmd === '/usr/bin/id') {
      return {
        code: 0,
        stdout: `sam:*:${user.uid}:${user.gid}::0:0:Sam:${user.home}:/bin/zsh\n`,
        stderr: '',
      };
    }
    return { code: 1, stdout: '', stderr: `${cmd} ${args[0] ?? ''}: not available in the preview` };
  };
  const sleep = sys.sleep.bind(sys);
  sys.sleep = async (ms) => {
    await delay(Math.min(ms, 400));
    return sleep(ms);
  };

  const db = openDb(join(dir, 'broker.sqlite'));
  const registry = new AgentRegistry(db);
  const optins = new PersistOptins(db);
  const policies = new PolicyStore(db);
  const clears: World['clears'] = [];
  const tokens: string[] = [];
  const items = new Set<string>();
  const signer = {
    ping: async () => {},
    storeItem: async () => {
      const itemId = randomUUID();
      items.add(itemId);
      return { itemId };
    },
    deleteItem: async (id: string) => ({ deleted: items.delete(id) }),
  };
  const daemon = {
    db,
    registry: {
      list: () => registry.list(),
      byId: (id: string) => registry.byId(id),
      revoke: (id: string) => registry.revoke(id),
      add: (name: string) => {
        const a = registry.add(name);
        tokens.push(a.token);
        return a;
      },
    },
    broker: { audit: new AuditLog(db) },
    signer: { client: signer },
    optins,
    mcpUrl: 'http://127.0.0.1:8765/mcp',
    sessions: {
      clearAgent: async (agent: string) => {
        clears.push({ agent, site: null });
        return { cookies: 12, pages: 1 };
      },
      clearSite: async (agent: string, site: string) => {
        clears.push({ agent, site });
        return { cookies: 3, pages: 0 };
      },
      refilter: async () => {},
    },
  } as unknown as Daemon;

  for (const name of ['claude-code', 'codex']) tokens.push(registry.add(name).token);
  const seeds = [
    { site: 'github.com', username: 'sam', password: 'world-gh-pw' },
    { site: 'linear.app', username: 'sam@example.com', password: 'world-linear-pw' },
    {
      site: 'https://app.example.com/',
      username: 'sam',
      password: 'world-ex-pw',
      totp: { secret: 'JBSWY3DPEHPK3PXP' },
    },
  ];
  for (const s of seeds) await addPasswordItem({ signer, db, now: () => NOW }, s);
  for (const site of o.passwords ?? []) {
    await addPasswordItem(
      { signer, db, now: () => NOW },
      { site, username: 'sam', password: 'world-extra-pw' },
    );
  }
  policies.set('bank.example', ALL_AGENTS, { mode: 'ask-strong' });
  optins.add(ALL_AGENTS_OPTIN, 'mail.example', 'admin');

  const phones: Phone[] = [{ credentialId: 'cred-phone-1', origin, createdAt: NOW - 3 * DAY }];
  const address: { state: AddressState } = { state: { kind: 'ok', checkedAt: NOW } };
  let pairing = false;

  const core = new AdminOps();
  registerCoreAdminOps(core, daemon, {
    intentSocketPath: '/run/keyflap/intent.sock',
    passwordSource: null,
  });
  registerCliAdminOps(core, db, dir);
  core.register('approver.pair', () => {
    pairing = true;
    return { url: `${origin}/pair#PREVIEW-not-a-real-pairing-code`, origin, validMinutes: 10 };
  });
  const signerOps = new AdminOps()
    .register('status', () => {
      if (pairing && sys.now() > NOW + 2_000) {
        pairing = false;
        phones.push({
          credentialId: `cred-phone-${phones.length + 1}`,
          origin,
          createdAt: sys.now(),
        });
      }
      return { approvers: phones.length, phoneLatched: false, sources: [], address: address.state };
    })
    .register('approver.list', () => ({ approvers: phones, native: [] }))
    .register('approver.remove', (p) => {
      const i = phones.findIndex((x) => x.credentialId === p.credentialId);
      if (i >= 0) phones.splice(i, 1);
      return { removed: i >= 0 };
    })
    .register('approver.address.clear', () => ({ state: address.state }));
  const servers: Server[] = [
    await startAdminServer({ listen: { path: paths.adminSocket }, ops: core }),
    await startAdminServer({ listen: { path: paths.signerAdminSocket }, ops: signerOps }),
  ];

  const m = requireServiceManager(platform);
  const dispatch: Dispatch = async (cmd, out) => {
    await delay(150);
    return runServiceCommand(cmd, out, paths, m, sys);
  };
  const admin = <T>(socket: string, op: string, params?: Record<string, unknown>) =>
    adminCall<T>(socket, op, params ?? {});
  const backend = await serviceBackend({ sys, paths, admin });
  const ctx: SetupContext = {
    sys,
    prompt: o.ui.prompt,
    out: o.ui.out,
    ui: o.ui,
    ...(o.style ? { style: o.style } : {}),
    backend,
    state: emptyState(8765),
    dataDir: paths.hookDir,
    defaults: { dataDir: paths.hookDir, mcpPort: 8765 },
    paths,
    simple: null,
    host: null,
    qr: (url) => ({ code: encodeQr(url), printed: renderQrTerminal(encodeQr(url)) }),
    pairingTimeoutMs: 600_000,
    chromium: () => ({ path: '/opt/keyflap/chromium', present: true }),
    doctor: async () => {
      await delay(1_200);
      return doctorReport(platform, false, origin, seeds.length, false);
    },
    secretEnv: {},
    startDaemon: null,
    interruptible: (fn) => fn(new AbortController().signal),
  };

  return {
    sys,
    paths,
    ctx,
    dispatch,
    snapshot: (via) =>
      statusSnapshot(via ?? dispatch, (state) => serviceAddressWords(state, { sys, m, paths })),
    phones,
    address,
    agents: registry,
    passwords: () =>
      new CredentialRepo(db)
        .allPasswords()
        .map((r) => ({ id: r.id, domain: r.registrable_domain, username: r.username })),
    policies,
    optins,
    clears,
    tokens,
    secrets: [
      'world-gh-pw',
      'world-linear-pw',
      'world-ex-pw',
      'world-extra-pw',
      'JBSWY3DPEHPK3PXP',
    ],
    async close() {
      for (const s of servers) await new Promise((r) => s.close(r));
      db.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}
