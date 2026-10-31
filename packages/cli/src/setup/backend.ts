import { join } from 'node:path';
import type { AgentListing } from '@aab/core';
import {
  headersCommand as devHeadersCommand,
  hookCommand as devHookCommand,
  shellQuote,
} from '../agent.ts';
import { devAgentTokenPath, isAgentIdShape, serviceAgentTokenPath } from '../mcp-headers.ts';
import { addressRefusalText, clearApproverAddress } from '../service/address.ts';
import { requireServiceManager } from '../service/manager.ts';
import type { ServicePaths } from '../service/paths.ts';
import type { FileOwner, System } from './system.ts';
import { lookupUser, type UserInfo } from './users.ts';

export type { UserInfo } from './users.ts';

export interface AgentInfo {
  id: string;
  name: string;
  revoked: boolean;
}

export interface PairOptions {
  origin: string;
  listen: { host: string; port: number };
  tls: { cert: string; key: string } | null;
  onOpen: (url: string) => Promise<void>;
  timeoutMs: number;
  signal: AbortSignal;
}

export type PairResult = 'paired' | 'timeout' | 'aborted';

export interface PasswordItem {
  site: string;
  username: string | null;
  password: string;
  totp: string | null;
}

export interface StoredLogin {
  domain: string;
  username: string | null;
  native: boolean;
}

interface PasswordListRow {
  registrable_domain: string;
  username: string | null;
  source: string;
}

const storedLogin = (r: PasswordListRow): StoredLogin => ({
  domain: r.registrable_domain,
  username: r.username,
  native: r.source === 'signer',
});

export interface Backend {
  kind: 'dev' | 'service';
  stateDir: string;
  fileOwner: FileOwner;
  denyDir: string;
  user: UserInfo;
  daemonRunning(): Promise<boolean>;
  mcpPort(): Promise<number>;
  listAgents(): Promise<AgentInfo[]>;
  createAgent(name: string): Promise<{ id: string; name: string; token: string }>;
  storeAgentToken(agentId: string, token: string): string;
  hasAgentToken(agentId: string): boolean;
  hookCommand(agentId: string): string;
  headersCommand(agentId: string): string;
  phonesPaired(origin: string | null): Promise<number | null>;
  pair(o: PairOptions): Promise<PairResult>;
  storedLogins(): Promise<StoredLogin[]>;
  addPassword(item: PasswordItem): Promise<{ id: string; domain: string }>;
}

export interface DevBackendOptions {
  sys: System;
  dataDir: string;
  mcpPort: number;
  home: string;
  passphrase: (o: { isNew: boolean; retry: boolean }) => Promise<string>;
}

export async function devBackend(o: DevBackendOptions): Promise<Backend> {
  const core = await import('@aab/core');
  const { createAgent, listAgents } = await import('../agent.ts');
  const { listPasswords } = await import('../password.ts');
  const { sys, dataDir } = o;
  let cached: string | null = null;

  const withSigner = async <T>(
    fn: (s: Parameters<Parameters<typeof core.withItemSigner>[2]>[0]) => Promise<T>,
  ): Promise<T> => {
    for (let attempt = 0; ; attempt++) {
      const isNew = !sys.exists(join(dataDir, 'signer', 'keys.enc.json'));
      cached ??= await o.passphrase({ isNew, retry: attempt > 0 });
      try {
        return await core.withItemSigner(dataDir, cached, fn);
      } catch (err) {
        if (/wrong passphrase/.test((err as Error).message) && attempt < 2) {
          cached = null;
          continue;
        }
        throw err;
      }
    }
  };
  const countAt = (
    r: { approvers: { origin: string }[]; native?: { origin: string }[] },
    origin: string | null,
  ) =>
    [...r.approvers, ...(r.native ?? [])].filter((k) => origin === null || k.origin === origin)
      .length;
  const uid = sys.uid;
  const user = (await lookupUser(sys, { uid })) ?? {
    uid,
    gid: -1,
    name: String(uid),
    home: o.home,
  };

  return {
    kind: 'dev',
    stateDir: dataDir,
    fileOwner: { uid: sys.uid, gid: sys.gid },
    denyDir: dataDir,
    user: { ...user, home: o.home },
    daemonRunning: () => sys.connectUnix(join(dataDir, 'run', 'intent.sock')),
    mcpPort: async () => o.mcpPort,
    async listAgents() {
      return listAgents(dataDir).map((a: AgentListing) => ({
        id: a.id,
        name: a.name,
        revoked: a.revokedAt !== null,
      }));
    },
    async createAgent(name) {
      return createAgent(dataDir, name, 'setup');
    },
    storeAgentToken(agentId, token) {
      const path = devAgentTokenPath(dataDir, agentId);
      const owner = { uid: sys.uid, gid: sys.gid };
      sys.mkdirUser(join(dataDir, 'agents'), 0o700, owner);
      sys.writeUserFile(path, `${token}\n`, 0o600, owner);
      return path;
    },
    hasAgentToken: (agentId) =>
      isAgentIdShape(agentId) && sys.exists(devAgentTokenPath(dataDir, agentId)),
    hookCommand: (agentId) => devHookCommand(agentId, dataDir),
    headersCommand: (agentId) => devHeadersCommand(agentId, dataDir),
    async phonesPaired(origin) {
      if (await sys.connectUnix(join(dataDir, 'run', 'intent.sock'))) {
        const text = sys.readFile(join(dataDir, 'approver', 'devices.json'));
        if (text === null) return 0;
        try {
          return ((JSON.parse(text) as { devices?: unknown[] }).devices ?? []).length;
        } catch {
          return null;
        }
      }
      if (!sys.exists(join(dataDir, 'signer', 'keys.enc.json'))) return 0;
      return countAt(await withSigner((s) => s.listApprovers()), origin);
    },
    async pair(p) {
      const { PhoneApprover } = await import('@aab/approver');
      return withSigner(async (signer) => {
        const before = countAt(await signer.listApprovers(), p.origin);
        const db = core.openDb(join(dataDir, 'broker.sqlite'));
        const audit = new core.AuditLog(db);
        const tls =
          p.tls === null
            ? undefined
            : { cert: sys.readFile(p.tls.cert) ?? '', key: sys.readFile(p.tls.key) ?? '' };
        let approver: Awaited<ReturnType<typeof PhoneApprover.start>> | null = null;
        try {
          approver = await PhoneApprover.start({
            dir: join(dataDir, 'approver'),
            origin: p.origin,
            listen: p.listen,
            ...(tls ? { tls } : {}),
            signer,
            onEvent: (event, fields) => {
              try {
                audit.append(event, fields);
              } catch {}
            },
            auditBefore: (event, fields) => {
              audit.append(event, fields);
            },
          });
          audit.append('setup.pairing', { origin: p.origin });
          await p.onOpen(approver.startPairing());
          const deadline = sys.now() + p.timeoutMs;
          while (sys.now() < deadline) {
            if (p.signal.aborted) return 'aborted';
            if (countAt(await signer.listApprovers(), p.origin) > before) return 'paired';
            await sys.sleep(1_000);
          }
          return 'timeout';
        } finally {
          await approver?.close();
          db.close();
        }
      });
    },
    async storedLogins() {
      return listPasswords(dataDir).map(storedLogin);
    },
    async addPassword(item) {
      const totp = item.totp === null ? null : core.parseTotpInput(item.totp);
      return withSigner(async (signer) => {
        const db = core.openDb(join(dataDir, 'broker.sqlite'));
        try {
          return await core.addPasswordItem(
            { signer, db },
            {
              site: item.site,
              username: item.username,
              password: item.password,
              ...(totp ? { totp } : {}),
            },
          );
        } finally {
          db.close();
        }
      });
    },
  };
}

export type AdminCall = <T>(
  socket: string,
  op: string,
  params?: Record<string, unknown>,
) => Promise<T>;

export interface ServiceBackendOptions {
  sys: System;
  paths: ServicePaths;
  admin: AdminCall;
}

export async function serviceBackend(o: ServiceBackendOptions): Promise<Backend> {
  const { sys, paths, admin } = o;
  const m = requireServiceManager(sys.platform);
  const st = sys.stat(paths.hookDir);
  if (!st) throw new Error(`${paths.hookDir} is missing: is the broker installed (install.sh)?`);
  const user = await lookupUser(sys, { uid: st.uid });
  if (!user) throw new Error(`no user with uid ${st.uid} (owner of ${paths.hookDir})`);
  const coreStatus = () => admin<{ mcpUrl: string | null }>(paths.adminSocket, 'status');
  const signerApprovers = async () =>
    (await admin<{ approvers: number }>(paths.signerAdminSocket, 'status')).approvers;

  return {
    kind: 'service',
    stateDir: paths.hookDir,
    fileOwner: { uid: user.uid, gid: user.gid },
    denyDir: paths.hookDir,
    user,
    daemonRunning: async () => {
      try {
        await coreStatus();
        return true;
      } catch {
        return false;
      }
    },
    async mcpPort() {
      const { mcpUrl } = await coreStatus();
      const port = mcpUrl ? Number(new URL(mcpUrl).port) : Number.NaN;
      return Number.isInteger(port) && port > 0 ? port : 8765;
    },
    async listAgents() {
      const { agents } = await admin<{ agents: AgentListing[] }>(paths.adminSocket, 'agent.list');
      return agents.map((a) => ({ id: a.id, name: a.name, revoked: a.revokedAt !== null }));
    },
    createAgent: (name) =>
      admin<{ id: string; name: string; token: string }>(paths.adminSocket, 'agent.add', { name }),
    storeAgentToken(agentId, token) {
      const path = serviceAgentTokenPath(paths.hookDir, agentId);
      sys.writeUserFile(path, `${token}\n`, 0o600, { uid: user.uid, gid: user.gid });
      return path;
    },
    hasAgentToken: (agentId) =>
      isAgentIdShape(agentId) && sys.exists(serviceAgentTokenPath(paths.hookDir, agentId)),
    hookCommand: (agentId) =>
      `${paths.wrapper} hook claude-code --agent ${shellQuote(agentId)} --service`,
    headersCommand: (agentId) =>
      `${paths.wrapper} mcp-headers --agent ${shellQuote(agentId)} --service`,
    phonesPaired: () => signerApprovers(),
    async pair(p) {
      const before = await signerApprovers();
      const state = await clearApproverAddress(admin, paths);
      if (state.kind === 'latched' || state.kind === 'paused') {
        throw new Error(addressRefusalText(state, { sys, m, paths }));
      }
      const r = await admin<{ url: string }>(paths.adminSocket, 'approver.pair');
      await p.onOpen(r.url);
      const deadline = sys.now() + p.timeoutMs;
      while (sys.now() < deadline) {
        if (p.signal.aborted) return 'aborted';
        if ((await signerApprovers()) > before) return 'paired';
        await sys.sleep(1_000);
      }
      return 'timeout';
    },
    async storedLogins() {
      const { passwords } = await admin<{ passwords: PasswordListRow[] }>(
        paths.adminSocket,
        'password.list',
      );
      return passwords.map(storedLogin);
    },
    addPassword: (item) =>
      admin<{ id: string; domain: string }>(paths.adminSocket, 'password.add', {
        site: item.site,
        username: item.username,
        password: item.password,
        ...(item.totp !== null ? { totp: item.totp } : {}),
      }),
  };
}
