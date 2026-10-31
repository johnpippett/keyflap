import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import type { DatabaseSync } from 'node:sqlite';
import type { Approver, HandoffSurface } from '@aab/approver';
import type { AgentResolver, ToolCallObserver } from '@aab/mcp';
import { type BrowserChannel, launchManagedBrowser, type ManagedBrowser } from '@aab/shim';
import type { TrustedApproverKeys } from '@aab/signer/approval';
import type { ApproverAddress } from '@aab/signer/approver-address';
import { connectSigner, type SignerHandle, spawnSigner } from '@aab/signer/client';
import { assertUnixSocketPath } from '@aab/signer/platform';
import type { SignerSourcesConfig } from '@aab/signer/protocol';
import { AgentPort } from './agent-port.ts';
import { AgentRegistry } from './agents.ts';
import { Broker, type HandoffSignInOffer } from './broker.ts';
import { BrowserStateStore, SessionPersistence } from './browser-state.ts';
import { openDb, PersistOptins, SessionStateRepo } from './db.ts';
import { HandoffManager } from './handoff.ts';
import { loadOrCreateHostToken, startIntentServer } from './intent-server.ts';
import { signerPaths } from './passwords.ts';
import { SessionTtl } from './session-ttl.ts';
import { AgentSessions } from './sessions.ts';
import { dropUnconfiguredSourceRows, SourceSync } from './source-sync.ts';

export const PROTON_PASS = 'proton-pass';
export const ONE_PASSWORD = '1password';

export interface PasswordSourceOptions {
  kind: typeof PROTON_PASS | typeof ONE_PASSWORD;
  bin?: string;
  vault?: string;
  env?: Record<string, string>;
  refreshMs?: number;
  retryMs?: number;
}

export function sourceIntervals(kind: PasswordSourceOptions['kind']): {
  refreshMs: number;
  retryMs: number;
} {
  return kind === ONE_PASSWORD
    ? { refreshMs: 30 * 60_000, retryMs: 5 * 60_000 }
    : { refreshMs: 5 * 60_000, retryMs: 30_000 };
}

export function onePasswordEnv(env: NodeJS.ProcessEnv): Record<string, string> {
  const out: Record<string, string> = {};
  for (const k of ['HOME', 'XDG_CONFIG_HOME', 'OP_SERVICE_ACCOUNT_TOKEN']) {
    const v = env[k];
    if (typeof v === 'string' && v.length > 0) out[k] = v;
  }
  return out;
}

export function protonPassEnv(env: NodeJS.ProcessEnv): Record<string, string> {
  const keep = [
    'HOME',
    'XDG_RUNTIME_DIR',
    'XDG_DATA_HOME',
    'XDG_CONFIG_HOME',
    'DBUS_SESSION_BUS_ADDRESS',
    'PROTON_PASS_KEY_PROVIDER',
    'PROTON_PASS_SESSION_DIR',
  ];
  const out: Record<string, string> = {};
  for (const k of keep) {
    const v = env[k];
    if (typeof v === 'string' && v.length > 0) out[k] = v;
  }
  return out;
}

export interface McpDeps {
  resolve: AgentResolver;
  onToolCall: ToolCallObserver;
  host: string;
  port: number;
}

export interface McpHandle {
  url: string;
  close(): Promise<void>;
}

export interface DaemonOptions {
  dataDir: string;
  passphrase?: string;
  signerService?: { socketPath: string; channelKey: Buffer };
  hostToken?: string;
  intentListenFd?: number;
  intentSocketPath?: string;
  approver?: Approver;
  makeApprover?: (deps: ApproverDeps) => Promise<ApproverHandle>;
  trustedApproverKeys: TrustedApproverKeys;
  highRiskDomains?: string[];
  mcpHost?: string;
  mcpPort?: number;
  headless?: boolean;
  browserChannel?: BrowserChannel;
  browserSandbox?: boolean;
  launchArgs?: string[];
  challengeHosts?: string[];
  intentTtlMs?: number;
  approvalTimeoutMs?: number;
  actionTimeoutMs?: number;
  fillStepTimeoutMs?: number;
  onSignerLog?: (line: string) => void;
  startMcp?: (deps: McpDeps) => Promise<McpHandle>;
  passwordSource?: PasswordSourceOptions;
  approverAddress?: ApproverAddress;
  sessionSweepMs?: number;
  revokeWatchMs?: number;
  browserState?: { persist?: boolean; saveMs?: number; fullSaveMs?: number };
}

export interface ApproverDeps {
  signer: SignerHandle['client'];
  audit: (event: string, fields: Record<string, unknown>) => void;
  auditBefore: (event: string, fields: Record<string, unknown>) => void;
}

export interface ApproverHandle {
  approver: Approver;
  handoffs?: HandoffSurface;
  close(): Promise<void>;
}

export interface Daemon {
  mcpUrl: string | null;
  intentSocketPath: string;
  hostToken: string;
  broker: Broker;
  registry: AgentRegistry;
  sessions: AgentSessions;
  browser: ManagedBrowser;
  db: DatabaseSync;
  signer: SignerHandle;
  sourceSync: SourceSync | null;
  sessionTtl: SessionTtl;
  persistence: SessionPersistence | null;
  optins: PersistOptins;
  handoffs: HandoffManager;
  resolveAgent: AgentResolver;
  stop(): Promise<void>;
}

export async function startDaemon(opts: DaemonOptions): Promise<Daemon> {
  const runDir = join(opts.dataDir, 'run');
  if (opts.intentListenFd === undefined) {
    assertUnixSocketPath(opts.intentSocketPath ?? join(runDir, 'intent.sock'), 'intent socket');
  }
  assertUnixSocketPath(
    opts.signerService?.socketPath ?? signerPaths(opts.dataDir).socketPath,
    'signer socket',
  );
  mkdirSync(opts.dataDir, { recursive: true, mode: 0o700 });
  if (!opts.signerService)
    mkdirSync(join(opts.dataDir, 'signer'), { recursive: true, mode: 0o700 });

  const teardown: (() => Promise<void> | void)[] = [];
  const stopAll = async () => {
    while (teardown.length > 0) {
      const t = teardown.pop() as () => Promise<void> | void;
      try {
        await t();
      } catch {}
    }
  };

  try {
    const hostToken = opts.hostToken ?? loadOrCreateHostToken(join(opts.dataDir, 'host-token'));
    if ((opts.passphrase === undefined) === (opts.signerService === undefined)) {
      throw new Error('pass exactly one of passphrase / signerService');
    }
    const signer = opts.signerService
      ? await connectSigner(opts.signerService)
      : await spawnDevSigner(opts, opts.passphrase as string);
    teardown.push(() => signer.stop());

    const db = openDb(join(opts.dataDir, 'broker.sqlite'));
    teardown.push(() => db.close());
    if ((opts.approver === undefined) === (opts.makeApprover === undefined)) {
      throw new Error('pass exactly one of approver / makeApprover');
    }
    let audit: (event: string, fields: Record<string, unknown>) => void = () => {};
    let auditBefore: (event: string, fields: Record<string, unknown>) => void = () => {
      throw new Error('the audit log is not open yet');
    };
    let approver = opts.approver as Approver;
    let handoffSurface: HandoffSurface | null = null;
    if (opts.makeApprover) {
      const h = await opts.makeApprover({
        signer: signer.client,
        audit: (e, f) => audit(e, f),
        auditBefore: (e, f) => auditBefore(e, f),
      });
      teardown.push(() => h.close());
      approver = h.approver;
      handoffSurface = h.handoffs ?? null;
    }
    const safeAudit = (event: string, fields: Record<string, unknown>) => {
      try {
        audit(event, fields);
      } catch {}
    };
    const optins = new PersistOptins(db, { audit: safeAudit });
    let persistence: SessionPersistence | null = null;
    const broker = new Broker({
      db,
      signer: signer.client,
      approver,
      keepSignedIn: {
        offer: (agentId, site) => persistence !== null && !optins.has(agentId, site),
        record: (agentId, site) => {
          optins.add(agentId, site, 'approval');
        },
      },
      ...(opts.highRiskDomains ? { highRiskDomains: opts.highRiskDomains } : {}),
      ...(opts.approvalTimeoutMs ? { approvalTimeoutMs: opts.approvalTimeoutMs } : {}),
      ...(opts.intentTtlMs ? { intentTtlMs: opts.intentTtlMs } : {}),
    });
    audit = (e, f) => broker.audit.append(e, f);
    auditBefore = audit;
    const registry = new AgentRegistry(db);

    dropUnconfiguredSourceRows(db, broker.audit, opts.passwordSource?.kind ?? null);
    let sourceSync: SourceSync | null = null;
    if (opts.passwordSource) {
      const every = sourceIntervals(opts.passwordSource.kind);
      const sync = new SourceSync({
        source: opts.passwordSource.kind,
        signer: signer.client,
        db,
        audit: broker.audit,
        minIntervalMs: opts.passwordSource.retryMs ?? every.retryMs,
      });
      sourceSync = sync;
      const tick = () => void sync.refresh().catch(() => {});
      tick();
      const timer = setInterval(tick, opts.passwordSource.refreshMs ?? every.refreshMs);
      timer.unref();
      teardown.push(() => clearInterval(timer));
    }

    const browser = await launchManagedBrowser({
      headless: opts.headless ?? true,
      ...(opts.browserChannel ? { channel: opts.browserChannel } : {}),
      ...(opts.browserSandbox ? { sandbox: true } : {}),
      ...(opts.launchArgs ? { launchArgs: opts.launchArgs } : {}),
    });
    teardown.push(() => browser.close());
    const isActive = (id: string) => registry.byId(id) !== null;
    const repo = new SessionStateRepo(db);
    if (opts.browserState?.persist !== false) {
      try {
        const { key } = await signer.client.browserStateKey();
        const store = new BrowserStateStore({
          dir: join(opts.dataDir, 'browser-state'),
          key: Buffer.from(key, 'base64url'),
        });
        persistence = new SessionPersistence({
          store,
          repo,
          optins,
          policy: broker.policy,
          ...(opts.highRiskDomains ? { highRiskDomains: opts.highRiskDomains } : {}),
          isActive,
          audit: safeAudit,
        });
        persistence.cleanupInactive();
      } catch (err) {
        persistence = null;
        safeAudit('browser_state.unavailable', {
          reason: err instanceof Error && /^[a-z_]+$/.test(err.message) ? err.message : 'error',
        });
      }
    }
    const sessions = new AgentSessions(browser, broker, {
      ...(opts.challengeHosts ? { challengeHosts: opts.challengeHosts } : {}),
      persistence,
      ...(opts.browserState?.saveMs ? { saveMs: opts.browserState.saveMs } : {}),
      ...(opts.browserState?.fullSaveMs ? { fullSaveMs: opts.browserState.fullSaveMs } : {}),
    });
    teardown.push(() => sessions.closeAll());
    registry.onRevoke((id) => {
      optins.forgetAgent(id);
      void sessions.discard(id, 'revoked');
    });
    registry.onRevoke((id) => broker.grants.dropAgent(id));
    const sessionTtl = new SessionTtl({
      broker,
      sessions,
      repo,
      isActive,
      optins: () => optins.list(),
      ...(opts.sessionSweepMs ? { sweepMs: opts.sessionSweepMs } : {}),
    });
    teardown.push(() => sessionTtl.close());

    const handoffs = new HandoffManager({
      surface: handoffSurface,
      intents: broker.intents,
      policy: broker.policy,
      approvalPending: (id) => broker.approvalPending(id),
      audit: (e, f) => audit(e, f),
      signIn: {
        offer: (agent, at) => broker.handoffSignInOffer(agent, at),
        approve: (agent, offer: HandoffSignInOffer, h) =>
          broker.approveHandoffSignIn(agent, offer, h),
        ended: (id, outcome) => broker.handoffEnded(id, outcome),
      },
      onDone: async (e) => {
        sessionTtl.record(e);
        sessions.peek(e.agentId)?.markDirty();
        await sessions.save(e.agentId, 'full');
      },
    });
    broker.setHandoffCheck((id) => handoffs.isOpen(id));
    registry.onRevoke((id) => handoffs.endAgent(id, 'revoked'));
    teardown.push(() => handoffs.close());

    const ports = new Map<string, AgentPort>();
    const resolveAgent: AgentResolver = (bearerToken) => {
      const agent = registry.byToken(bearerToken);
      if (!agent) return null;
      let port = ports.get(agent.id);
      if (!port) {
        port = new AgentPort({
          agent,
          sessions,
          broker,
          isActive: () => registry.byId(agent.id) !== null,
          ...(opts.actionTimeoutMs ? { actionTimeoutMs: opts.actionTimeoutMs } : {}),
          ...(opts.fillStepTimeoutMs ? { fillStepTimeoutMs: opts.fillStepTimeoutMs } : {}),
          ...(sourceSync ? { refreshCredentials: () => sourceSync.refreshIfStale() } : {}),
          handoffs,
        });
        ports.set(agent.id, port);
      }
      return { agentId: agent.id, port };
    };

    const noticed = new Set<string>();
    registry.onRevoke((id) => noticed.add(id));
    const revokeWatch = setInterval(() => {
      try {
        for (const id of new Set([...sessions.agentIds(), ...ports.keys()])) {
          if (noticed.has(id)) continue;
          if (registry.noticeRevoked(id)) {
            noticed.add(id);
            ports.delete(id);
          }
        }
      } catch {}
    }, opts.revokeWatchMs ?? 2_000);
    revokeWatch.unref();
    teardown.push(() => clearInterval(revokeWatch));

    const intentSocketPath = opts.intentSocketPath ?? join(runDir, 'intent.sock');
    const intentServer = await startIntentServer({
      socketPath: intentSocketPath,
      ...(opts.intentListenFd !== undefined ? { listenFd: opts.intentListenFd } : {}),
      hostToken,
      registry,
      broker,
    });
    teardown.push(() => intentServer.close());

    let mcpUrl: string | null = null;
    if (opts.startMcp) {
      const onToolCall: ToolCallObserver = (e) => {
        broker.audit.append('mcp.tool_call', { agentId: e.agentId, tool: e.tool, ok: e.ok });
      };
      const mcp = await opts.startMcp({
        resolve: resolveAgent,
        onToolCall,
        host: opts.mcpHost ?? '127.0.0.1',
        port: opts.mcpPort ?? 0,
      });
      teardown.push(() => mcp.close());
      mcpUrl = mcp.url;
    }

    let stopped: Promise<void> | null = null;
    return {
      mcpUrl,
      intentSocketPath,
      hostToken,
      broker,
      registry,
      sessions,
      browser,
      db,
      signer,
      sourceSync,
      sessionTtl,
      persistence,
      optins,
      handoffs,
      resolveAgent,
      stop: () => {
        stopped ??= stopAll();
        return stopped;
      },
    };
  } catch (err) {
    await stopAll();
    throw err;
  }
}

function spawnDevSigner(opts: DaemonOptions, passphrase: string): Promise<SignerHandle> {
  return spawnSigner({
    ...signerPaths(opts.dataDir),
    passphrase,
    trustedApproverKeys: opts.trustedApproverKeys,
    highRiskDomains: opts.highRiskDomains ?? [],
    ...(opts.onSignerLog ? { onLog: opts.onSignerLog } : {}),
    ...(opts.passwordSource ? { sources: devSources(opts.passwordSource) } : {}),
    ...(opts.approverAddress ? { approverAddress: opts.approverAddress } : {}),
  });
}

function devSources(ps: PasswordSourceOptions): SignerSourcesConfig {
  const vault = ps.vault !== undefined ? { vault: ps.vault } : {};
  if (ps.kind === ONE_PASSWORD) {
    return {
      onePassword: { bin: ps.bin ?? 'op', env: ps.env ?? onePasswordEnv(process.env), ...vault },
    };
  }
  return {
    protonPass: {
      bin: ps.bin ?? 'pass-cli',
      env: ps.env ?? protonPassEnv(process.env),
      ...vault,
    },
  };
}
