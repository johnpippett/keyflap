import { execFile } from 'node:child_process';
import { rmSync } from 'node:fs';
import { join } from 'node:path';
import { ApproverKey } from '@aab/approver';
import { startMcpHttpServer } from '@aab/mcp';
import { startTestRp, type TestRp, type TestRpOptions } from '@aab/test-rp';
import type { BrowserContext, Page } from 'playwright';
import type { NewAgent } from '../src/agents.ts';
import { type Daemon, type DaemonOptions, startDaemon } from '../src/daemon.ts';
import { tmpDir } from './harness.ts';
import {
  CapturingApprover,
  connectAgent,
  type McpAgent,
  PASSPHRASE,
  postIntent,
} from './mcp-harness.ts';

export interface PersistHarness {
  rp: TestRp;
  dataDir: string;
  approver: CapturingApprover;
  agent: NewAgent;
  daemon: Daemon;
  mcp: McpAgent;
  start(extra?: Partial<DaemonOptions>): Promise<void>;
  stop(): Promise<void>;
  restart(extra?: Partial<DaemonOptions>): Promise<void>;
  intent(text: string, agentId?: string): Promise<void>;
  connect(agent: NewAgent): Promise<McpAgent>;
  context(agent?: NewAgent): Promise<BrowserContext>;
  page(agent?: NewAgent): Page;
  auditEvents(): { type: string; payload: Record<string, unknown> }[];
  stateFile(agentId?: string): string;
  close(): Promise<void>;
}

export async function startPersistHarness(
  opts: { rp?: TestRpOptions; daemon?: Partial<DaemonOptions>; agentName?: string } = {},
): Promise<PersistHarness> {
  const rp = await startTestRp({ host: 'rp.localhost', ...opts.rp });
  const dataDir = tmpDir();
  const approverKey = ApproverKey.generate('test-approver');
  const approver = new CapturingApprover(approverKey);
  const clients: McpAgent[] = [];
  let daemon: Daemon | null = null;
  let mcp: McpAgent | null = null;
  let agent: NewAgent | null = null;

  const h: PersistHarness = {
    rp,
    dataDir,
    approver,
    get agent() {
      return agent as NewAgent;
    },
    get daemon() {
      if (!daemon) throw new Error('daemon stopped');
      return daemon;
    },
    get mcp() {
      if (!mcp) throw new Error('daemon stopped');
      return mcp;
    },
    async start(extra = {}) {
      daemon = await startDaemon({
        dataDir,
        passphrase: PASSPHRASE,
        approver,
        trustedApproverKeys: approverKey.trustEntry(),
        approvalTimeoutMs: 10_000,
        actionTimeoutMs: 3_000,
        startMcp: (deps) => startMcpHttpServer(deps),
        ...opts.daemon,
        ...extra,
      });
      agent ??= daemon.registry.add(opts.agentName ?? 'persist-agent');
      mcp = await connectAgent(daemon.mcpUrl as string, agent);
      clients.push(mcp);
    },
    async stop() {
      for (const c of clients.splice(0)) await c.close();
      await daemon?.stop();
      daemon = null;
      mcp = null;
    },
    async restart(extra) {
      await h.stop();
      await h.start(extra);
    },
    async intent(text, agentId = h.agent.id) {
      const r = await postIntent(
        h.daemon.intentSocketPath,
        { agentId, text },
        { token: h.daemon.hostToken },
      );
      if (r.status !== 201) throw new Error(`intent socket answered ${r.status}`);
    },
    async connect(a) {
      const c = await connectAgent(h.daemon.mcpUrl as string, a);
      clients.push(c);
      return c;
    },
    async context(a = h.agent) {
      return (await h.daemon.sessions.get(a)).context;
    },
    page(a = h.agent) {
      const p = h.daemon.sessions.peek(a.id)?.currentPage();
      if (!p) throw new Error('no page');
      return p;
    },
    auditEvents() {
      return h.daemon.broker.audit.all().map((r) => ({
        type: r.event_type,
        payload: JSON.parse(r.payload_json) as Record<string, unknown>,
      }));
    },
    stateFile(agentId = h.agent.id) {
      return join(dataDir, 'browser-state', `${agentId}.state`);
    },
    async close() {
      await h.stop();
      await rp.close();
      rmSync(dataDir, { recursive: true, force: true });
    },
  };
  await h.start();
  return h;
}

const CLI = join(import.meta.dirname, '..', '..', 'cli', 'src', 'main.ts');

export function keyflap(
  dataDir: string,
  ...args: string[]
): Promise<{ code: number; out: string }> {
  return new Promise((resolve) => {
    execFile(
      process.execPath,
      [CLI, ...args, '--data-dir', dataDir],
      { timeout: 20_000 },
      (err, stdout, stderr) => {
        const code = err ? ((err as { code?: number }).code ?? 1) : 0;
        resolve({ code: typeof code === 'number' ? code : 1, out: `${stdout}${stderr}` });
      },
    );
  });
}

export async function until(cond: () => boolean | Promise<boolean>, ms = 15_000): Promise<void> {
  const deadline = Date.now() + ms;
  while (!(await cond())) {
    if (Date.now() > deadline) throw new Error('timed out');
    await new Promise((r) => setTimeout(r, 100));
  }
}
