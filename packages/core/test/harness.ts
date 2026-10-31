import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { DatabaseSync } from 'node:sqlite';
import { type ApprovalRequest, ApproverKey, ScriptedApprover } from '@aab/approver';
import { startTestRp, type TestRp, type TestRpOptions } from '@aab/test-rp';
import type { BrowserContext, Page } from 'playwright';
import type { NewAgent } from '../src/agents.ts';
import { type Daemon, type DaemonOptions, startDaemon } from '../src/daemon.ts';

export const AGENT = { id: 'test-agent', name: 'test-agent' };

export function registerAgents(db: DatabaseSync, ...agents: { id: string; name: string }[]) {
  for (const a of agents) {
    db.prepare('INSERT INTO agents (id, name, created_at, token_hash) VALUES (?, ?, ?, ?)').run(
      a.id,
      a.name,
      0,
      `test-token-hash-${a.id}`,
    );
  }
}

export function tmpDir(): string {
  const d = mkdtempSync(join(tmpdir(), 'keyflap-'));
  mkdirSync(d, { recursive: true });
  return d;
}

export interface Harness {
  rp: TestRp;
  daemon: Daemon;
  dataDir: string;
  approver: ScriptedApprover;
  approverKey: ApproverKey;
  signerLog: string[];
  agent: NewAgent;
  context: BrowserContext;
  page: Page;
  close(): Promise<void>;
}

export async function startHarness(
  opts: {
    rp?: TestRpOptions;
    decide?: (req: ApprovalRequest) => boolean | Promise<boolean>;
    intent?: string | null;
    userVerified?: boolean;
    launchArgs?: string[];
    agentName?: string;
    daemon?: Partial<DaemonOptions>;
  } = {},
): Promise<Harness> {
  const rp = await startTestRp({ host: 'rp.localhost', ...opts.rp });
  const dataDir = tmpDir();
  const approverKey = ApproverKey.generate('test-approver');
  const approver = new ScriptedApprover(approverKey, opts.decide, {
    userVerified: opts.userVerified ?? false,
  });
  const signerLog: string[] = [];
  const daemon = await startDaemon({
    dataDir,
    passphrase: 'test-passphrase',
    approver,
    trustedApproverKeys: approverKey.trustEntry(),
    approvalTimeoutMs: 10_000,
    onSignerLog: (l) => signerLog.push(l),
    ...(opts.launchArgs ? { launchArgs: opts.launchArgs } : {}),
    ...opts.daemon,
  });
  const agent = daemon.registry.add(opts.agentName ?? 'test-agent');
  if (opts.intent !== null) {
    daemon.broker.intents.record(agent.id, opts.intent ?? 'sign me in to the test site');
  }
  const session = await daemon.sessions.get(agent);
  const page = await session.newPage();
  return {
    rp,
    daemon,
    dataDir,
    approver,
    approverKey,
    signerLog,
    agent,
    context: session.context,
    page,
    async close() {
      await daemon.stop();
      await rp.close();
      rmSync(dataDir, { recursive: true, force: true });
    },
  };
}

export async function signUpAndRegister(h: Harness, username: string): Promise<string | null> {
  const { page, rp } = h;
  await page.goto(`${rp.url}signup`);
  await page.fill('#username', username);
  await page.click('#signup');
  await page.click('#add-passkey');
  await page.waitForFunction(() => document.querySelector('#status')?.textContent !== 'working');
  return page.textContent('#status');
}
