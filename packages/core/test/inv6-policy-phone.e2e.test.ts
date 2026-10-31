import { rmSync } from 'node:fs';
import { createServer as createNetServer } from 'node:net';
import { join } from 'node:path';
import {
  type ApprovalDecision,
  type ApprovalRequest,
  type Approver,
  PhoneApprover,
} from '@aab/approver';
import { startTestRp, type TestRp } from '@aab/test-rp';
import { type Browser, chromium, type Page } from 'playwright';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { NewAgent } from '../src/agents.ts';
import { type Daemon, startDaemon } from '../src/daemon.ts';
import { ALL_AGENTS } from '../src/policy.ts';
import { tmpDir } from './harness.ts';

async function freePort(): Promise<number> {
  return new Promise((resolve) => {
    const s = createNetServer().listen(0, '127.0.0.1', () => {
      const p = (s.address() as { port: number }).port;
      s.close(() => resolve(p));
    });
  });
}

class Recording implements Approver {
  readonly decisions: ApprovalDecision[] = [];
  readonly requests: ApprovalRequest[] = [];
  inner: Approver | null = null;
  async request(req: ApprovalRequest, o?: { signal?: AbortSignal }) {
    this.requests.push(req);
    const d = await (this.inner as Approver).request(req, o);
    this.decisions.push(d);
    return d;
  }
}

const rpStatus = (p: Page) =>
  p
    .waitForFunction(() => document.querySelector('#status')?.textContent !== 'working')
    .then(() => p.textContent('#status'));

describe('invariant 6: policy with the phone approver (allow-for line, grant, strong)', () => {
  let rp: TestRp;
  let daemon: Daemon;
  let dataDir: string;
  let approver: PhoneApprover;
  const recording = new Recording();
  let agent: NewAgent;
  let agentPage: Page;
  let phoneBrowser: Browser;
  let phonePage: Page;

  const approveOnPhone = async (): Promise<string> => {
    const card = phonePage.locator('#requests .card').first();
    await card.waitFor({ timeout: 15_000 });
    const text = await card.innerText();
    await card.locator('.approve').click();
    await card.waitFor({ state: 'detached', timeout: 15_000 });
    return text;
  };
  const passkeyLogin = async () => {
    await agentPage.goto(`${rp.url}login`);
    await agentPage.click('#passkey-login');
  };
  const signedIn = async () => {
    await agentPage.waitForURL('**/account');
    return agentPage.textContent('#whoami');
  };
  const logout = async () => {
    await agentPage.goto(`${rp.url}account`);
    await agentPage.click('#logout');
  };

  beforeAll(async () => {
    rp = await startTestRp({ host: 'rp.localhost' });
    dataDir = tmpDir();
    const port = await freePort();
    const origin = `http://approver.localhost:${port}`;
    daemon = await startDaemon({
      dataDir,
      passphrase: 'test-passphrase',
      trustedApproverKeys: {},
      approvalTimeoutMs: 30_000,
      makeApprover: async ({ signer, audit, auditBefore }) => {
        approver = await PhoneApprover.start({
          dir: join(dataDir, 'approver'),
          origin,
          listen: { host: '127.0.0.1', port },
          signer,
          onEvent: audit,
          auditBefore,
          timeoutMs: 25_000,
        });
        recording.inner = approver;
        const a = approver;
        return { approver: recording, close: () => a.close() };
      },
    });
    agent = daemon.registry.add('phone-policy-agent');
    daemon.broker.intents.record(agent.id, 'sign me in to the test site');
    agentPage = await (await daemon.sessions.get(agent)).newPage();
    phoneBrowser = await chromium.launch({ headless: true });
    const phone = await phoneBrowser.newContext();
    phonePage = await phone.newPage();
    const cdp = await phone.newCDPSession(phonePage);
    await cdp.send('WebAuthn.enable');
    await cdp.send('WebAuthn.addVirtualAuthenticator', {
      options: {
        protocol: 'ctap2',
        transport: 'internal',
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
        automaticPresenceSimulation: true,
      },
    });
    await phonePage.goto(approver.startPairing());
    await phonePage.click('#pair-button');
    await phonePage.waitForFunction(
      () => document.querySelector('#status')?.textContent === 'No pending requests.',
    );
    await agentPage.goto(`${rp.url}signup`);
    await agentPage.fill('#username', 'quinn');
    await agentPage.click('#signup');
    await agentPage.click('#add-passkey');
    const card = await approveOnPhone();
    expect(card).not.toContain('Allow-for');
    expect(await rpStatus(agentPage)).toBe('passkey added');
    await logout();
  });
  afterAll(async () => {
    await phoneBrowser?.close();
    await daemon?.stop();
    await rp?.close();
    if (dataDir) rmSync(dataDir, { recursive: true, force: true });
  });

  it('allow-for: the phone shows the window and signs the grant; then no prompt in the window', async () => {
    daemon.broker.policy.set(rp.origin, agent.id, { mode: 'allow-for', allowForMs: 10 * 60_000 });
    const n = recording.requests.length;
    await passkeyLogin();
    const card = await approveOnPhone();
    expect(await signedIn()).toBe('Signed in as quinn');
    expect(card).toContain('Allow-for');
    expect(card).toContain(
      'approving also lets this agent sign in here again without asking, for 10 minutes',
    );
    const d = recording.decisions.at(-1) as Extract<ApprovalDecision, { approved: true }>;
    expect(d.approved).toBe(true);
    expect(d.approval.webauthn).toBeDefined();
    expect(d.approval.statement.grant).toEqual({
      agentId: agent.id,
      until: d.approval.statement.issuedAt + 10 * 60_000,
    });

    await logout();
    await passkeyLogin();
    expect(await signedIn()).toBe('Signed in as quinn');
    expect(recording.requests.length).toBe(n + 1);
    expect(await phonePage.locator('#requests .card').count()).toBe(0);
    const used = daemon.broker.audit.all().filter((r) => r.event_type === 'grant.used');
    expect(used).toHaveLength(1);
    await logout();
  });

  it('ask-strong by policy on an ordinary origin: a strong statement, no grant, no allow-for line', async () => {
    daemon.broker.policy.set('rp.localhost', ALL_AGENTS, { mode: 'ask-strong' });
    const n = recording.requests.length;
    await passkeyLogin();
    const card = await approveOnPhone();
    expect(await signedIn()).toBe('Signed in as quinn');
    expect(card).not.toContain('Allow-for');
    expect(recording.requests.length).toBe(n + 1);
    const req = recording.requests.at(-1) as ApprovalRequest;
    expect(req.policy.tier).toBe('ask-strong');
    expect(req.binding.grant).toBeUndefined();
    const d = recording.decisions.at(-1) as Extract<ApprovalDecision, { approved: true }>;
    expect(d.approval.statement.strong).toBe(true);
    expect(d.approval.statement.grant).toBeUndefined();
    expect(d.approval.statement.userVerified).toBe(true);
    expect(d.approval.statement.expiresAt - d.approval.statement.issuedAt).toBeLessThanOrEqual(
      60_000,
    );
    expect(daemon.broker.audit.verify()).toBeNull();
  });
});
