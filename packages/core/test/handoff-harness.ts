import { createDecipheriv, createECDH, hkdfSync } from 'node:crypto';
import { rmSync } from 'node:fs';
import { createServer, type IncomingMessage, type Server } from 'node:http';
import { createServer as createNetServer } from 'node:net';
import { join } from 'node:path';
import {
  type ApprovalDecision,
  type ApprovalRequest,
  type Approver,
  PhoneApprover,
} from '@aab/approver';
import { startMcpHttpServer } from '@aab/mcp';
import { startTestRp, type TestRp, type TestRpOptions } from '@aab/test-rp';
import { type Browser, type BrowserContext, chromium, type Page } from 'playwright';
import type { NewAgent } from '../src/agents.ts';
import { type Daemon, type DaemonOptions, startDaemon } from '../src/daemon.ts';
import { addPasswordItem } from '../src/passwords.ts';
import { tmpDir } from './harness.ts';
import { connectAgent, type McpAgent, postIntent } from './mcp-harness.ts';

export const ALICE_PW = 'alice-handoff-pw-9Kz!';
export const USERS = [{ username: 'alice', password: ALICE_PW }];

async function freePort(): Promise<number> {
  return new Promise((resolve) => {
    const s = createNetServer().listen(0, '127.0.0.1', () => {
      const p = (s.address() as { port: number }).port;
      s.close(() => resolve(p));
    });
  });
}

export class RecordingApprover implements Approver {
  readonly requests: ApprovalRequest[] = [];
  readonly decisions: ApprovalDecision[] = [];
  inner: Approver | null = null;
  wrap: ((d: ApprovalDecision, req: ApprovalRequest) => ApprovalDecision) | null = null;
  async request(req: ApprovalRequest, o?: { signal?: AbortSignal }) {
    this.requests.push(req);
    let d = await (this.inner as Approver).request(req, o);
    if (this.wrap) d = this.wrap(d, req);
    this.decisions.push(d);
    return d;
  }
}

export interface HandoffHarness {
  rp: TestRp;
  daemon: Daemon;
  dataDir: string;
  approver: PhoneApprover;
  recording: RecordingApprover;
  agent: NewAgent;
  mcp: McpAgent;
  phoneBrowser: Browser;
  phone: BrowserContext;
  phonePage: Page;
  pushes: { headers: IncomingMessage['headers']; body: Buffer }[];
  pushPayload(i: number): string;
  intent(text: string): Promise<void>;
  page(): Page;
  auditEvents(): { seq: number; type: string; payload: Record<string, unknown> }[];
  approveOnPhone(o?: { keep?: boolean }): Promise<string>;
  openLiveView(): Promise<void>;
  tapOnPhone(selector: string): Promise<void>;
  restart(): Promise<void>;
  close(): Promise<void>;
}

export async function startHandoffHarness(
  opts: { rp?: TestRpOptions; daemon?: Partial<DaemonOptions>; password?: boolean } = {},
): Promise<HandoffHarness> {
  const rp = await startTestRp({ host: 'rp.localhost', users: USERS, ...opts.rp });
  const dataDir = tmpDir();
  const port = await freePort();
  const origin = `http://approver.localhost:${port}`;
  const recording = new RecordingApprover();

  const pushes: HandoffHarness['pushes'] = [];
  const pushServer: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      pushes.push({ headers: req.headers, body: Buffer.concat(chunks) });
      res.writeHead(201).end();
    });
  });
  await new Promise<void>((r) => pushServer.listen(0, '127.0.0.1', () => r()));
  const pushUrl = `http://127.0.0.1:${(pushServer.address() as { port: number }).port}/push/1`;

  let approver: PhoneApprover | null = null;
  const options = (): DaemonOptions => ({
    dataDir,
    passphrase: 'test-passphrase',
    trustedApproverKeys: {},
    approvalTimeoutMs: 30_000,
    actionTimeoutMs: 3_000,
    challengeHosts: ['captcha.localhost'],
    startMcp: (deps) => startMcpHttpServer(deps),
    makeApprover: async ({ signer, audit, auditBefore }) => {
      const a = await PhoneApprover.start({
        dir: join(dataDir, 'approver'),
        origin,
        listen: { host: '127.0.0.1', port },
        signer,
        onEvent: audit,
        auditBefore,
        allowInsecurePushEndpoints: true,
        timeoutMs: 25_000,
      });
      approver = a;
      recording.inner = a;
      return { approver: recording, handoffs: a, close: () => a.close() };
    },
    ...opts.daemon,
  });

  let daemon = await startDaemon(options());
  const agent = daemon.registry.add('handoff-agent');
  if (opts.password !== false) {
    await addPasswordItem(
      { signer: daemon.signer.client, db: daemon.db },
      { site: 'rp.localhost', username: 'alice', password: ALICE_PW },
    );
  }
  const clients: McpAgent[] = [];
  let mcp = await connectAgent(daemon.mcpUrl as string, agent);
  clients.push(mcp);

  const phoneBrowser = await chromium.launch({ headless: true });
  const phone = await phoneBrowser.newContext();
  const phonePage = await phone.newPage();
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
  await phonePage.goto((approver as unknown as PhoneApprover).startPairing());
  await phonePage.click('#pair-button');
  await phonePage.waitForFunction(
    () => document.querySelector('#status')?.textContent === 'No pending requests.',
  );
  const ua = createECDH('prime256v1');
  ua.generateKeys();
  const auth = Buffer.alloc(16, 5);
  const sub = {
    endpoint: pushUrl,
    keys: { p256dh: ua.getPublicKey().toString('base64url'), auth: auth.toString('base64url') },
  };
  const subStatus = await phonePage.evaluate(async (subscription) => {
    const r = await fetch('/api/push', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ subscription }),
    });
    return r.status;
  }, sub);
  if (subStatus !== 200) throw new Error(`push subscription answered ${subStatus}`);

  const h: HandoffHarness = {
    rp,
    get daemon() {
      return daemon;
    },
    dataDir,
    get approver() {
      return approver as unknown as PhoneApprover;
    },
    recording,
    agent,
    get mcp() {
      return mcp;
    },
    phoneBrowser,
    phone,
    phonePage,
    pushes,
    pushPayload(i) {
      const p = pushes[i];
      if (!p) throw new Error(`no push ${i}`);
      const salt = p.body.subarray(0, 16);
      const idlen = p.body[20] as number;
      const asPublic = p.body.subarray(21, 21 + idlen);
      const ct = p.body.subarray(21 + idlen);
      const ikm = Buffer.from(
        hkdfSync(
          'sha256',
          ua.computeSecret(asPublic),
          auth,
          Buffer.concat([Buffer.from('WebPush: info\0'), ua.getPublicKey(), asPublic]),
          32,
        ),
      );
      const cek = Buffer.from(hkdfSync('sha256', ikm, salt, 'Content-Encoding: aes128gcm\0', 16));
      const nonce = Buffer.from(hkdfSync('sha256', ikm, salt, 'Content-Encoding: nonce\0', 12));
      const d = createDecipheriv('aes-128-gcm', cek, nonce);
      d.setAuthTag(ct.subarray(ct.length - 16));
      const plain = Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]);
      return plain.subarray(0, plain.length - 1).toString('utf8');
    },
    async intent(text) {
      const r = await postIntent(
        daemon.intentSocketPath,
        { agentId: agent.id, text },
        { token: daemon.hostToken },
      );
      if (r.status !== 201) throw new Error(`intent socket answered ${r.status}`);
    },
    page() {
      const p = daemon.sessions.peek(agent.id)?.currentPage();
      if (!p) throw new Error('no page');
      return p;
    },
    auditEvents() {
      return daemon.broker.audit.all().map((r) => ({
        seq: r.seq,
        type: r.event_type,
        payload: JSON.parse(r.payload_json) as Record<string, unknown>,
      }));
    },
    async approveOnPhone(o = {}) {
      await phonePage.goto(`${origin}/`);
      const card = phonePage.locator('#requests .card').first();
      await card.waitFor({ timeout: 15_000 });
      const text = (await card.textContent()) ?? '';
      if (o.keep) await card.locator('.keep-box').check();
      await card.locator('.approve').click();
      await card.waitFor({ state: 'detached', timeout: 15_000 });
      return text;
    },
    async openLiveView() {
      await phonePage.goto(`${origin}/handoff`);
      const live = phonePage.locator('#live');
      try {
        await live.waitFor({ state: 'visible', timeout: 5_000 });
      } catch {
        await phonePage.click('#start-button');
        await live.waitFor({ state: 'visible', timeout: 10_000 });
      }
      await phonePage.waitForFunction(() => {
        const img = document.querySelector('#screen') as HTMLImageElement | null;
        return img?.complete === true && img.naturalWidth > 0;
      });
    },
    async tapOnPhone(selector) {
      const box = await h.page().locator(selector).boundingBox();
      const vp = h.page().viewportSize();
      if (!box || !vp) throw new Error(`no box for ${selector}`);
      const fx = (box.x + box.width / 2) / vp.width;
      const fy = (box.y + box.height / 2) / vp.height;
      const img = await phonePage.locator('#screen').boundingBox();
      if (!img) throw new Error('no live image');
      await phonePage.mouse.click(img.x + fx * img.width, img.y + fy * img.height);
    },
    async restart() {
      for (const c of clients) await c.close();
      await daemon.stop();
      daemon = await startDaemon(options());
      mcp = await connectAgent(daemon.mcpUrl as string, agent);
      clients.push(mcp);
    },
    async close() {
      for (const c of clients) await c.close();
      await phoneBrowser.close();
      await daemon.stop();
      await rp.close();
      await new Promise<void>((r) => pushServer.close(() => r()));
      rmSync(dataDir, { recursive: true, force: true });
    },
  };
  return h;
}

export async function routeChallengePage(
  h: HandoffHarness,
  path: string,
  body: string,
  title = 'Check',
): Promise<string> {
  const ctx = (await h.daemon.sessions.get(h.agent)).context;
  const port = new URL(h.rp.origin).port;
  await ctx.route(/captcha\.localhost:\d+\/challenge\/widget/, (route) =>
    route.fulfill({ contentType: 'text/html; charset=utf-8', body: '<p>widget</p>' }),
  );
  await ctx.route(new RegExp(`rp\\.localhost:\\d+${path.replace(/[/.]/g, '\\$&')}$`), (route) =>
    route.fulfill({
      contentType: 'text/html; charset=utf-8',
      body: `<!doctype html><title>${title}</title><body>${body}
<iframe id="challenge-widget" title="challenge" src="http://captcha.localhost:${port}/challenge/widget" width="320" height="160"></iframe>
</body>`,
    }),
  );
  return `${h.rp.url}${path.replace(/^\//, '')}`;
}
