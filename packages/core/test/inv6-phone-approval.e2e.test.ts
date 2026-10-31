import { createDecipheriv, createECDH, createPublicKey, hkdfSync, verify } from 'node:crypto';
import { rmSync, statSync } from 'node:fs';
import { createServer, type IncomingMessage } from 'node:http';
import { createServer as createNetServer } from 'node:net';
import { join } from 'node:path';
import {
  type ApprovalDecision,
  type ApprovalRequest,
  type Approver,
  ApproverKey,
  PhoneApprover,
  TerminalApprover,
} from '@aab/approver';
import type { SignedApproval } from '@aab/signer/approval';
import { startTestRp, type TestRp } from '@aab/test-rp';
import { type Browser, type BrowserContext, chromium, type Page } from 'playwright';
import { afterEach, describe, expect, it } from 'vitest';
import type { NewAgent } from '../src/agents.ts';
import { type Daemon, startDaemon } from '../src/daemon.ts';
import { startHarness, tmpDir } from './harness.ts';

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

interface PhoneSetup {
  rp: TestRp;
  daemon: Daemon;
  dataDir: string;
  approver: PhoneApprover;
  recording: Recording;
  agent: NewAgent;
  agentPage: Page;
  phoneBrowser: Browser;
  phone: BrowserContext;
  phonePage: Page;
  pushes: { url: string | undefined; headers: IncomingMessage['headers']; body: Buffer }[];
  pushUrl: string;
  close(): Promise<void>;
}

async function startPhoneSetup(
  opts: { uv?: boolean; highRisk?: string[]; approverTimeoutMs?: number } = {},
): Promise<PhoneSetup> {
  const rp = await startTestRp({ host: 'rp.localhost', userVerification: 'required' });
  const dataDir = tmpDir();
  const port = await freePort();
  const origin = `http://approver.localhost:${port}`;
  const recording = new Recording();
  let approver: PhoneApprover | null = null;

  const pushes: PhoneSetup['pushes'] = [];
  const pushServer = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      pushes.push({ url: req.url, headers: req.headers, body: Buffer.concat(chunks) });
      res.writeHead(201).end();
    });
  });
  await new Promise<void>((r) => pushServer.listen(0, '127.0.0.1', () => r()));
  const pushUrl = `http://127.0.0.1:${(pushServer.address() as { port: number }).port}/push/1`;

  const daemon = await startDaemon({
    dataDir,
    passphrase: 'test-passphrase',
    trustedApproverKeys: {},
    highRiskDomains: opts.highRisk ?? ['rp.localhost'],
    approvalTimeoutMs: 30_000,
    makeApprover: async ({ signer, audit, auditBefore }) => {
      approver = await PhoneApprover.start({
        dir: join(dataDir, 'approver'),
        origin,
        listen: { host: '127.0.0.1', port },
        signer,
        onEvent: audit,
        auditBefore,
        allowInsecurePushEndpoints: true,
        timeoutMs: opts.approverTimeoutMs ?? 25_000,
      });
      recording.inner = approver;
      const a = approver;
      return { approver: recording, close: () => a.close() };
    },
  });
  const agent = daemon.registry.add('test-agent');
  daemon.broker.intents.record(agent.id, 'sign me in to the test site');
  const agentPage = await (await daemon.sessions.get(agent)).newPage();

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
      isUserVerified: opts.uv ?? true,
      automaticPresenceSimulation: true,
    },
  });

  return {
    rp,
    daemon,
    dataDir,
    approver: approver as unknown as PhoneApprover,
    recording,
    agent,
    agentPage,
    phoneBrowser,
    phone,
    phonePage,
    pushes,
    pushUrl,
    async close() {
      await phoneBrowser.close();
      await daemon.stop();
      await rp.close();
      await new Promise<void>((r) => pushServer.close(() => r()));
      rmSync(dataDir, { recursive: true, force: true });
    },
  };
}

async function pairPhone(s: PhoneSetup): Promise<void> {
  await s.phonePage.goto(s.approver.startPairing());
  await s.phonePage.click('#pair-button');
  await s.phonePage.waitForFunction(
    () => document.querySelector('#status')?.textContent === 'No pending requests.',
  );
}

async function approveOnPhone(s: PhoneSetup): Promise<string> {
  const card = s.phonePage.locator('#requests .card').first();
  await card.waitFor({ timeout: 15_000 });
  const text = (await card.textContent()) ?? '';
  await card.locator('.approve').click();
  await card.waitFor({ state: 'detached', timeout: 15_000 });
  return text;
}

async function signUp(s: PhoneSetup, username: string): Promise<void> {
  await s.agentPage.goto(`${s.rp.url}signup`);
  await s.agentPage.fill('#username', username);
  await s.agentPage.click('#signup');
}

const rpStatus = (p: Page) =>
  p
    .waitForFunction(() => document.querySelector('#status')?.textContent !== 'working')
    .then(() => p.textContent('#status'));

describe('invariant 6: approvals under policy; high-risk needs UV on the approver device', () => {
  let s: PhoneSetup | null = null;
  afterEach(async () => {
    await s?.close();
    s = null;
  });

  it('phone pairs, then approves a high-risk registration and sign-in with UV', async () => {
    s = await startPhoneSetup();
    await pairPhone(s);
    const paired = s.daemon.broker.audit.all().filter((r) => r.event_type === 'approver.paired');
    expect(paired).toHaveLength(1);
    expect(statSync(join(s.dataDir, 'approver', 'devices.json')).mode & 0o777).toBe(0o600);

    await signUp(s, 'ivy');
    await s.agentPage.click('#add-passkey');
    const shown = await approveOnPhone(s);
    expect(await rpStatus(s.agentPage)).toBe('passkey added');
    expect(shown).toContain('sign me in to the test site');
    expect(shown).toContain(s.rp.origin);
    expect(shown).toContain('test-agent');
    expect(shown).toContain('passkey (register)');

    await s.agentPage.click('#logout');
    await s.agentPage.goto(`${s.rp.url}login`);
    await s.agentPage.click('#passkey-login');
    await approveOnPhone(s);
    await s.agentPage.waitForURL('**/account');
    expect(await s.agentPage.textContent('#whoami')).toBe('Signed in as ivy');

    expect(s.recording.requests.map((r) => r.policy.tier)).toEqual(['ask-strong', 'ask-strong']);
    for (const d of s.recording.decisions) {
      expect(d.approved).toBe(true);
      const a = (d as { approval: SignedApproval }).approval;
      expect(a.webauthn).toBeDefined();
      expect(a.signature).toBeUndefined();
      expect(a.statement.userVerified).toBe(true);
      expect(a.statement.expiresAt - a.statement.issuedAt).toBeLessThanOrEqual(60_000);
      const cd = JSON.parse(
        Buffer.from(a.webauthn?.clientDataJSON as string, 'base64url').toString(),
      );
      expect(cd.origin).toBe(s.approver.origin);
      expect(cd.type).toBe('webauthn.get');
      const flags = Buffer.from(a.webauthn?.authenticatorData as string, 'base64url')[32] as number;
      expect(flags & 0x05).toBe(0x05);
    }
    expect(() => statSync(join(s?.dataDir as string, 'approver-key.json'))).toThrow();
    expect(s.daemon.broker.audit.verify()).toBeNull();
  });

  it('pairing survives a reload; a /pair page that lost its code says so', async () => {
    s = await startPhoneSetup();
    const url = s.approver.startPairing();
    const origin = new URL(url).origin;

    await s.phonePage.goto(`${origin}/pair`);
    await s.phonePage.locator('#lost-code').waitFor();
    expect(await s.phonePage.locator('#pair').isHidden()).toBe(true);

    await s.phonePage.goto('about:blank');
    await s.phonePage.goto(url);
    await s.phonePage.locator('#pair-button').waitFor();
    expect(s.phonePage.url()).toBe(`${origin}/pair`);
    await s.phonePage.reload();
    await s.phonePage.click('#pair-button');
    await s.phonePage.waitForFunction(
      () => document.querySelector('#status')?.textContent === 'No pending requests.',
    );
    expect(await s.phonePage.evaluate(() => sessionStorage.getItem('keyflap.pairCode'))).toBe(null);
    const paired = s.daemon.broker.audit.all().filter((r) => r.event_type === 'approver.paired');
    expect(paired).toHaveLength(1);
  });

  it('invariant 10: a phone is not paired while its pairing row cannot be written', async () => {
    s = await startPhoneSetup();
    const link = s.approver.startPairing();
    s.daemon.db.exec(
      `CREATE TRIGGER audit_unwritable BEFORE INSERT ON audit
         BEGIN SELECT RAISE(ABORT, 'disk full at /var/lib/keyflap/core/broker.sqlite'); END`,
    );
    await s.phonePage.goto(link);
    await s.phonePage.click('#pair-button');
    await s.phonePage.waitForFunction(() =>
      document.querySelector('#status')?.textContent?.startsWith('Pairing failed'),
    );
    expect(await s.phonePage.textContent('#status')).not.toContain('disk full');
    expect((await s.daemon.signer.client.listApprovers()).approvers).toEqual([]);
    expect(s.daemon.broker.audit.all().map((r) => r.event_type)).not.toContain('approver.paired');

    s.daemon.db.exec('DROP TRIGGER audit_unwritable');
    await s.phonePage.click('#pair-button');
    await s.phonePage.waitForFunction(
      () => document.querySelector('#status')?.textContent === 'No pending requests.',
    );
    const key = (await s.daemon.signer.client.listApprovers()).approvers;
    expect(key).toHaveLength(1);
    const rows = s.daemon.broker.audit.all();
    const accepted = rows.findIndex((r) => r.event_type === 'approver.pairing_accepted');
    const paired = rows.findIndex((r) => r.event_type === 'approver.paired');
    expect(accepted).toBeGreaterThanOrEqual(0);
    expect(accepted).toBeLessThan(paired);
    expect(JSON.parse(rows[accepted]?.payload_json ?? '{}')).toEqual({
      origin: key[0]?.origin,
      credentialId: key[0]?.credentialId,
      first: true,
      kind: 'web',
    });
  });

  it('an approver device that cannot verify the user cannot approve', async () => {
    s = await startPhoneSetup({ uv: false, approverTimeoutMs: 8_000 });
    await s.phonePage.goto(s.approver.startPairing());
    await s.phonePage.click('#pair-button');
    await s.phonePage.waitForFunction(() =>
      document.querySelector('#status')?.textContent?.startsWith('Pairing failed'),
    );
    expect((await s.daemon.signer.client.listApprovers()).approvers).toHaveLength(0);
    await signUp(s, 'jay');
    await s.agentPage.click('#add-passkey');
    expect(await rpStatus(s.agentPage)).toBe('error: NotAllowedError');
    const denied = s.daemon.broker.audit.all().filter((r) => r.event_type === 'denied');
    expect(JSON.parse(denied.at(-1)?.payload_json ?? '{}').reason).toBe(
      'approval_no_approver_paired',
    );
  });

  it('a paired phone whose authenticator stops verifying the user is refused', async () => {
    s = await startPhoneSetup({ approverTimeoutMs: 8_000 });
    await pairPhone(s);
    await signUp(s, 'kim');
    await s.agentPage.click('#add-passkey');
    await s.phonePage.locator('#requests .card').first().waitFor();
    const result = await s.phonePage.evaluate(async () => {
      const st = await (await fetch('/api/state')).json();
      const id = st.pending[0].id;
      const ch = await (
        await fetch('/api/challenge', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ id }),
        })
      ).json();
      const dec = (s: string) =>
        Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
      const enc = (b: ArrayBuffer) =>
        btoa(String.fromCharCode(...new Uint8Array(b)))
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/=+$/, '');
      const cred = (await navigator.credentials.get({
        publicKey: {
          challenge: dec(ch.challenge),
          rpId: ch.rpId,
          userVerification: 'discouraged',
        },
      })) as PublicKeyCredential;
      const r = cred.response as AuthenticatorAssertionResponse;
      const ad = new Uint8Array(r.authenticatorData);
      ad[32] = (ad[32] as number) & ~0x04;
      const res = await fetch('/api/decide', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          id,
          decision: 'approve',
          credential: {
            id: cred.id,
            response: {
              authenticatorData: enc(ad.buffer),
              clientDataJSON: enc(r.clientDataJSON),
              signature: enc(r.signature),
            },
          },
        }),
      });
      return { status: res.status, body: await res.json() };
    });
    expect(result).toEqual({ status: 400, body: { error: 'user_not_verified' } });
    expect(await rpStatus(s.agentPage)).toBe('error: NotAllowedError');
    expect(s.recording.decisions.at(-1)).toEqual({ approved: false, reason: 'timeout' });
  });

  it('a second phone is added only when the first approves it, both showing one check code', async () => {
    s = await startPhoneSetup();
    await pairPhone(s);
    const phone2 = await s.phoneBrowser.newContext();
    const page2 = await phone2.newPage();
    const cdp2 = await phone2.newCDPSession(page2);
    await cdp2.send('WebAuthn.enable');
    await cdp2.send('WebAuthn.addVirtualAuthenticator', {
      options: {
        protocol: 'ctap2',
        transport: 'internal',
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
        automaticPresenceSimulation: true,
      },
    });
    await page2.goto(s.approver.startPairing());
    await page2.click('#pair-button');
    await page2.waitForFunction(() =>
      document.querySelector('#status')?.textContent?.startsWith('Check code'),
    );
    const shownOn2 = /Check code ([0-9A-F-]{14})/.exec(
      (await page2.textContent('#status')) ?? '',
    )?.[1];
    expect(shownOn2).toMatch(/^[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$/);
    expect((await s.daemon.signer.client.listApprovers()).approvers).toHaveLength(1);
    const card = await approveOnPhone(s);
    expect(card).toContain(`check code ${shownOn2}`);
    await page2.waitForFunction(
      () => document.querySelector('#status')?.textContent === 'No pending requests.',
      undefined,
      { timeout: 15_000 },
    );
    expect((await s.daemon.signer.client.listApprovers()).approvers).toHaveLength(2);

    await signUp(s, 'pat');
    await s.agentPage.click('#add-passkey');
    const c2 = page2.locator('#requests .card').first();
    await c2.waitFor({ timeout: 15_000 });
    await c2.locator('.approve').click();
    expect(await rpStatus(s.agentPage)).toBe('passkey added');
    await expect(
      s.daemon.signer.client.removeApprover(
        (await s.daemon.signer.client.listApprovers()).approvers[0]?.credentialId as string,
      ),
    ).resolves.toEqual({ removed: true });
    await expect(
      s.daemon.signer.client.removeApprover(
        (await s.daemon.signer.client.listApprovers()).approvers[0]?.credentialId as string,
      ),
    ).rejects.toThrow('last_approver_needs_admin');
  });

  it('push: a phone whose subscription iOS dropped sends its current one again when the app opens', async () => {
    s = await startPhoneSetup();
    await pairPhone(s);
    const pushUrl = s.pushUrl;
    const subAt = (path: string) => {
      const ua = createECDH('prime256v1');
      ua.generateKeys();
      return {
        endpoint: new URL(path, pushUrl).href,
        keys: {
          p256dh: ua.getPublicKey().toString('base64url'),
          auth: Buffer.alloc(16, 7).toString('base64url'),
        },
      };
    };
    const st = await s.phonePage.evaluate(async (subscription) => {
      const r = await fetch('/api/push', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ subscription }),
      });
      return r.status;
    }, subAt('/push/dropped'));
    expect(st).toBe(200);
    await s.phonePage.addInitScript((sub) => {
      Object.defineProperty(Notification, 'permission', { get: () => 'granted' });
      const live = { endpoint: sub.endpoint, toJSON: () => sub };
      PushManager.prototype.getSubscription = async () => live as unknown as PushSubscription;
      PushManager.prototype.subscribe = async () => live as unknown as PushSubscription;
    }, subAt('/push/live'));
    const resent = s.phonePage.waitForResponse(
      (r) => new URL(r.url()).pathname === '/api/push' && r.request().method() === 'POST',
    );
    await s.phonePage.reload();
    expect((await resent).status()).toBe(200);
    expect(await s.phonePage.isVisible('#push')).toBe(false);

    await signUp(s, 'lou');
    await s.agentPage.click('#add-passkey');
    await approveOnPhone(s);
    expect(s.pushes.map((p) => p.url)).toEqual(['/push/live']);
  });

  it('push: a content-free, encrypted, VAPID-signed message reaches the push service', async () => {
    s = await startPhoneSetup();
    await pairPhone(s);
    const ua = createECDH('prime256v1');
    ua.generateKeys();
    const auth = Buffer.alloc(16, 7);
    const sub = {
      endpoint: s.pushUrl,
      keys: { p256dh: ua.getPublicKey().toString('base64url'), auth: auth.toString('base64url') },
    };
    const st = await s.phonePage.evaluate(async (subscription) => {
      const r = await fetch('/api/push', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ subscription }),
      });
      return r.status;
    }, sub);
    expect(st).toBe(200);

    await signUp(s, 'lou');
    await s.agentPage.click('#add-passkey');
    await approveOnPhone(s);
    expect(await rpStatus(s.agentPage)).toBe('passkey added');
    expect(s.pushes).toHaveLength(1);
    const p = s.pushes[0] as PhoneSetup['pushes'][number];
    expect(p.headers['content-encoding']).toBe('aes128gcm');
    expect(p.headers.ttl).toBe('60');

    const m = /^vapid t=([^,]+), k=(.+)$/.exec(p.headers.authorization ?? '');
    const [h, c, sig] = String(m?.[1]).split('.') as [string, string, string];
    const raw = Buffer.from(m?.[2] as string, 'base64url');
    const vapidPub = createPublicKey({
      key: {
        kty: 'EC',
        crv: 'P-256',
        x: raw.subarray(1, 33).toString('base64url'),
        y: raw.subarray(33).toString('base64url'),
      },
      format: 'jwk',
    });
    expect(
      verify(
        'sha256',
        Buffer.from(`${h}.${c}`),
        { key: vapidPub, dsaEncoding: 'ieee-p1363' },
        Buffer.from(sig, 'base64url'),
      ),
    ).toBe(true);
    expect(JSON.parse(Buffer.from(c, 'base64url').toString()).aud).toBe(new URL(s.pushUrl).origin);

    const salt = p.body.subarray(0, 16);
    const idlen = p.body[20] as number;
    const asPublic = p.body.subarray(21, 21 + idlen);
    const ct = p.body.subarray(21 + idlen);
    const ecdhSecret = ua.computeSecret(asPublic);
    const ikm = Buffer.from(
      hkdfSync(
        'sha256',
        ecdhSecret,
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
    expect(plain.toString()).toBe('{"t":"approval"}\u0002');
    const everything = `${JSON.stringify(p.headers)}${p.body.toString('latin1')}${plain}`;
    for (const leak of ['rp.localhost', 'sign me in', 'test-agent', 'passkey']) {
      expect(everything).not.toContain(leak);
    }
  });
});

describe('invariant 6: approvers that cannot verify the user never pass a high-risk origin', () => {
  it('a scripted Ed25519 approver that says yes is still denied (broker), and never reaches the signer', async () => {
    const h = await startHarness({ daemon: { highRiskDomains: ['rp.localhost'] } });
    try {
      await h.page.goto(`${h.rp.url}signup`);
      await h.page.fill('#username', 'max');
      await h.page.click('#signup');
      await h.page.click('#add-passkey');
      expect(await rpStatus(h.page)).toBe('error: NotAllowedError');
      expect(h.approver.seen.map((r) => r.policy.tier)).toEqual(['ask-strong']);
      const denied = h.daemon.broker.audit.all().filter((r) => r.event_type === 'denied');
      expect(JSON.parse(denied.at(-1)?.payload_json ?? '{}').reason).toBe(
        'user_verification_required',
      );
      expect(h.daemon.broker.credentials.passkeysForRp('rp.localhost')).toHaveLength(0);
    } finally {
      await h.close();
    }
  });

  it('the terminal approver denies a high-risk request without showing a prompt', async () => {
    const out: string[] = [];
    const { PassThrough } = await import('node:stream');
    const input = new PassThrough();
    const output = new PassThrough();
    output.on('data', (c: Buffer) => out.push(c.toString()));
    const key = ApproverKey.generate('terminal');
    const h = await startHarness({
      daemon: {
        highRiskDomains: ['rp.localhost'],
        approver: new TerminalApprover({ key, input, output }),
        trustedApproverKeys: key.trustEntry(),
      },
    });
    try {
      await h.page.goto(`${h.rp.url}signup`);
      await h.page.fill('#username', 'ned');
      await h.page.click('#signup');
      await h.page.click('#add-passkey');
      expect(await rpStatus(h.page)).toBe('error: NotAllowedError');
      expect(out.join('')).toBe('');
      const denied = h.daemon.broker.audit.all().filter((r) => r.event_type === 'denied');
      expect(JSON.parse(denied.at(-1)?.payload_json ?? '{}').reason).toBe(
        'approval_user_verification_unavailable',
      );
    } finally {
      await h.close();
    }
  });

  it('a plain origin still works with an approval under the default ask tier', async () => {
    const h = await startHarness();
    try {
      await h.page.goto(`${h.rp.url}signup`);
      await h.page.fill('#username', 'ola');
      await h.page.click('#signup');
      await h.page.click('#add-passkey');
      expect(await rpStatus(h.page)).toBe('passkey added');
      expect(h.approver.seen.map((r) => r.policy.tier)).toEqual(['ask']);
    } finally {
      await h.close();
    }
  });
});
