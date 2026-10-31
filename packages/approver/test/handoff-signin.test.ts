import {
  createDecipheriv,
  createECDH,
  createHash,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  sign,
} from 'node:crypto';
import { mkdirSync, mkdtempSync } from 'node:fs';
import { createServer, type IncomingMessage, request, type Server } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';
import {
  approvalChallenge,
  HANDOFF_GRANT_MAX_MS,
  type WebAuthnApproverKey,
} from '@aab/signer/approval';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { DeviceStore } from '../src/devices.ts';
import {
  type ApprovalDecision,
  type ApprovalRequest,
  ApproverKey,
  buildStatement,
  type HandoffPort,
  type HandoffView,
  renderPrompt,
  requestProblem,
  TerminalApprover,
} from '../src/index.ts';
import { PhoneApprover } from '../src/phone.ts';

const HOST = 'approver.localhost';
const HANDOFF_ID = '6f0a7c5e-1d0b-4c38-9d8e-2b1f3e4a5b6c';

interface Res {
  status: number;
  text: string;
}

function http(
  port: number,
  path: string,
  o: { method?: string; headers?: Record<string, string>; body?: string } = {},
): Promise<Res> {
  return new Promise((resolve, reject) => {
    const r = request(
      {
        host: '127.0.0.1',
        port,
        path,
        method: o.method ?? 'GET',
        headers: { host: `${HOST}:${port}`, ...o.headers },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () =>
          resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() }),
        );
      },
    );
    r.on('error', reject);
    r.end(o.body);
  });
}

async function freePort(): Promise<number> {
  const { createServer: net } = await import('node:net');
  return new Promise((resolve) => {
    const s = net().listen(0, '127.0.0.1', () => {
      const p = (s.address() as { port: number }).port;
      s.close(() => resolve(p));
    });
  });
}

function softPhone(rpId: string, origin: string) {
  const credentialId = randomBytes(32).toString('base64url');
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' });
  const key: WebAuthnApproverKey = {
    credentialId,
    x: jwk.x as string,
    y: jwk.y as string,
    rpId,
    origin,
    signCount: 0,
    createdAt: 0,
  };
  return {
    key,
    assert(challenge: string) {
      const cd = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin }));
      const ad = Buffer.concat([
        createHash('sha256').update(rpId).digest(),
        Buffer.of(0x05),
        Buffer.alloc(4),
      ]);
      const sig = sign('sha256', Buffer.concat([ad, createHash('sha256').update(cd).digest()]), {
        key: privateKey,
        dsaEncoding: 'der',
      });
      return {
        id: credentialId,
        response: {
          authenticatorData: ad.toString('base64url'),
          clientDataJSON: cd.toString('base64url'),
          signature: sig.toString('base64url'),
        },
      };
    },
  };
}

function combined(over: Partial<ApprovalRequest['display']> = {}): ApprovalRequest {
  return {
    display: {
      intentText: 'sign me in to the test site',
      intentAt: 1,
      verifiedOrigin: 'http://rp.localhost:3000',
      agentName: 'test-agent',
      credentialType: 'password',
      action: 'sign-in',
      handoffSignIn: { withinMs: HANDOFF_GRANT_MAX_MS },
      ...over,
    },
    binding: {
      requestId: randomBytes(16).toString('hex'),
      kind: 'fill',
      rpId: 'rp.localhost',
      credentialId: 'item-1',
      intentHash: 'aW50ZW50',
      clientDataHash: 'c2NvcGU',
      grant: { agentId: 'agent-1', durationMs: HANDOFF_GRANT_MAX_MS, uses: 1 },
      handoff: { id: HANDOFF_ID },
    },
    policy: { tier: 'ask' },
  };
}

class FakePort implements HandoffPort {
  views = new Map<string, HandoffView>();
  controllers = new Map<string, string>();
  started: string[] = [];
  list() {
    return [...this.views.values()];
  }
  get(id: string) {
    return this.views.get(id) ?? null;
  }
  controller(id: string) {
    return this.controllers.get(id) ?? null;
  }
  start(id: string, deviceId: string) {
    this.started.push(deviceId);
    return this.views.get(id)?.withSignIn ? ('approval_only' as const) : ('ok' as const);
  }
  async frame() {
    return null;
  }
  async input() {
    return { ok: false as const, reason: 'not_open' as const };
  }
  finish() {
    return false;
  }
}

describe('P3b: one approval for a human check and the sign-in after it (phone approver)', () => {
  let approver: PhoneApprover;
  let port: number;
  let origin: string;
  let phoneA: ReturnType<typeof softPhone>;
  let phoneB: ReturnType<typeof softPhone>;
  let cookieA: string;
  let cookieB: string;
  let deviceA: string;
  let nativeToken: string;
  let fake: FakePort;
  let pushServer: Server;
  let pushes: { headers: IncomingMessage['headers']; body: Buffer }[];
  let apnsSent: unknown[];
  const ua = createECDH('prime256v1');
  ua.generateKeys();
  const auth = Buffer.alloc(16, 7);

  const post = (path: string, body: unknown, headers: Record<string, string> = {}) =>
    http(port, path, {
      method: 'POST',
      headers: { origin, 'content-type': 'application/json', ...headers },
      body: JSON.stringify(body),
    });
  const get = (path: string, headers: Record<string, string> = {}) => http(port, path, { headers });
  const decrypt = (body: Buffer) => {
    const salt = body.subarray(0, 16);
    const idlen = body[20] as number;
    const asPublic = body.subarray(21, 21 + idlen);
    const ct = body.subarray(21 + idlen);
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
  };

  beforeEach(async () => {
    const dir = join(mkdtempSync(join(tmpdir(), 'keyflap-hsi-')), 'approver');
    port = await freePort();
    origin = `http://${HOST}:${port}`;
    phoneA = softPhone(HOST, origin);
    phoneB = softPhone(HOST, origin);
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    pushes = [];
    pushServer = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (c: Buffer) => chunks.push(c));
      req.on('end', () => {
        pushes.push({ headers: req.headers, body: Buffer.concat(chunks) });
        res.writeHead(201).end();
      });
    });
    await new Promise<void>((r) => pushServer.listen(0, '127.0.0.1', () => r()));
    const pushUrl = `http://127.0.0.1:${(pushServer.address() as { port: number }).port}/push/1`;
    const store = new DeviceStore(join(dir, 'devices.json'));
    const a = store.add(phoneA.key.credentialId);
    deviceA = a.device.id;
    cookieA = `__Host-aab_device=${a.token}`;
    cookieB = `__Host-aab_device=${store.add(phoneB.key.credentialId).token}`;
    store.setPush(deviceA, {
      endpoint: pushUrl,
      keys: { p256dh: ua.getPublicKey().toString('base64url'), auth: auth.toString('base64url') },
    });
    const native = store.add(phoneA.key.credentialId, Date.now(), 'native');
    nativeToken = native.token;
    store.setApns(native.device.id, { token: 'ab'.repeat(32), environment: 'sandbox' });
    apnsSent = [];
    approver = await PhoneApprover.start({
      dir,
      origin,
      listen: { host: '127.0.0.1', port },
      auditBefore: () => {},
      signer: {
        listApprovers: async () => ({
          approvers: [phoneA.key, phoneB.key],
          native: [
            {
              keyId: phoneA.key.credentialId,
              x: 'x',
              y: 'y',
              origin,
              userVerification: 'biometry' as const,
              createdAt: 0,
            },
          ],
        }),
        addApprover: async () => ({ added: true }),
      },
      allowInsecurePushEndpoints: true,
      apns: {
        send: async (_t: string, _e: unknown, n: unknown) => {
          apnsSent.push(n);
          return 'sent';
        },
      } as never,
      timeoutMs: 5_000,
    });
    fake = new FakePort();
    fake.views.set(HANDOFF_ID, {
      id: HANDOFF_ID,
      host: 'rp.localhost',
      agentName: 'test-agent',
      intentText: 'sign me in to the test site',
      intentAt: 1,
      openedAt: 2,
      expiresAt: Date.now() + 300_000,
      withSignIn: true,
    });
    approver.attachHandoffs(fake);
  });
  afterEach(async () => {
    await approver.close();
    await new Promise<void>((r) => pushServer.close(() => r()));
  });

  it('a normal card on the approvals page with only broker fields; the handoff has no link card yet', async () => {
    const req = combined();
    const decision = approver.request(req);
    await expect.poll(() => pushes.length).toBe(1);
    expect(decrypt(pushes[0]?.body as Buffer)).toBe('{"t":"approval"}');
    expect(apnsSent).toEqual([]);
    const st = JSON.parse((await get('/api/state', { cookie: cookieA })).text);
    expect(st.pending).toHaveLength(1);
    expect(st.pending[0]).toEqual({
      id: req.binding.requestId,
      createdAt: expect.any(Number),
      kind: 'credential',
      display: req.display,
    });
    expect(Object.keys(st.pending[0].display).sort()).toEqual([
      'action',
      'agentName',
      'credentialType',
      'handoffSignIn',
      'intentAt',
      'intentText',
      'verifiedOrigin',
    ]);
    expect(st.handoffs).toEqual([]);
    const native = JSON.parse(
      (await get('/api/native/state', { authorization: `Bearer ${nativeToken}` })).text,
    );
    expect(native.pending).toEqual([]);
    expect(
      (
        await post(
          '/api/native/challenge',
          { id: req.binding.requestId },
          { authorization: `Bearer ${nativeToken}` },
        )
      ).status,
    ).toBe(404);
    await post('/api/decide', { id: req.binding.requestId, decision: 'deny' }, { cookie: cookieA });
    expect(await decision).toEqual({ approved: false, reason: 'user_denied' });
  });

  it("only the approving device's own passkey approves, and the decision names that device", async () => {
    const req = combined();
    const decision = approver.request(req);
    await expect.poll(() => pushes.length).toBe(1);
    const ch = await post('/api/challenge', { id: req.binding.requestId }, { cookie: cookieA });
    expect(ch.status).toBe(200);
    const c = JSON.parse(ch.text);
    expect(c.allowCredentials).toEqual([phoneA.key.credentialId]);
    const wrong = await post(
      '/api/decide',
      { id: req.binding.requestId, decision: 'approve', credential: phoneB.assert(c.challenge) },
      { cookie: cookieA },
    );
    expect(wrong.status).toBe(403);
    const ok = await post(
      '/api/decide',
      { id: req.binding.requestId, decision: 'approve', credential: phoneA.assert(c.challenge) },
      { cookie: cookieA },
    );
    expect(ok.status).toBe(200);
    const d = (await decision) as Extract<ApprovalDecision, { approved: true }>;
    expect(d.approved).toBe(true);
    expect(d.deviceId).toBe(deviceA);
    const s = d.approval.statement;
    expect(s.handoff).toEqual({ id: HANDOFF_ID });
    expect(s.grant).toEqual({
      agentId: 'agent-1',
      until: s.issuedAt + HANDOFF_GRANT_MAX_MS,
      uses: 1,
    });
    expect(s.strong).toBeUndefined();
    expect(c.challenge).toBe(approvalChallenge(s));
    const req2 = combined();
    const d2 = approver.request(req2);
    await expect.poll(() => pushes.length).toBe(2);
    const ch2 = JSON.parse(
      (await post('/api/challenge', { id: req2.binding.requestId }, { cookie: cookieB })).text,
    );
    expect(ch2.allowCredentials).toEqual([phoneB.key.credentialId]);
    await post(
      '/api/decide',
      { id: req2.binding.requestId, decision: 'deny' },
      { cookie: cookieB },
    );
    expect((await d2).approved).toBe(false);
  });

  it('/handoff can never start a combined handoff with its own Face ID check', async () => {
    const ch = await post('/api/handoff/challenge', { id: HANDOFF_ID }, { cookie: cookieA });
    expect(ch.status).toBe(409);
    expect(JSON.parse(ch.text).error).toBe('started_by_approval');
    const st = await post(
      '/api/handoff/start',
      { id: HANDOFF_ID, credential: phoneA.assert('x') },
      { cookie: cookieA },
    );
    expect(st.status).toBe(400);
    expect(fake.started).toEqual([]);
    const hs = JSON.parse((await get('/api/handoff/state', { cookie: cookieA })).text);
    expect(hs.handoffs[0]).toMatchObject({ id: HANDOFF_ID, withSignIn: true, started: false });
    fake.controllers.set(HANDOFF_ID, deviceA);
    const st2 = JSON.parse((await get('/api/state', { cookie: cookieA })).text);
    expect(st2.handoffs).toEqual([
      { id: HANDOFF_ID, host: 'rp.localhost', agentName: 'test-agent' },
    ]);
    const mine = JSON.parse((await get('/api/handoff/state', { cookie: cookieA })).text);
    expect(mine.handoffs[0]).toMatchObject({ started: true, mine: true, withSignIn: true });
  });

  it('the statement matches the card; inconsistent requests are refused unseen', async () => {
    const req = combined();
    expect(requestProblem(req)).toBeNull();
    const s = buildStatement(req, { userVerified: true, now: 1000 });
    expect(s.grant).toEqual({ agentId: 'agent-1', until: 1000 + HANDOFF_GRANT_MAX_MS, uses: 1 });
    expect(s.handoff).toEqual({ id: HANDOFF_ID });
    const bad: ApprovalRequest[] = [
      combined({ handoffSignIn: { withinMs: 60_000 } }),
      combined({ handoffSignIn: { withinMs: HANDOFF_GRANT_MAX_MS + 1 } }),
      combined({ allowForMs: HANDOFF_GRANT_MAX_MS }),
      combined({ keepSignedInSite: 'rp.localhost' }),
      combined({ action: 'register' }),
      { ...combined(), policy: { tier: 'ask-strong' } },
      { ...combined(), binding: { ...combined().binding, handoff: undefined } },
      {
        ...combined(),
        binding: {
          ...combined().binding,
          grant: { agentId: 'agent-1', durationMs: HANDOFF_GRANT_MAX_MS },
        },
      },
      { ...combined(), binding: { ...combined().binding, kind: 'webauthn.create' } },
      { ...combined(), binding: { ...combined().binding, handoff: { id: '../x' } } },
    ];
    for (const r of bad) expect(requestProblem(r)).toBe('inconsistent_request');
    const before = pushes.length;
    expect(await approver.request(bad[5] as ApprovalRequest)).toEqual({
      approved: false,
      reason: 'inconsistent_request',
    });
    expect(pushes.length).toBe(before);
  });

  it('the terminal approver (no live view) refuses a combined request without prompting', async () => {
    const out = new PassThrough();
    let printed = '';
    out.on('data', (c: Buffer) => {
      printed += c.toString();
    });
    const t = new TerminalApprover({
      key: ApproverKey.generate(),
      input: new PassThrough(),
      output: out,
    });
    expect(await t.request(combined())).toEqual({ approved: false, reason: 'handoff_unsupported' });
    expect(printed).toBe('');
    expect(renderPrompt(combined())).toContain('Human check, then sign in to rp.localhost:3000');
  });
});
