import {
  createDecipheriv,
  createECDH,
  createHash,
  generateKeyPairSync,
  hkdfSync,
  type KeyObject,
  randomBytes,
  sign,
} from 'node:crypto';
import { mkdtempSync, readFileSync } from 'node:fs';
import { createServer, type IncomingMessage, request, type Server } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { WebAuthnApproverKey } from '@aab/signer/approval';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { DeviceStore } from '../src/devices.ts';
import {
  type ApprovalRequest,
  type HandoffClip,
  type HandoffInput,
  type HandoffPort,
  type HandoffView,
  handoffStartChallenge,
} from '../src/index.ts';
import { PhoneApprover, parseHandoffClip, parseHandoffInput } from '../src/phone.ts';

const HOST = 'approver.localhost';

interface Res {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: Buffer;
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
        res.on('end', () => {
          const body = Buffer.concat(chunks);
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            body,
            text: body.toString(),
          });
        });
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
    assert(challenge: string, o: { flags?: number; signWith?: KeyObject; id?: string } = {}) {
      const cd = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin }));
      const ad = Buffer.concat([
        createHash('sha256').update(rpId).digest(),
        Buffer.of(o.flags ?? 0x05),
        Buffer.alloc(4),
      ]);
      const sig = sign('sha256', Buffer.concat([ad, createHash('sha256').update(cd).digest()]), {
        key: o.signWith ?? privateKey,
        dsaEncoding: 'der',
      });
      return {
        id: o.id ?? credentialId,
        response: {
          authenticatorData: ad.toString('base64url'),
          clientDataJSON: cd.toString('base64url'),
          signature: sig.toString('base64url'),
        },
      };
    },
  };
}

class FakePort implements HandoffPort {
  views = new Map<string, HandoffView>();
  controllers = new Map<string, string>();
  inputs: HandoffInput[] = [];
  finished: string[] = [];
  clips: (HandoffClip | undefined)[] = [];
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
    if (!this.views.has(id)) return 'not_found' as const;
    const c = this.controllers.get(id);
    if (c && c !== deviceId) return 'taken' as const;
    this.controllers.set(id, deviceId);
    return 'ok' as const;
  }
  async frame(id: string, deviceId: string, clip?: HandoffClip) {
    this.clips.push(clip);
    return this.controllers.get(id) === deviceId ? Buffer.from([0xff, 0xd8, 0xff, 0xd9]) : null;
  }
  async input(id: string, deviceId: string, input: HandoffInput) {
    if (this.controllers.get(id) !== deviceId)
      return { ok: false as const, reason: 'not_controller' as const };
    if (input.type === 'text' && input.text.includes('pw')) {
      return { ok: false as const, reason: 'sensitive_field' as const };
    }
    this.inputs.push(input);
    return { ok: true as const };
  }
  finish(id: string, deviceId: string, outcome: 'done' | 'cancelled') {
    if (this.controllers.get(id) !== deviceId || !this.views.has(id)) return false;
    this.views.delete(id);
    this.finished.push(outcome);
    return true;
  }
}

const VIEW: HandoffView = {
  id: '6f0a7c5e-1d0b-4c38-9d8e-2b1f3e4a5b6c',
  host: 'rp.localhost',
  agentName: 'test-agent',
  intentText: 'sign me in to the test site',
  intentAt: 1,
  openedAt: 2,
  expiresAt: Date.now() + 300_000,
};

describe('phone approver: handoff live view', () => {
  let approver: PhoneApprover;
  let port: number;
  let origin: string;
  let dir: string;
  let keys: WebAuthnApproverKey[];
  let phoneA: ReturnType<typeof softPhone>;
  let phoneB: ReturnType<typeof softPhone>;
  let cookieA: string;
  let cookieB: string;
  let nativeToken: string;
  let fake: FakePort;
  let pushServer: Server;
  let pushes: { headers: IncomingMessage['headers']; body: Buffer }[];
  let pushUrl: string;

  const post = (path: string, body: unknown, headers: Record<string, string> = {}) =>
    http(port, path, {
      method: 'POST',
      headers: { origin, 'content-type': 'application/json', ...headers },
      body: JSON.stringify(body),
    });
  const get = (path: string, headers: Record<string, string> = {}) => http(port, path, { headers });

  async function startView(cookie: string, phone: ReturnType<typeof softPhone>) {
    const ch = await post('/api/handoff/challenge', { id: VIEW.id }, { cookie });
    expect(ch.status).toBe(200);
    const c = JSON.parse(ch.text);
    return post(
      '/api/handoff/start',
      { id: VIEW.id, credential: phone.assert(c.challenge) },
      { cookie },
    );
  }

  beforeEach(async () => {
    dir = join(mkdtempSync(join(tmpdir(), 'keyflap-hand-')), 'approver');
    port = await freePort();
    origin = `http://${HOST}:${port}`;
    phoneA = softPhone(HOST, origin);
    phoneB = softPhone(HOST, origin);
    keys = [phoneA.key, phoneB.key];
    const { mkdirSync } = await import('node:fs');
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const store = new DeviceStore(join(dir, 'devices.json'));
    cookieA = `__Host-aab_device=${store.add(phoneA.key.credentialId).token}`;
    cookieB = `__Host-aab_device=${store.add(phoneB.key.credentialId).token}`;
    nativeToken = store.add(phoneA.key.credentialId, Date.now(), 'native').token;
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
    pushUrl = `http://127.0.0.1:${(pushServer.address() as { port: number }).port}/push/1`;
    approver = await PhoneApprover.start({
      dir,
      origin,
      listen: { host: '127.0.0.1', port },
      auditBefore: () => {},
      signer: {
        listApprovers: async () => ({
          approvers: keys,
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
      timeoutMs: 3_000,
    });
    fake = new FakePort();
    fake.views.set(VIEW.id, VIEW);
  });
  afterEach(async () => {
    await approver.close();
    await new Promise<void>((r) => pushServer.close(() => r()));
  });

  it('without attachHandoffs the endpoints do not exist', async () => {
    expect((await get('/api/handoff/state', { cookie: cookieA })).status).toBe(404);
    expect(approver.handoffAvailable()).toBe(true);
  });

  it('/handoff is its own document: strict CSP, no framing, no approval controls', async () => {
    const r = await get('/handoff');
    expect(r.status).toBe(200);
    const csp = r.headers['content-security-policy'] as string;
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("script-src 'self'");
    expect(csp).toContain("img-src 'self'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).not.toContain('unsafe');
    expect(csp).not.toMatch(/blob:|data:/);
    expect(r.headers['x-frame-options']).toBe('DENY');
    expect(r.headers['cache-control']).toBe('no-store');
    expect(r.text).toContain('<script src="/handoff.js" defer>');
    expect(r.text).not.toContain('/app.js');
    expect(r.text).not.toMatch(/class="approve"|>Approve</);
    expect(r.text).toContain('nothing here can approve a sign-in');
    expect(r.text).toContain("Don't type passwords here.");
    const js = (await get('/handoff.js')).text;
    expect(js).not.toMatch(/\/api\/state|\/api\/challenge|\/api\/decide/);
    expect(js.match(/navigator\.credentials\.\w+/g)).toEqual(['navigator.credentials.get']);
    expect(js).not.toMatch(/innerHTML|outerHTML|insertAdjacentHTML|document\.write/);
    const page = fileURLToPath(new URL('../src/page/handoff.js', import.meta.url));
    expect(readFileSync(page, 'utf8')).toBe(js);
  });

  describe('with handoffs attached', () => {
    beforeEach(() => approver.attachHandoffs(fake));

    it('needs the device cookie, our Host, Origin and JSON', async () => {
      expect((await get('/api/handoff/state')).status).toBe(401);
      expect((await get(`/api/handoff/frame?id=${VIEW.id}`)).status).toBe(401);
      expect((await post('/api/handoff/challenge', { id: VIEW.id })).status).toBe(401);
      expect(
        (
          await http(port, '/api/handoff/state', {
            headers: { host: 'evil.example', cookie: cookieA },
          })
        ).status,
      ).toBe(421);
      expect(
        (
          await post(
            '/api/handoff/challenge',
            { id: VIEW.id },
            { cookie: cookieA, origin: 'http://evil.localhost' },
          )
        ).status,
      ).toBe(403);
      expect(
        (
          await post(
            '/api/handoff/challenge',
            { id: VIEW.id },
            { cookie: cookieA, 'sec-fetch-site': 'cross-site' },
          )
        ).status,
      ).toBe(403);
      expect(
        (
          await get(`/api/handoff/frame?id=${VIEW.id}`, {
            cookie: cookieA,
            'sec-fetch-site': 'cross-site',
          })
        ).status,
      ).toBe(403);
      expect(
        (
          await post('/api/handoff/challenge', 'x', {
            cookie: cookieA,
            'content-type': 'text/plain',
          })
        ).status,
      ).toBe(415);
      expect(
        (await get('/api/handoff/state', { cookie: `__Host-aab_device=${nativeToken}` })).status,
      ).toBe(401);
    });

    it('state shows broker fields only; 404 for unknown ids or when nothing is open', async () => {
      const st = JSON.parse((await get('/api/handoff/state', { cookie: cookieA })).text);
      expect(st.handoffs).toEqual([
        {
          id: VIEW.id,
          host: 'rp.localhost',
          agentName: 'test-agent',
          intentText: 'sign me in to the test site',
          intentAt: 1,
          openedAt: 2,
          expiresAt: VIEW.expiresAt,
          withSignIn: false,
          started: false,
          mine: false,
        },
      ]);
      const other = '00000000-0000-4000-8000-000000000000';
      expect(
        (await post('/api/handoff/challenge', { id: other }, { cookie: cookieA })).status,
      ).toBe(404);
      expect(
        (await post('/api/handoff/challenge', { id: '../x' }, { cookie: cookieA })).status,
      ).toBe(400);
      fake.views.clear();
      expect(
        (await post('/api/handoff/challenge', { id: VIEW.id }, { cookie: cookieA })).status,
      ).toBe(404);
      expect(
        JSON.parse((await get('/api/handoff/state', { cookie: cookieA })).text).handoffs,
      ).toEqual([]);
    });

    it('frames only for the device that started it, and only after a valid start assertion', async () => {
      expect((await get(`/api/handoff/frame?id=${VIEW.id}`, { cookie: cookieA })).status).toBe(403);
      expect(
        (
          await post(
            '/api/handoff/input',
            { id: VIEW.id, input: { type: 'click', x: 0.5, y: 0.5 } },
            { cookie: cookieA },
          )
        ).status,
      ).toBe(403);
      const ch = JSON.parse(
        (await post('/api/handoff/challenge', { id: VIEW.id }, { cookie: cookieA })).text,
      );
      expect(ch.allowCredentials).toEqual([phoneA.key.credentialId]);
      expect(ch.rpId).toBe(HOST);
      const noUv = await post(
        '/api/handoff/start',
        { id: VIEW.id, credential: phoneA.assert(ch.challenge, { flags: 0x01 }) },
        { cookie: cookieA },
      );
      expect(noUv.status).toBe(400);
      expect(fake.controller(VIEW.id)).toBeNull();
      const ch2 = JSON.parse(
        (await post('/api/handoff/challenge', { id: VIEW.id }, { cookie: cookieA })).text,
      );
      const wrongKey = await post(
        '/api/handoff/start',
        { id: VIEW.id, credential: phoneB.assert(ch2.challenge) },
        { cookie: cookieA },
      );
      expect(wrongKey.status).toBe(403);
      const ok = await startView(cookieA, phoneA);
      expect(ok.status).toBe(200);
      expect(fake.controller(VIEW.id)).not.toBeNull();
      const f = await get(`/api/handoff/frame?id=${VIEW.id}`, { cookie: cookieA });
      expect(f.status).toBe(200);
      expect(f.headers['content-type']).toBe('image/jpeg');
      expect(f.headers['cache-control']).toBe('no-store');
      expect(f.headers['cross-origin-resource-policy']).toBe('same-origin');
      expect([...f.body]).toEqual([0xff, 0xd8, 0xff, 0xd9]);
      const zoomed = await get(`/api/handoff/frame?id=${VIEW.id}&clip=0.25,0.5,0.5,0.25`, {
        cookie: cookieA,
      });
      expect(zoomed.status).toBe(200);
      expect(fake.clips.at(-1)).toEqual({ x: 0.25, y: 0.5, w: 0.5, h: 0.25 });
      for (const bad of [
        '',
        '0.1,0.1,0.5',
        '0.6,0,0.5,0.5',
        '0,0,0.01,0.5',
        '-0,0,1,1',
        '1e-1,0,1,1',
        '0,0,1,1,1',
        '0.12345,0,0.5,0.5',
        'NaN,0,1,1',
      ]) {
        const r = await get(`/api/handoff/frame?id=${VIEW.id}&clip=${encodeURIComponent(bad)}`, {
          cookie: cookieA,
        });
        expect(r.status, bad).toBe(400);
        expect(() => parseHandoffClip(bad), bad).toThrow();
      }
      expect(parseHandoffClip(null)).toBeNull();
      expect(parseHandoffClip('0,0,1,1')).toEqual({ x: 0, y: 0, w: 1, h: 1 });
      expect((await get(`/api/handoff/frame?id=${VIEW.id}`, { cookie: cookieB })).status).toBe(403);
      expect(
        (await post('/api/handoff/challenge', { id: VIEW.id }, { cookie: cookieB })).status,
      ).toBe(409);
      const st = JSON.parse((await get('/api/handoff/state', { cookie: cookieB })).text);
      expect(st.handoffs[0]).toMatchObject({ started: true, mine: false });
      expect(
        (await post('/api/handoff/finish', { id: VIEW.id, outcome: 'done' }, { cookie: cookieB }))
          .status,
      ).toBe(403);
      expect(
        (await post('/api/handoff/finish', { id: VIEW.id, outcome: 'maybe' }, { cookie: cookieA }))
          .status,
      ).toBe(400);
      expect(
        (await post('/api/handoff/finish', { id: VIEW.id, outcome: 'done' }, { cookie: cookieA }))
          .status,
      ).toBe(200);
      expect(fake.finished).toEqual(['done']);
    });

    it('a start challenge is single use and expires with its ceremony', async () => {
      const ch = JSON.parse(
        (await post('/api/handoff/challenge', { id: VIEW.id }, { cookie: cookieA })).text,
      );
      const cred = phoneA.assert(ch.challenge);
      expect(
        (await post('/api/handoff/start', { id: VIEW.id, credential: cred }, { cookie: cookieA }))
          .status,
      ).toBe(200);
      expect(
        (await post('/api/handoff/start', { id: VIEW.id, credential: cred }, { cookie: cookieA }))
          .status,
      ).toBe(400);
      expect(
        (await post('/api/handoff/start', { id: VIEW.id, credential: cred }, { cookie: cookieB }))
          .status,
      ).toBe(400);
    });

    it('an approval assertion cannot start a handoff, and a start assertion cannot approve', async () => {
      const req: ApprovalRequest = {
        display: {
          intentText: 'sign me in',
          intentAt: 1,
          verifiedOrigin: 'https://example.com',
          agentName: 'agent',
          credentialType: 'passkey',
          action: 'sign-in',
        },
        policy: { tier: 'ask' },
        binding: {
          requestId: 'r1',
          kind: 'webauthn.get',
          rpId: 'example.com',
          credentialId: 'c1',
          intentHash: 'aA',
          clientDataHash: 'bB',
        },
      };
      const decision = approver.request(req);
      const ac = JSON.parse((await post('/api/challenge', { id: 'r1' }, { cookie: cookieA })).text);
      const approvalAssertion = phoneA.assert(ac.challenge);
      await post('/api/handoff/challenge', { id: VIEW.id }, { cookie: cookieA });
      const r = await post(
        '/api/handoff/start',
        { id: VIEW.id, credential: approvalAssertion },
        { cookie: cookieA },
      );
      expect(r.status).toBe(400);
      expect(fake.controller(VIEW.id)).toBeNull();
      const sc = JSON.parse(
        (await post('/api/handoff/challenge', { id: VIEW.id }, { cookie: cookieA })).text,
      );
      const startAssertion = phoneA.assert(sc.challenge);
      const d = await post(
        '/api/decide',
        { id: 'r1', decision: 'approve', credential: startAssertion },
        { cookie: cookieA },
      );
      expect(d.status).toBe(400);
      expect(JSON.parse(d.text).error).toBe('assertion_challenge_mismatch');
      expect(handoffStartChallenge(VIEW.id, 'n')).not.toBe(ac.challenge);
      await post('/api/decide', { id: 'r1', decision: 'deny' }, { cookie: cookieA });
      expect(await decision).toEqual({ approved: false, reason: 'user_denied' });
    });

    it('validates every input strictly; refuses text into password fields with a fixed message', async () => {
      expect((await startView(cookieA, phoneA)).status).toBe(200);
      const send = (input: unknown) =>
        post('/api/handoff/input', { id: VIEW.id, input }, { cookie: cookieA });
      const bad: unknown[] = [
        null,
        'click',
        { type: 'click', x: 1.5, y: 0 },
        { type: 'click', x: -0.1, y: 0 },
        { type: 'click', x: 0.5 },
        { type: 'click', x: 0.5, y: 0.5, button: 'right' },
        { type: 'scroll', dy: 0.5 },
        { type: 'scroll', dy: 100_000 },
        { type: 'drag', from: { x: 0, y: 0 } },
        { type: 'drag', from: { x: 0, y: 0 }, to: { x: 2, y: 0 } },
        { type: 'key', key: 'F12' },
        { type: 'key', key: 'Control+Shift+I' },
        { type: 'text', text: '' },
        { type: 'text', text: 'x'.repeat(257) },
        { type: 'text', text: 'line\nbreak' },
        { type: 'text', text: 'esc\u001b[2J' },
        { type: 'eval', code: '1' },
      ];
      for (const b of bad) {
        expect((await send(b)).status, JSON.stringify(b)).toBe(400);
        expect(parseHandoffInput(b)).toBeNull();
      }
      expect(fake.inputs).toEqual([]);
      const good: HandoffInput[] = [
        { type: 'click', x: 0.5, y: 0.25 },
        { type: 'scroll', dy: -400 },
        { type: 'drag', from: { x: 0.1, y: 0.2 }, to: { x: 0.9, y: 0.2 } },
        { type: 'key', key: 'Enter' },
        { type: 'text', text: 'Main Street 1' },
      ];
      for (const g of good) expect((await send(g)).status).toBe(200);
      expect(fake.inputs).toEqual(good);
      const refused = await send({ type: 'text', text: 'my-pw' });
      expect(refused.status).toBe(422);
      expect(JSON.parse(refused.text)).toEqual({
        error: 'sensitive_field',
        message: "Use the broker's sign-in for passwords",
      });
    });

    it('handoffs are never in `pending`: a link on the web state, nothing on the native one', async () => {
      const st = JSON.parse((await get('/api/state', { cookie: cookieA })).text);
      expect(st.pending).toEqual([]);
      expect(st.handoffs).toEqual([{ id: VIEW.id, host: 'rp.localhost', agentName: 'test-agent' }]);
      const native = JSON.parse(
        (await get('/api/native/state', { authorization: `Bearer ${nativeToken}` })).text,
      );
      expect(native.pending).toEqual([]);
      expect(native.handoffs).toBeUndefined();
      expect(JSON.stringify(native)).not.toContain(VIEW.id);
      expect(
        (await get('/api/handoff/state', { authorization: `Bearer ${nativeToken}` })).status,
      ).toBe(401);
    });

    it('Web Push: an encrypted {"t":"handoff","host"} payload, nothing else', async () => {
      const ua = createECDH('prime256v1');
      ua.generateKeys();
      const auth = Buffer.alloc(16, 9);
      const sub = {
        endpoint: pushUrl,
        keys: { p256dh: ua.getPublicKey().toString('base64url'), auth: auth.toString('base64url') },
      };
      expect((await post('/api/push', { subscription: sub }, { cookie: cookieA })).status).toBe(
        200,
      );
      await approver.notifyHandoff(VIEW);
      expect(pushes).toHaveLength(1);
      const p = pushes[0] as (typeof pushes)[number];
      expect(p.headers['content-encoding']).toBe('aes128gcm');
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
      expect(plain.toString()).toBe('{"t":"handoff","host":"rp.localhost"}\u0002');
      const raw = `${JSON.stringify(p.headers)}${p.body.toString('latin1')}`;
      for (const leak of ['rp.localhost', 'test-agent', 'sign me in', VIEW.id]) {
        expect(raw).not.toContain(leak);
      }
    });
  });
});
