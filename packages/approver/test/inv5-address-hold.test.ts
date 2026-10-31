import { createECDH, createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { mkdirSync, mkdtempSync } from 'node:fs';
import { createServer, request } from 'node:http';
import { createServer as createTcpServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { WebAuthnApproverKey } from '@aab/signer/approval';
import type { AddressState } from '@aab/signer/approver-address';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ApproverAddressSync } from '../src/address-sync.ts';
import { DeviceStore } from '../src/devices.ts';
import type { ApprovalDecision, ApprovalRequest } from '../src/index.ts';
import { PairingRefused, PhoneApprover } from '../src/phone.ts';

const HOST = 'approver.localhost';
const COOKIE = '__Host-aab_device';

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

function req(id: string): ApprovalRequest {
  return {
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
      requestId: id,
      kind: 'webauthn.get',
      rpId: 'example.com',
      credentialId: 'c1',
      intentHash: 'aA',
      clientDataHash: 'bB',
    },
  };
}

function freePort(): Promise<number> {
  return new Promise((resolve) => {
    const s = createTcpServer().listen(0, '127.0.0.1', () => {
      const p = (s.address() as { port: number }).port;
      s.close(() => resolve(p));
    });
  });
}

interface Res {
  status: number;
  json: Record<string, unknown>;
}

function http(port: number, path: string, o: { cookie: string; body?: unknown }): Promise<Res> {
  const origin = `http://${HOST}:${port}`;
  return new Promise((resolve, reject) => {
    const r = request(
      {
        host: '127.0.0.1',
        port,
        path,
        method: o.body === undefined ? 'GET' : 'POST',
        headers: {
          host: `${HOST}:${port}`,
          cookie: o.cookie,
          ...(o.body === undefined ? {} : { origin, 'content-type': 'application/json' }),
        },
      },
      (res) => {
        let text = '';
        res.on('data', (c) => {
          text += c;
        });
        res.on('end', () =>
          resolve({ status: res.statusCode ?? 0, json: text ? JSON.parse(text) : {} }),
        );
      },
    );
    r.on('error', reject);
    r.end(o.body === undefined ? undefined : JSON.stringify(o.body));
  });
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const until = async (ok: () => boolean, what: string) => {
  for (let i = 0; i < 400 && !ok(); i++) await sleep(5);
  if (!ok()) throw new Error(`timed out waiting for ${what}`);
};

const settled = (p: Promise<ApprovalDecision>) => {
  let done: ApprovalDecision | null = null;
  void p.then((d) => {
    done = d;
  });
  return () => done;
};

describe('invariant 5 (the approval address): a short Tailscale pause keeps pending approvals waiting', () => {
  let approver: PhoneApprover;
  let sync: ApproverAddressSync;
  let port: number;
  let cookie: string;
  let phone: ReturnType<typeof softPhone>;
  let signerState: AddressState;
  let audit: { event: string; fields: Record<string, unknown> }[];
  let pushes: string[];
  let pushServer: ReturnType<typeof createServer>;

  const hold = (detail: string, forMs = 10_000): AddressState => ({
    kind: 'paused',
    since: Date.now(),
    detail,
    graceUntil: Date.now() + forMs,
  });
  const warnings = () => pushes.filter((ttl) => ttl === '300');
  const challenge = (id: string) => http(port, '/api/challenge', { cookie, body: { id } });
  const decide = (id: string, credential: unknown) =>
    http(port, '/api/decide', { cookie, body: { id, decision: 'approve', credential } });
  const signedFor = (c: Res) => phone.assert(c.json.challenge as string);
  const pollsSettle = () => sleep(60);

  beforeEach(async () => {
    const dir = join(mkdtempSync(join(tmpdir(), 'keyflap-hold-')), 'approver');
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    port = await freePort();
    const origin = `http://${HOST}:${port}`;
    phone = softPhone(HOST, origin);
    pushes = [];
    pushServer = createServer((r, res) => {
      pushes.push(String(r.headers.ttl));
      res.writeHead(201).end();
    });
    const pushPort = await new Promise<number>((resolve) =>
      pushServer.listen(0, '127.0.0.1', () =>
        resolve((pushServer.address() as { port: number }).port),
      ),
    );
    const devices = new DeviceStore(join(dir, 'devices.json'));
    const { device, token } = devices.add(phone.key.credentialId, 0, 'web');
    const ecdh = createECDH('prime256v1');
    ecdh.generateKeys();
    devices.setPush(device.id, {
      endpoint: `http://127.0.0.1:${pushPort}/push`,
      keys: {
        p256dh: ecdh.getPublicKey().toString('base64url'),
        auth: randomBytes(16).toString('base64url'),
      },
    });
    cookie = `${COOKIE}=${token}`;
    approver = await PhoneApprover.start({
      dir,
      origin,
      listen: { host: '127.0.0.1', port },
      auditBefore: () => {},
      allowInsecurePushEndpoints: true,
      platformWord: 'Mac',
      signer: {
        listApprovers: async () => ({ approvers: [phone.key] }),
        addApprover: async () => ({ added: true }),
      },
      timeoutMs: 20_000,
    });
    signerState = { kind: 'ok', checkedAt: 1 };
    audit = [];
    sync = new ApproverAddressSync({
      signer: { approverAddress: async () => ({ state: signerState }) },
      phone: approver,
      audit: (event, fields) => audit.push({ event, fields }),
      pollMs: { idle: 10, fast: 5 },
    });
    await sync.start();
  });
  afterEach(async () => {
    sync.stop();
    await approver.close();
    await new Promise((r) => pushServer.close(r));
  });

  it('a restart (not running, an unreadable token, nothing served, then correct) cancels nothing, and the approval completes after it', async () => {
    const decision = approver.request(req('r1'));
    const outcome = settled(decision);
    await until(() => approver.busy(), 'the request to be pending');
    const early = await challenge('r1');
    expect(early.status).toBe(200);
    const heldAssertion = signedFor(early);

    const pausedAt = Date.now();
    const restart = [
      'Tailscale is not running',
      "Tailscale's token cannot be read",
      'Tailscale is not connected',
    ];
    for (const detail of restart) {
      signerState = { kind: 'paused', detail, since: pausedAt, graceUntil: pausedAt + 10_000 };
      await pollsSettle();
      expect(outcome()).toBeNull();
      expect(approver.busy()).toBe(true);
      const page = await http(port, '/api/state', { cookie });
      expect(page.status).toBe(200);
      expect(page.json.address).toBeUndefined();
      expect(page.json.pending).toHaveLength(1);
      expect(await challenge('r1')).toMatchObject({
        status: 503,
        json: { error: 'approver_address_unverified' },
      });
      expect(await decide('r1', heldAssertion)).toMatchObject({
        status: 503,
        json: { error: 'approver_address_unverified' },
      });
      expect(() => approver.startPairing()).toThrow(PairingRefused);
    }
    expect(outcome()).toBeNull();
    expect(warnings()).toEqual([]);
    expect(audit.map((a) => a.event)).toEqual(restart.map(() => 'approver.address_unreadable'));

    signerState = { kind: 'ok', checkedAt: Date.now() };
    await until(() => audit.length === restart.length + 1, 'the readable audit event');
    expect(audit.at(-1)).toEqual({
      event: 'approver.address_readable',
      fields: { origin: approver.origin },
    });
    const fresh = await challenge('r1');
    expect(fresh.status).toBe(200);
    expect(await decide('r1', signedFor(fresh))).toMatchObject({ status: 200 });
    await expect(decision).resolves.toMatchObject({ approved: true });
  });

  it('a request that arrives during the pause is refused, not queued or pushed; one already waiting can still be denied', async () => {
    const waiting = approver.request(req('r2'));
    await until(() => approver.busy(), 'the request to be pending');
    await until(() => pushes.length > 0, 'the push for the waiting request');
    const pushed = pushes.length;
    for (const detail of ['Tailscale is not connected', 'Tailscale is not running']) {
      signerState = hold(detail);
      await pollsSettle();
      await expect(approver.request(req(`late-${detail}`))).resolves.toEqual({
        approved: false,
        reason: 'approver_address_unverified',
      });
    }
    await sleep(50);
    expect(pushes).toHaveLength(pushed);
    expect(
      await http(port, '/api/decide', { cookie, body: { id: 'r2', decision: 'deny' } }),
    ).toMatchObject({ status: 200 });
    await expect(waiting).resolves.toEqual({ approved: false, reason: 'user_denied' });
  });

  it('pairing a phone during the pause is refused before any passkey is made', async () => {
    const code = approver.startPairing().split('#')[1];
    signerState = hold('Tailscale is not connected');
    await pollsSettle();
    const refused = { status: 503, json: { error: 'approver_address_unverified' } };
    expect(await http(port, '/api/pair/options', { cookie: '', body: { code } })).toMatchObject(
      refused,
    );
    expect(
      await http(port, '/api/pair/finish', { cookie: '', body: { code, response: {} } }),
    ).toMatchObject(refused);
    signerState = { kind: 'ok', checkedAt: Date.now() };
    await pollsSettle();
    expect(await http(port, '/api/pair/options', { cookie: '', body: { code } })).toMatchObject({
      status: 200,
    });
  });

  it('a pause that outlasts its grace cancels what waits, as any pause does, and tells the page', async () => {
    const decision = approver.request(req('r3'));
    await until(() => approver.busy(), 'the request to be pending');
    signerState = hold('Tailscale is not connected', 150);
    await pollsSettle();
    expect(approver.busy()).toBe(true);
    await expect(decision).resolves.toEqual({
      approved: false,
      reason: 'approver_address_unverified',
    });
    const page = await http(port, '/api/state', { cookie });
    expect(page.json.address).toEqual({
      kind: 'paused',
      detail: 'Tailscale is not connected',
      on: 'Mac',
    });
    await expect(approver.request(req('r4'))).resolves.toEqual({
      approved: false,
      reason: 'approver_address_unverified',
    });
    expect(warnings()).toEqual([]);
  });

  it('a pause with no grace cancels at once, as before', async () => {
    const decision = approver.request(req('r5'));
    await until(() => approver.busy(), 'the request to be pending');
    signerState = { kind: 'paused', since: Date.now(), detail: 'tailscale timed out' };
    await expect(decision).resolves.toEqual({
      approved: false,
      reason: 'approver_address_unverified',
    });
  });

  it('a trip during the pause still cancels, warns and signs out', async () => {
    const decision = approver.request(req('r6'));
    await until(() => approver.busy(), 'the request to be pending');
    signerState = hold('Tailscale is not running');
    await pollsSettle();
    signerState = { kind: 'latched', at: Date.now(), seen: 'h:8766 proxies to http://x:1' };
    await expect(decision).resolves.toEqual({
      approved: false,
      reason: 'approver_address_changed',
    });
    expect(warnings()).toHaveLength(1);
    expect(approver.handoffAvailable()).toBe(false);
  });
});
