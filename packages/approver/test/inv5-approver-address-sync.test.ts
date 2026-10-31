import { createECDH, randomBytes } from 'node:crypto';
import { mkdirSync, mkdtempSync } from 'node:fs';
import { createServer, request } from 'node:http';
import { createServer as createTcpServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { WebAuthnApproverKey } from '@aab/signer/approval';
import type { AddressState } from '@aab/signer/approver-address';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ApproverAddressSync, sameAddressState } from '../src/address-sync.ts';
import { DeviceStore } from '../src/devices.ts';
import type { ApprovalRequest } from '../src/index.ts';
import { PairingRefused, PhoneApprover } from '../src/phone.ts';

const HOST = 'approver.localhost';
const COOKIE = '__Host-aab_device';

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

function http(
  port: number,
  path: string,
  headers: Record<string, string> = {},
): Promise<{ status: number; json: Record<string, unknown> }> {
  return new Promise((resolve, reject) => {
    const r = request(
      { host: '127.0.0.1', port, path, headers: { host: `${HOST}:${port}`, ...headers } },
      (res) => {
        let body = '';
        res.on('data', (c) => {
          body += c;
        });
        res.on('end', () =>
          resolve({ status: res.statusCode ?? 0, json: body ? JSON.parse(body) : {} }),
        );
      },
    );
    r.on('error', reject);
    r.end();
  });
}

function post(port: number, path: string, body: unknown): Promise<number> {
  return new Promise((resolve, reject) => {
    const r = request(
      {
        host: '127.0.0.1',
        port,
        path,
        method: 'POST',
        headers: {
          host: `${HOST}:${port}`,
          origin: `http://${HOST}:${port}`,
          'content-type': 'application/json',
        },
      },
      (res) => {
        res.resume();
        res.on('end', () => resolve(res.statusCode ?? 0));
      },
    );
    r.on('error', reject);
    r.end(JSON.stringify(body));
  });
}

const until = async (ok: () => boolean, what: string) => {
  for (let i = 0; i < 400 && !ok(); i++) await new Promise((r) => setTimeout(r, 5));
  if (!ok()) throw new Error(`timed out waiting for ${what}`);
};

const warningsOf = (pushes: { ttl: string; devicesLeft: boolean }[]) =>
  pushes.filter((p) => p.ttl === '300');

const OK: AddressState = { kind: 'ok', checkedAt: 1 };
const LATCHED: AddressState = { kind: 'latched', at: 2, seen: 'h:8766 proxies to http://x:1' };
const PAUSED: AddressState = { kind: 'paused', since: 3, detail: 'tailscale timed out' };

describe('invariant 5 (the approval address): the core side', () => {
  let approver: PhoneApprover;
  let sync: ApproverAddressSync;
  let port: number;
  let origin: string;
  let cookie: string;
  let signerState: AddressState;
  let polls: { pending: boolean }[];
  let listCalls: number;
  let audit: { event: string; fields: Record<string, unknown> }[];
  let pushes: { ttl: string; devicesLeft: boolean }[];
  let pushServer: ReturnType<typeof createServer>;
  const warnings = () => warningsOf(pushes);

  beforeEach(async () => {
    const dir = join(mkdtempSync(join(tmpdir(), 'keyflap-addr-')), 'approver');
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    port = await freePort();
    origin = `http://${HOST}:${port}`;
    const key: WebAuthnApproverKey = {
      credentialId: randomBytes(32).toString('base64url'),
      x: randomBytes(32).toString('base64url'),
      y: randomBytes(32).toString('base64url'),
      rpId: HOST,
      origin,
      signCount: 0,
      createdAt: 0,
    };
    pushes = [];
    pushServer = createServer((r, res) => {
      pushes.push({ ttl: String(r.headers.ttl), devicesLeft: approver.handoffAvailable() });
      res.writeHead(201).end();
    });
    const pushPort = await new Promise<number>((resolve) =>
      pushServer.listen(0, '127.0.0.1', () =>
        resolve((pushServer.address() as { port: number }).port),
      ),
    );
    const devices = new DeviceStore(join(dir, 'devices.json'));
    const { device, token } = devices.add(key.credentialId, 0, 'web');
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
    listCalls = 0;
    approver = await PhoneApprover.start({
      dir,
      origin,
      listen: { host: '127.0.0.1', port },
      auditBefore: () => {},
      allowInsecurePushEndpoints: true,
      platformWord: 'Mac',
      signer: {
        listApprovers: async () => {
          listCalls++;
          return { approvers: [key] };
        },
        addApprover: async () => ({ added: true }),
      },
      timeoutMs: 5_000,
    });
    signerState = OK;
    polls = [];
    audit = [];
    sync = new ApproverAddressSync({
      signer: {
        approverAddress: async (o) => {
          polls.push(o);
          return { state: signerState };
        },
      },
      phone: approver,
      audit: (event, fields) => audit.push({ event, fields }),
      pollMs: { idle: 15, fast: 5 },
    });
  });
  afterEach(async () => {
    sync.stop();
    await approver.close();
    await new Promise((r) => pushServer.close(r));
  });

  it('a changed address cancels the pending approval, warns the phone before signing it out, and is audited', async () => {
    expect(await sync.start()).toEqual(OK);
    const decision = approver.request(req('r1'));
    await until(() => approver.busy(), 'the request to be pending');
    expect((await http(port, '/api/state', { cookie })).json.pending).toHaveLength(1);

    signerState = LATCHED;
    await expect(decision).resolves.toEqual({
      approved: false,
      reason: 'approver_address_changed',
    });
    expect(warnings()).toEqual([{ ttl: '300', devicesLeft: true }]);
    expect(approver.handoffAvailable()).toBe(false);
    expect(audit).toEqual([
      { event: 'approver.address_tripped', fields: { origin, seen: LATCHED.seen } },
    ]);

    const signedOut = await http(port, '/api/state', { cookie });
    expect(signedOut).toEqual({
      status: 401,
      json: { error: 'approver_address_changed', on: 'Mac' },
    });
    const before = listCalls;
    await expect(approver.request(req('r2'))).resolves.toEqual({
      approved: false,
      reason: 'approver_address_changed',
    });
    expect(listCalls).toBe(before);
    expect(() => approver.startPairing()).toThrow(PairingRefused);
    expect(approver.busy()).toBe(false);

    await until(() => polls.length > 3, 'more polls');
    expect(audit).toHaveLength(1);
    expect(warnings()).toHaveLength(1);
  });

  it('a pairing link that is open when the address changes stops working', async () => {
    await sync.start();
    const code = new URL(approver.startPairing()).hash.slice(1);
    expect(await post(port, '/api/pair/status', { code })).toBe(200);
    signerState = LATCHED;
    await until(() => audit.length > 0, 'the trip');
    expect(await post(port, '/api/pair/status', { code })).toBe(403);
  });

  it('an unreadable address pauses approvals with its own reason, tells the page why, and resumes on a good read', async () => {
    await sync.start();
    const decision = approver.request(req('r1'));
    await until(() => approver.busy(), 'the request to be pending');
    signerState = PAUSED;
    await expect(decision).resolves.toEqual({
      approved: false,
      reason: 'approver_address_unverified',
    });
    expect(audit).toEqual([
      { event: 'approver.address_unreadable', fields: { origin, detail: PAUSED.detail } },
    ]);
    expect(warnings()).toEqual([]);
    const state = await http(port, '/api/state', { cookie });
    expect(state.status).toBe(200);
    expect(state.json.address).toEqual({ kind: 'paused', detail: PAUSED.detail, on: 'Mac' });
    expect(() => approver.startPairing()).toThrow(PairingRefused);
    await expect(approver.request(req('r2'))).resolves.toEqual({
      approved: false,
      reason: 'approver_address_unverified',
    });

    signerState = { kind: 'ok', checkedAt: 9 };
    await until(() => audit.length === 2, 'the readable audit event');
    expect(audit[1]).toEqual({ event: 'approver.address_readable', fields: { origin } });
    expect((await http(port, '/api/state', { cookie })).json.address).toBeUndefined();
    const again = approver.request(req('r3'));
    await until(() => approver.busy(), 'approvals to be asked again');
    expect((await http(port, '/api/state', { cookie })).json.pending).toHaveLength(1);
    approver.cancelAll('test_over');
    await expect(again).resolves.toEqual({ approved: false, reason: 'test_over' });
  });

  it('a clear after a trip is audited, and a good read with a new timestamp is not a transition', async () => {
    signerState = LATCHED;
    await sync.start();
    expect(audit.map((a) => a.event)).toEqual(['approver.address_tripped']);
    signerState = { kind: 'ok', checkedAt: 5 };
    await until(() => audit.length === 2, 'the cleared audit event');
    expect(audit[1]).toEqual({ event: 'approver.address_cleared', fields: { origin } });
    signerState = { kind: 'ok', checkedAt: 6 };
    await until(() => polls.length > 6, 'more polls');
    expect(audit).toHaveLength(2);
  });

  it('refresh brings the state up to date at once, so pairing right after a clear is not refused', async () => {
    signerState = LATCHED;
    await sync.start();
    expect(() => approver.startPairing()).toThrow(PairingRefused);
    signerState = { kind: 'ok', checkedAt: 5 };
    expect(await sync.refresh()).toEqual({ kind: 'ok', checkedAt: 5 });
    expect(audit.map((a) => a.event)).toEqual([
      'approver.address_tripped',
      'approver.address_cleared',
    ]);
    expect(approver.startPairing()).toContain('/pair#');
  });

  it('polls fast and reports pending while an approval waits, idle otherwise', async () => {
    await sync.start();
    expect(polls).toEqual([{ pending: false }]);
    const decision = approver.request(req('r1'));
    await until(() => approver.busy(), 'the request to be pending');
    const idle = polls.length;
    await new Promise((r) => setTimeout(r, 60));
    const busyPolls = polls.slice(idle);
    expect(busyPolls.length).toBeGreaterThanOrEqual(6);
    expect(busyPolls.every((p) => p.pending)).toBe(true);
    approver.cancelAll('test_over');
    await expect(decision).resolves.toEqual({ approved: false, reason: 'test_over' });
  });

  it('stops after the first answer when the address is not watched', async () => {
    signerState = { kind: 'unwatched' };
    expect(await sync.start()).toEqual({ kind: 'unwatched' });
    await new Promise((r) => setTimeout(r, 60));
    expect(polls).toHaveLength(1);
    expect(audit).toEqual([]);
    const decision = approver.request(req('r1'));
    await until(() => approver.busy(), 'approvals to be asked as before');
    approver.cancelAll('test_over');
    await expect(decision).resolves.toEqual({ approved: false, reason: 'test_over' });
  });

  it('sameAddressState compares the kind and what the person would be told', () => {
    expect(sameAddressState(OK, { kind: 'ok', checkedAt: 99 })).toBe(true);
    expect(sameAddressState(LATCHED, { ...LATCHED, at: 50 })).toBe(true);
    expect(sameAddressState(LATCHED, { ...LATCHED, seen: 'other' })).toBe(false);
    expect(sameAddressState(PAUSED, { ...PAUSED, detail: 'tailscale exited 1' })).toBe(false);
    expect(sameAddressState(PAUSED, OK)).toBe(false);
  });
});
