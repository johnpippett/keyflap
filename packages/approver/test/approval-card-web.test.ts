import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { mkdirSync, mkdtempSync } from 'node:fs';
import { request } from 'node:http';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { ApprovalStatement, WebAuthnApproverKey } from '@aab/signer/approval';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { DeviceStore } from '../src/devices.ts';
import type { ApprovalDecision, ApprovalRequest } from '../src/index.ts';
import { PhoneApprover } from '../src/phone.ts';

const HOST = 'approver.localhost';

function softPhone(origin: string) {
  const credentialId = randomBytes(32).toString('base64url');
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' });
  const key: WebAuthnApproverKey = {
    credentialId,
    x: jwk.x as string,
    y: jwk.y as string,
    rpId: HOST,
    origin,
    signCount: 0,
    createdAt: 0,
  };
  return {
    key,
    cookie: '',
    assert(challenge: string) {
      const cd = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin }));
      const ad = Buffer.concat([
        createHash('sha256').update(HOST).digest(),
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

const req = (id: string): ApprovalRequest => ({
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
});

interface Res {
  status: number;
  json: Record<string, unknown>;
}

describe('approval card states (web path): one statement per card, the latest tap wins', () => {
  let approver: PhoneApprover;
  let port: number;
  let a: ReturnType<typeof softPhone>;
  let b: ReturnType<typeof softPhone>;
  let hold: { skip: number; reached: () => void; release: Promise<void> } | null = null;

  const post = (path: string, cookie: string, body: unknown): Promise<Res> =>
    new Promise((resolve, reject) => {
      const r = request(
        {
          host: '127.0.0.1',
          port,
          path,
          method: 'POST',
          headers: {
            host: `${HOST}:${port}`,
            cookie,
            origin: `http://${HOST}:${port}`,
            'content-type': 'application/json',
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
      r.end(JSON.stringify(body));
    });
  const challenge = (p: ReturnType<typeof softPhone>, id: string) =>
    post('/api/challenge', p.cookie, { id });
  const approve = (p: ReturnType<typeof softPhone>, id: string, ch: Res) =>
    post('/api/decide', p.cookie, {
      id,
      decision: 'approve',
      credential: p.assert(ch.json.challenge as string),
    });

  beforeEach(async () => {
    const dir = join(mkdtempSync(join(tmpdir(), 'keyflap-card-')), 'approver');
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    port = await new Promise<number>((resolve) => {
      const s = createServer().listen(0, '127.0.0.1', () => {
        const p = (s.address() as { port: number }).port;
        s.close(() => resolve(p));
      });
    });
    const origin = `http://${HOST}:${port}`;
    a = softPhone(origin);
    b = softPhone(origin);
    const devices = new DeviceStore(join(dir, 'devices.json'));
    a.cookie = `__Host-aab_device=${devices.add(a.key.credentialId, 0, 'web').token}`;
    b.cookie = `__Host-aab_device=${devices.add(b.key.credentialId, 0, 'web').token}`;
    hold = null;
    approver = await PhoneApprover.start({
      dir,
      origin,
      listen: { host: '127.0.0.1', port },
      auditBefore: () => {},
      signer: {
        listApprovers: async () => {
          const h = hold;
          if (h && h.skip-- === 0) {
            hold = null;
            h.reached();
            await h.release;
          }
          return { approvers: [a.key, b.key] };
        },
        addApprover: async () => ({ added: true }),
      },
      timeoutMs: 20_000,
    });
  });
  afterEach(() => approver.close());

  it("phone A asks, phone B asks: A's assertion is refused, B's is accepted", async () => {
    const decision = approver.request(req('r1'));
    const chA = await challenge(a, 'r1');
    const chB = await challenge(b, 'r1');
    expect(chB.json.challenge).not.toBe(chA.json.challenge);
    expect((await approve(a, 'r1', chA)).status).toBe(400);
    expect(await approve(b, 'r1', chB)).toEqual({ status: 200, json: { ok: true } });
    const d = await decision;
    expect(d.approved).toBe(true);
    expect(d.approved && d.approval.statement).toEqual(chB.json.statement as ApprovalStatement);
  });

  it("B's challenge landing while A's decision is being checked still wins", async () => {
    const decision = approver.request(req('r2'));
    const chA = await challenge(a, 'r2');
    let reached!: () => void;
    const atAwait = new Promise<void>((r) => {
      reached = r;
    });
    let release!: () => void;
    hold = {
      skip: 2,
      reached,
      release: new Promise<void>((r) => {
        release = r;
      }),
    };
    const decidingA = approve(a, 'r2', chA);
    await atAwait;
    const chB = await challenge(b, 'r2');
    release();
    const resA = await decidingA;
    expect(resA.status).toBe(400);
    expect(await approve(b, 'r2', chB)).toEqual({ status: 200, json: { ok: true } });
    const d: ApprovalDecision = await decision;
    expect(d.approved && d.approval.statement).toEqual(chB.json.statement as ApprovalStatement);
  });
});
