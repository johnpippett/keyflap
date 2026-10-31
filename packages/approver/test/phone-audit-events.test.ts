import { generateKeyPairSync, type KeyObject, sign } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { request } from 'node:http';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  type ApprovalStatement,
  nativeApprovalSigningBytes,
  nativeApproverDescriptor,
  nativeKeyId,
  nativePairingProofBytes,
} from '@aab/signer/approval';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { KeyStore } from '../../signer/src/keystore.ts';
import { SignerHandler } from '../../signer/src/server.ts';
import { PhoneApprover } from '../src/phone.ts';

const HOST = 'approver.localhost';
const IDENTIFIER_FIELDS = new Set([
  'origin',
  'deviceId',
  'credentialId',
  'first',
  'kind',
  'keyRemoved',
]);

interface Res {
  status: number;
  json: Record<string, unknown>;
}

function nativeApp(origin: string) {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' });
  const x = jwk.x as string;
  const y = jwk.y as string;
  const keyId = nativeKeyId(x, y);
  const descriptor = nativeApproverDescriptor({
    keyId,
    x,
    y,
    origin,
    userVerification: 'biometry',
  });
  const der = (data: Buffer, key: KeyObject = privateKey) =>
    sign('sha256', data, { key, dsaEncoding: 'der' }).toString('base64url');
  return {
    keyId,
    token: '',
    pairBody: (code: string) => ({
      code,
      key: { x, y },
      userVerification: 'biometry',
      proof: der(nativePairingProofBytes(descriptor)),
    }),
    sign: (s: ApprovalStatement) => der(nativeApprovalSigningBytes(s)),
  };
}

describe('the phone approver audit events carry identifiers only', () => {
  let approver: PhoneApprover;
  let port: number;
  let origin: string;
  let handler: SignerHandler;
  let events: { event: string; fields: Record<string, unknown> }[];

  const call = (op: Record<string, unknown>) => {
    const r = handler.handle(op as never);
    if (!r.ok) return Promise.reject(new Error(r.error));
    return Promise.resolve(r.result as never);
  };

  function http(
    method: string,
    path: string,
    o: { body?: unknown; token?: string } = {},
  ): Promise<Res> {
    return new Promise((resolve, reject) => {
      const r = request(
        {
          host: '127.0.0.1',
          port,
          path,
          method,
          headers: {
            host: `${HOST}:${port}`,
            ...(o.body !== undefined ? { 'content-type': 'application/json' } : {}),
            ...(o.token ? { authorization: `Bearer ${o.token}` } : {}),
          },
        },
        (res) => {
          let body = '';
          res.on('data', (c) => {
            body += c;
          });
          res.on('end', () =>
            resolve({
              status: res.statusCode ?? 0,
              json: body ? (JSON.parse(body) as Record<string, unknown>) : {},
            }),
          );
        },
      );
      r.on('error', reject);
      r.end(o.body === undefined ? undefined : JSON.stringify(o.body));
    });
  }
  const post = (path: string, body: unknown, token?: string) =>
    http('POST', path, { body, ...(token ? { token } : {}) });

  beforeEach(async () => {
    const dir = mkdtempSync(join(tmpdir(), 'keyflap-events-'));
    handler = new SignerHandler({
      store: KeyStore.open(join(dir, 'keys'), 'pw'),
      trustedApproverKeys: {},
    });
    port = await new Promise<number>((resolve) => {
      const s = createServer().listen(0, '127.0.0.1', () => {
        const p = (s.address() as { port: number }).port;
        s.close(() => resolve(p));
      });
    });
    origin = `http://${HOST}:${port}`;
    events = [];
    approver = await PhoneApprover.start({
      auditBefore: () => {},
      dir: join(dir, 'approver'),
      origin,
      listen: { host: '127.0.0.1', port },
      signer: {
        listApprovers: () => call({ op: 'list_approvers' }),
        addApprover: (r) => call({ op: 'add_approver', ...r }),
        addNativeApprover: (r) => call({ op: 'add_native_approver', ...r }),
        removeApprover: (id) => call({ op: 'remove_approver', credentialId: id }),
      },
      onEvent: (event, fields) => events.push({ event, fields }),
      timeoutMs: 5_000,
    });
  });
  afterEach(() => approver.close());

  async function pendingPairing(code: string, token: string) {
    const st = await http('GET', '/api/native/state', { token });
    const pending = st.json.pending as { id: string; kind: string; check: string }[];
    const item = pending.find((p) => p.kind === 'pair');
    expect(item?.check).toEqual(expect.any(String));
    const ch = await post('/api/native/challenge', { id: item?.id }, token);
    return {
      id: item?.id as string,
      check: item?.check as string,
      statement: ch.json.statement as ApprovalStatement,
      descriptor: ch.json.descriptor as string,
      code,
    };
  }

  it('pairing, a refused pairing, a removed key and unpairing log ids, never a code, token, check or signature', async () => {
    const secrets: string[] = [];
    const first = nativeApp(origin);
    const code1 = new URL(approver.startPairing()).hash.slice(1);
    secrets.push(code1);
    const paired = await post('/api/native/pair', first.pairBody(code1));
    expect(paired.json).toMatchObject({ status: 'paired' });
    first.token = paired.json.deviceToken as string;
    secrets.push(first.token);

    const refused = nativeApp(origin);
    const code2 = new URL(approver.startPairing()).hash.slice(1);
    secrets.push(code2);
    const waiting = await post('/api/native/pair', refused.pairBody(code2));
    expect(waiting.status).toBe(202);
    secrets.push(waiting.json.check as string);
    const p2 = await pendingPairing(code2, first.token);
    secrets.push(p2.descriptor);
    await post('/api/native/decide', { id: p2.id, decision: 'deny' }, first.token);

    const second = nativeApp(origin);
    const code3 = new URL(approver.startPairing()).hash.slice(1);
    secrets.push(code3);
    const waiting3 = await post('/api/native/pair', second.pairBody(code3));
    secrets.push(waiting3.json.check as string);
    const p3 = await pendingPairing(code3, first.token);
    secrets.push(p3.descriptor);
    const signature = first.sign(p3.statement);
    secrets.push(signature);
    await post('/api/native/decide', { id: p3.id, decision: 'approve', signature }, first.token);
    let done: Res | null = null;
    for (let i = 0; i < 100 && !done; i++) {
      const r = await post('/api/native/pair/status', { code: code3 });
      if (r.json.status === 'paired') done = r;
      else await new Promise((res) => setTimeout(res, 20));
    }
    second.token = (done as Res | null)?.json.deviceToken as string;
    secrets.push(second.token);

    await call({ op: 'remove_approver', credentialId: second.keyId });
    expect((await http('GET', '/api/native/state', { token: second.token })).status).toBe(401);
    expect((await post('/api/native/unpair', {}, first.token)).status).toBe(200);

    expect(events.map((e) => e.event)).toEqual([
      'approver.pairing_started',
      'approver.paired',
      'approver.pairing_started',
      'approver.pairing_failed',
      'approver.pairing_started',
      'approver.paired',
      'approver.device_untrusted',
      'approver.unpaired',
    ]);
    for (const e of events) {
      expect(Object.keys(e.fields).filter((k) => !IDENTIFIER_FIELDS.has(k))).toEqual([]);
    }
    const text = JSON.stringify(events);
    expect(secrets).toHaveLength(10);
    for (const secret of secrets) {
      expect(secret.length).toBeGreaterThan(4);
      expect(text).not.toContain(secret);
    }
  });
});
