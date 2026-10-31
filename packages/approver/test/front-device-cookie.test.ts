import { createHash, generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { type IncomingHttpHeaders, request } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { WebAuthnApproverKey } from '@aab/signer/approval';
import { isoCBOR } from '@simplewebauthn/server/helpers';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ApproverFront } from '../src/front.ts';
import { PhoneApprover } from '../src/phone.ts';

const HOST = 'approver.localhost';
const ORIGIN = `http://${HOST}`;

function call(
  port: number,
  path: string,
  o: { body?: unknown; cookie?: string } = {},
): Promise<{ status: number; headers: IncomingHttpHeaders; json: Record<string, unknown> }> {
  return new Promise((resolve, reject) => {
    const r = request(
      {
        host: '127.0.0.1',
        port,
        path,
        method: o.body === undefined ? 'GET' : 'POST',
        headers: {
          host: `${HOST}:${port}`,
          ...(o.body === undefined ? {} : { origin: ORIGIN, 'content-type': 'application/json' }),
          ...(o.cookie ? { cookie: o.cookie } : {}),
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () =>
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            json: JSON.parse(Buffer.concat(chunks).toString() || '{}'),
          }),
        );
      },
    );
    r.on('error', reject);
    r.end(o.body === undefined ? undefined : JSON.stringify(o.body));
  });
}

type Cbor = number | string | Uint8Array | Map<string | number, Cbor>;

function attestation(challenge: string) {
  const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' });
  const credentialId = createHash('sha256').update(challenge).digest();
  const authData = Buffer.concat([
    createHash('sha256').update(HOST).digest(),
    Buffer.of(0x45),
    Buffer.alloc(4),
    Buffer.alloc(16),
    Buffer.of(credentialId.length >> 8, credentialId.length & 0xff),
    credentialId,
    isoCBOR.encode(
      new Map<string | number, Cbor>([
        [1, 2],
        [3, -7],
        [-1, 1],
        [-2, Buffer.from(jwk.x as string, 'base64url')],
        [-3, Buffer.from(jwk.y as string, 'base64url')],
      ]),
    ),
  ]);
  const id = credentialId.toString('base64url');
  return {
    id,
    rawId: id,
    type: 'public-key',
    response: {
      clientDataJSON: Buffer.from(
        JSON.stringify({ type: 'webauthn.create', challenge, origin: ORIGIN }),
      ).toString('base64url'),
      attestationObject: Buffer.from(
        isoCBOR.encode(
          new Map<string | number, Cbor>([
            ['fmt', 'none'],
            ['attStmt', new Map<string | number, Cbor>()],
            ['authData', authData],
          ]),
        ),
      ).toString('base64url'),
      transports: [],
    },
    clientExtensionResults: {},
  };
}

describe('the front passes the device cookie the real approver sets', () => {
  const dir = mkdtempSync(join(tmpdir(), 'keyflap-front-cookie-'));
  const approvers: WebAuthnApproverKey[] = [];
  let approver: PhoneApprover;
  let front: ApproverFront;
  let port: number;

  beforeAll(async () => {
    approver = await PhoneApprover.start({
      auditBefore: () => {},
      dir: join(dir, 'approver'),
      origin: ORIGIN,
      listen: { path: join(dir, 'api.sock') },
      apiOnly: true,
      signer: {
        listApprovers: async () => ({ approvers }),
        addApprover: async ({ key }) => {
          approvers.push({ ...key, signCount: 0, createdAt: 0 });
          return { added: true };
        },
      },
    });
    front = await ApproverFront.start({
      origin: ORIGIN,
      listen: { host: '127.0.0.1', port: 0 },
      upstream: join(dir, 'api.sock'),
    });
    port = Number(new URL(front.listenUrl).port);
  });
  afterAll(async () => {
    await front.close();
    await approver.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it('pairing the first phone through the front hands it a cookie that works', async () => {
    const code = new URL(approver.startPairing()).hash.slice(1);
    const options = await call(port, '/api/pair/options', { body: { code } });
    expect(options.status).toBe(200);
    const finished = await call(port, '/api/pair/finish', {
      body: { code, response: attestation(options.json.challenge as string) },
    });
    expect(finished.status).toBe(200);
    expect(finished.json).toEqual({ status: 'paired' });
    const cookies = finished.headers['set-cookie'] ?? [];
    expect(cookies).toHaveLength(1);
    expect(cookies[0]).toMatch(/^__Host-aab_device=[A-Za-z0-9_-]{43}; /);

    const state = await call(port, '/api/state', { cookie: (cookies[0] as string).split(';')[0] });
    expect(state.status).toBe(200);
    expect(state.json.pending).toEqual([]);
  });
});
