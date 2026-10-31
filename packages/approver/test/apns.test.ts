import { createPublicKey, generateKeyPairSync, verify } from 'node:crypto';
import { createServer, type Http2Server, type IncomingHttpHeaders } from 'node:http2';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  APNS_CATEGORY,
  APNS_HANDOFF_CATEGORY,
  ApnsSender,
  apnsPayload,
  checkApnsOptions,
} from '../src/apns.ts';

interface Seen {
  headers: IncomingHttpHeaders;
  body: string;
}

async function fakeApns(
  reply: (h: IncomingHttpHeaders) => { status: number; body?: unknown },
): Promise<{ server: Http2Server; url: string; seen: Seen[] }> {
  const seen: Seen[] = [];
  const server = createServer();
  server.on('stream', (stream, headers) => {
    let body = '';
    stream.on('data', (c) => {
      body += c;
    });
    stream.on('end', () => {
      seen.push({ headers, body });
      const r = reply(headers);
      stream.respond({ ':status': r.status, 'content-type': 'application/json' });
      stream.end(r.body === undefined ? undefined : JSON.stringify(r.body));
    });
  });
  const port = await new Promise<number>((resolve) =>
    server.listen(0, '127.0.0.1', () => resolve((server.address() as { port: number }).port)),
  );
  return { server, url: `http://127.0.0.1:${port}`, seen };
}

const TOKEN = 'a1'.repeat(32);
const note = {
  requestId: 'req-1',
  kind: 'sign-in' as const,
  verifiedOrigin: 'https://github.com',
};

describe('APNs sender', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const pem = privateKey.export({ format: 'pem', type: 'pkcs8' });
  let servers: Http2Server[] = [];
  let senders: ApnsSender[] = [];
  let now = 1_760_000_000_000;

  const sender = (
    hosts: { sandbox?: string; production?: string },
    o: { generic?: boolean } = {},
  ) => {
    const s = new ApnsSender({
      key: pem,
      keyId: 'KEY1234567',
      teamId: 'TEAM123456',
      bundleId: 'me.example.Keyflap',
      hosts,
      now: () => now,
      ...o,
    });
    senders.push(s);
    return s;
  };

  beforeEach(() => {
    servers = [];
    senders = [];
  });
  afterEach(async () => {
    for (const s of senders) s.close();
    await Promise.all(servers.map((s) => new Promise<void>((r) => s.close(() => r()))));
  });

  it('signs an ES256 provider token (kid, iss, iat) and caches it for 50 minutes', () => {
    const s = sender({});
    const jwt = s.providerToken();
    const [h, p, sig] = jwt.split('.') as [string, string, string];
    expect(JSON.parse(Buffer.from(h, 'base64url').toString())).toEqual({
      alg: 'ES256',
      kid: 'KEY1234567',
    });
    expect(JSON.parse(Buffer.from(p, 'base64url').toString())).toEqual({
      iss: 'TEAM123456',
      iat: Math.floor(now / 1000),
    });
    const ok = verify(
      'sha256',
      Buffer.from(`${h}.${p}`),
      {
        key: createPublicKey(publicKey.export({ format: 'pem', type: 'spki' })),
        dsaEncoding: 'ieee-p1363',
      },
      Buffer.from(sig, 'base64url'),
    );
    expect(ok).toBe(true);
    now += 49 * 60_000;
    expect(s.providerToken()).toBe(jwt);
    now += 2 * 60_000;
    expect(s.providerToken()).not.toBe(jwt);
  });

  it('posts an alert with the request id and the site host, nothing else', async () => {
    const f = await fakeApns(() => ({ status: 200 }));
    servers.push(f.server);
    const s = sender({ production: f.url });
    expect(await s.send(TOKEN, 'production', note)).toBe('sent');
    const [req] = f.seen;
    expect(req?.headers[':method']).toBe('POST');
    expect(req?.headers[':path']).toBe(`/3/device/${TOKEN}`);
    expect(req?.headers.authorization).toBe(`bearer ${s.providerToken()}`);
    expect(req?.headers['apns-topic']).toBe('me.example.Keyflap');
    expect(req?.headers['apns-push-type']).toBe('alert');
    expect(req?.headers['apns-priority']).toBe('10');
    expect(req?.headers['apns-collapse-id']).toBe('req-1');
    expect(Number(req?.headers['apns-expiration'])).toBe(Math.floor(now / 1000) + 120);
    expect(JSON.parse(req?.body ?? '')).toEqual({
      aps: {
        alert: { title: 'Sign-in request', body: 'Approve sign-in to github.com?' },
        sound: 'default',
        category: 'AAB_APPROVAL',
        'thread-id': 'aab-approvals',
        'interruption-level': 'time-sensitive',
      },
      aab: { v: 1, rid: 'req-1' },
    });
  });

  it('routes by environment, defaulting to production', async () => {
    const sb = await fakeApns(() => ({ status: 200 }));
    const pr = await fakeApns(() => ({ status: 200 }));
    servers.push(sb.server, pr.server);
    const s = sender({ sandbox: sb.url, production: pr.url });
    await s.send(TOKEN, 'sandbox', note);
    await s.send(TOKEN, undefined, note);
    expect(sb.seen).toHaveLength(1);
    expect(pr.seen).toHaveLength(1);
  });

  it('maps APNs answers: 410 / BadDeviceToken gone, others failed; bad tokens never sent', async () => {
    let answer: { status: number; body?: unknown } = {
      status: 410,
      body: { reason: 'Unregistered' },
    };
    const f = await fakeApns(() => answer);
    servers.push(f.server);
    const s = sender({ production: f.url });
    expect(await s.send(TOKEN, 'production', note)).toBe('gone');
    answer = { status: 400, body: { reason: 'BadDeviceToken' } };
    expect(await s.send(TOKEN, 'production', note)).toBe('gone');
    answer = { status: 500, body: { reason: 'InternalServerError' } };
    expect(await s.send(TOKEN, 'production', note)).toBe('failed');
    const first = s.providerToken();
    answer = { status: 403, body: { reason: 'ExpiredProviderToken' } };
    expect(await s.send(TOKEN, 'production', note)).toBe('failed');
    now += 1_000;
    expect(s.providerToken()).not.toBe(first);
    const before = f.seen.length;
    expect(await s.send('not-hex', 'production', note)).toBe('gone');
    expect(f.seen.length).toBe(before);
  });

  it('a dead server is a failure, not an exception', async () => {
    const s = sender({ production: 'http://127.0.0.1:1' });
    expect(await s.send(TOKEN, 'production', note)).toBe('failed');
  });

  it('payload wording: registration, pairing, generic mode, odd hosts', () => {
    const body = (n: Parameters<typeof apnsPayload>[0], g = false) =>
      JSON.parse(apnsPayload(n, g).toString()).aps.alert.body;
    expect(body({ ...note, kind: 'register' })).toBe('Approve a new passkey for github.com?');
    expect(body({ requestId: 'p', kind: 'pair', verifiedOrigin: null })).toBe(
      'Approve adding a new approver phone?',
    );
    expect(body(note, true)).toBe('Open Keyflap to review the request.');
    expect(body({ ...note, verifiedOrigin: 'https://xn--bcher-kva.example:8443' })).toBe(
      'Approve sign-in to xn--bcher-kva.example:8443?',
    );
    expect(body({ ...note, verifiedOrigin: 'not a url' })).toBe(
      'Open Keyflap to review the request.',
    );
  });

  it('handoff (P3): "Human check on <host>", its own category with no actions, no request id', async () => {
    const f = await fakeApns(() => ({ status: 200 }));
    servers.push(f.server);
    const s = sender({ production: f.url });
    const handoff = {
      requestId: 'h-1',
      kind: 'handoff' as const,
      verifiedOrigin: 'https://huggingface.co',
      ttlSeconds: 300,
    };
    expect(await s.send(TOKEN, 'production', handoff)).toBe('sent');
    const [req] = f.seen;
    expect(req?.headers['apns-collapse-id']).toBe('h-1');
    const payload = JSON.parse(req?.body ?? '');
    expect(payload).toEqual({
      aps: {
        alert: { title: 'Human check', body: 'Human check on huggingface.co' },
        sound: 'default',
        category: APNS_HANDOFF_CATEGORY,
        'thread-id': 'aab-handoffs',
        'interruption-level': 'time-sensitive',
      },
      aab: { v: 1, handoff: 'h-1' },
    });
    expect(APNS_HANDOFF_CATEGORY).not.toBe(APNS_CATEGORY);
    expect(payload.aab.rid).toBeUndefined();
    const generic = JSON.parse(apnsPayload(handoff, true).toString());
    expect(generic.aps.alert.body).toBe('Open Keyflap: a human check is waiting.');
    expect(JSON.stringify(generic)).not.toContain('huggingface');
    expect(
      JSON.parse(apnsPayload({ ...handoff, verifiedOrigin: 'bad' }).toString()).aps.alert.body,
    ).toBe('Open Keyflap: a human check is waiting.');
  });

  it('refuses malformed configuration and keys', () => {
    expect(() =>
      checkApnsOptions({ keyId: 'short', teamId: 'TEAM123456', bundleId: 'a.b' }),
    ).toThrow();
    expect(() =>
      checkApnsOptions({ keyId: 'KEY1234567', teamId: 'team', bundleId: 'a.b' }),
    ).toThrow();
    expect(() =>
      checkApnsOptions({ keyId: 'KEY1234567', teamId: 'TEAM123456', bundleId: 'ab' }),
    ).toThrow();
    const ed = generateKeyPairSync('ed25519').privateKey.export({ format: 'pem', type: 'pkcs8' });
    expect(
      () => new ApnsSender({ key: ed, keyId: 'KEY1234567', teamId: 'TEAM123456', bundleId: 'a.b' }),
    ).toThrow(/P-256/);
  });
});
