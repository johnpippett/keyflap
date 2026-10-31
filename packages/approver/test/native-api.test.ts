import { generateKeyPairSync, type KeyObject, sign } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { request } from 'node:http';
import { createServer as createH2Server, type Http2Server } from 'node:http2';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  type ApprovalStatement,
  type NativeApproval,
  nativeApprovalSigningBytes,
  nativeApproverDescriptor,
  nativeKeyId,
  nativePairingProofBytes,
  sha256B64url,
} from '@aab/signer/approval';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { KeyStore } from '../../signer/src/keystore.ts';
import { SignerHandler } from '../../signer/src/server.ts';
import { ApnsSender } from '../src/apns.ts';
import type { ApprovalRequest } from '../src/index.ts';
import { checkCode, PhoneApprover } from '../src/phone.ts';

const HOST = 'approver.localhost';

function req(id = 'r1'): ApprovalRequest {
  return {
    display: {
      intentText: 'sign me in to example',
      intentAt: 1_700_000_000_000,
      verifiedOrigin: 'https://example.com',
      agentName: 'claude',
      credentialType: 'password+totp',
      action: 'sign-in',
    },
    policy: { tier: 'ask' },
    binding: {
      requestId: id,
      kind: 'fill',
      rpId: 'example.com',
      credentialId: 'item-1',
      intentHash: 'SECRET-INTENT-HASH',
      clientDataHash: 'SECRET-SCOPE-HASH',
    },
  };
}

interface Res {
  status: number;
  json: Record<string, unknown>;
  headers: Record<string, string | string[] | undefined>;
}

function app(origin: string) {
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
    pairBody: (code: string, over: Record<string, unknown> = {}) => ({
      code,
      key: { x, y },
      userVerification: 'biometry',
      proof: der(nativePairingProofBytes(descriptor)),
      ...over,
    }),
    signStatement: (s: ApprovalStatement, key?: KeyObject) =>
      der(nativeApprovalSigningBytes(s), key),
    token: '',
  };
}

describe('native iOS approver API', () => {
  let approver: PhoneApprover;
  let port: number;
  let origin: string;
  let handler: SignerHandler;
  let apnsServer: Http2Server | null = null;
  let sender: ApnsSender | undefined;
  const apnsSeen: { path: string; headers: Record<string, unknown>; body: string }[] = [];
  const audited: [string, Record<string, unknown>][] = [];
  const auditedWhenRegistering: number[] = [];
  let auditDown = false;

  const call = (op: Record<string, unknown>) => {
    const r = handler.handle(op as never);
    if (!r.ok) return Promise.reject(new Error(r.error));
    return Promise.resolve(r.result as never);
  };

  function http(
    method: string,
    path: string,
    o: { body?: unknown; token?: string; headers?: Record<string, string> } = {},
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
            ...o.headers,
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
              headers: res.headers,
            }),
          );
        },
      );
      r.on('error', reject);
      r.end(o.body === undefined ? undefined : JSON.stringify(o.body));
    });
  }
  const post = (path: string, body: unknown, token?: string, headers?: Record<string, string>) =>
    http('POST', path, { body, ...(token ? { token } : {}), ...(headers ? { headers } : {}) });

  async function start(withApns = false) {
    audited.length = 0;
    auditedWhenRegistering.length = 0;
    auditDown = false;
    const dir = mkdtempSync(join(tmpdir(), 'keyflap-native-'));
    handler = new SignerHandler({
      store: KeyStore.open(join(dir, 'keys'), 'pw'),
      trustedApproverKeys: {},
    });
    const { createServer } = await import('node:net');
    port = await new Promise<number>((resolve) => {
      const s = createServer().listen(0, '127.0.0.1', () => {
        const p = (s.address() as { port: number }).port;
        s.close(() => resolve(p));
      });
    });
    origin = `http://${HOST}:${port}`;
    let apns: ApnsSender | undefined;
    sender = undefined;
    if (withApns) {
      const h2 = createH2Server();
      apnsServer = h2;
      h2.on('stream', (stream, headers) => {
        let body = '';
        stream.on('data', (c) => {
          body += c;
        });
        stream.on('end', () => {
          apnsSeen.push({ path: String(headers[':path']), headers, body });
          stream.respond({ ':status': 200 });
          stream.end();
        });
      });
      const apnsPort = await new Promise<number>((resolve) => {
        h2.listen(0, '127.0.0.1', () => resolve((h2.address() as { port: number }).port));
      });
      apns = new ApnsSender({
        key: generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey.export({
          format: 'pem',
          type: 'pkcs8',
        }),
        keyId: 'KEYID12345',
        teamId: 'TEAM123456',
        bundleId: 'me.example.Keyflap',
        hosts: {
          sandbox: `http://127.0.0.1:${apnsPort}`,
          production: `http://127.0.0.1:${apnsPort}`,
        },
      });
      sender = apns;
    }
    approver = await PhoneApprover.start({
      dir: join(dir, 'approver'),
      origin,
      listen: { host: '127.0.0.1', port },
      signer: {
        listApprovers: () => call({ op: 'list_approvers' }),
        addApprover: (r) => call({ op: 'add_approver', ...r }),
        addNativeApprover: (r) => {
          auditedWhenRegistering.push(audited.length);
          return call({ op: 'add_native_approver', ...r });
        },
        removeApprover: (id) => call({ op: 'remove_approver', credentialId: id }),
      },
      auditBefore: (event, fields) => {
        if (auditDown) throw new Error('disk full at /var/lib/keyflap/core/broker.sqlite');
        audited.push([event, fields]);
      },
      ...(apns ? { apns } : {}),
      timeoutMs: 5_000,
    });
  }

  async function pairFirst() {
    const a = app(origin);
    const code = new URL(approver.startPairing()).hash.slice(1);
    const r = await post('/api/native/pair', a.pairBody(code));
    expect(r.status).toBe(200);
    expect(r.json).toMatchObject({ status: 'paired', keyId: a.keyId });
    a.token = r.json.deviceToken as string;
    expect(a.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    return a;
  }

  beforeEach(() => start());
  afterEach(async () => {
    await approver.close();
    sender?.close();
    await new Promise<void>((r) => (apnsServer ? apnsServer.close(() => r()) : r()));
    apnsServer = null;
    apnsSeen.length = 0;
  });

  it('pairs the app key with the one-time code; bad proofs and missing biometry are refused', async () => {
    const a = app(origin);
    const other = app(origin);
    const code = new URL(approver.startPairing()).hash.slice(1);
    expect((await post('/api/native/pair', a.pairBody('A'.repeat(43)))).status).toBe(403);
    expect(
      (await post('/api/native/pair', a.pairBody(code, { proof: other.pairBody(code).proof })))
        .json,
    ).toEqual({ error: 'bad_proof' });
    expect(
      (await post('/api/native/pair', a.pairBody(code, { userVerification: 'none' }))).json,
    ).toEqual({ error: 'user_verification_required' });
    expect(
      (
        await post('/api/native/pair', a.pairBody(code), undefined, {
          origin: 'https://evil.example',
        })
      ).status,
    ).toBe(403);
    expect(((await call({ op: 'list_approvers' })) as { native: unknown[] }).native).toEqual([]);
    const ok = await post('/api/native/pair', a.pairBody(code));
    expect(ok.status).toBe(200);
    expect(ok.headers['set-cookie']).toBeUndefined();
    const listed = (await call({ op: 'list_approvers' })) as { native: { keyId: string }[] };
    expect(listed.native.map((k) => k.keyId)).toEqual([a.keyId]);
    expect((await post('/api/native/pair', other.pairBody(code))).status).toBe(403);
  });

  it('shows the app only display fields, and its signature approves the request', async () => {
    const a = await pairFirst();
    expect((await http('GET', '/api/native/state')).status).toBe(401);
    expect((await http('GET', '/api/native/state', { token: 'A'.repeat(43) })).status).toBe(401);
    expect(
      (await http('GET', '/api/state', { headers: { cookie: `__Host-aab_device=${a.token}` } }))
        .status,
    ).toBe(401);

    const decision = approver.request(req('r1'));
    const st = await http('GET', '/api/native/state', { token: a.token });
    expect(st.status).toBe(200);
    const pending = st.json.pending as Record<string, unknown>[];
    expect(pending).toHaveLength(1);
    expect(pending[0]).toEqual({
      id: 'r1',
      createdAt: expect.any(Number),
      expiresAt: expect.any(Number),
      kind: 'credential',
      display: req().display,
    });
    expect(JSON.stringify(st.json)).not.toContain('SECRET');
    expect(st.json.device).toEqual({ id: expect.any(String), keyId: a.keyId });

    const ch = await post('/api/native/challenge', { id: 'r1' }, a.token);
    expect(ch.status).toBe(200);
    const s = ch.json.statement as ApprovalStatement;
    expect(s).toMatchObject({
      requestId: 'r1',
      kind: 'fill',
      verifiedOrigin: 'https://example.com',
      userVerified: true,
    });
    expect(ch.json.descriptor).toBeNull();

    const wrong = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey;
    expect(
      (
        await post(
          '/api/native/decide',
          { id: 'r1', decision: 'approve', signature: a.signStatement(s, wrong) },
          a.token,
        )
      ).json,
    ).toEqual({ error: 'bad_signature' });
    expect(
      (
        await post(
          '/api/native/decide',
          { id: 'r1', decision: 'approve', signature: a.signStatement({ ...s, rpId: 'evil.com' }) },
          a.token,
        )
      ).json,
    ).toEqual({ error: 'bad_signature' });

    const ok = await post(
      '/api/native/decide',
      { id: 'r1', decision: 'approve', signature: a.signStatement(s) },
      a.token,
    );
    expect(ok.status).toBe(200);
    const d = await decision;
    expect(d.approved).toBe(true);
    const approval = (d as { approval: NativeApproval }).approval;
    expect(approval).toEqual({
      statement: s,
      approverKeyId: a.keyId,
      native: { signature: expect.any(String) },
    });
    expect((await http('GET', '/api/native/state', { token: a.token })).json.pending).toEqual([]);
  });

  it('M5: the allow-for window shown is the one signed; ask-strong statements say strong', async () => {
    const a = await pairFirst();
    const base = req('g1');
    const granted: ApprovalRequest = {
      ...base,
      display: { ...base.display, allowForMs: 30 * 60_000 },
      binding: { ...base.binding, grant: { agentId: 'agt_1', durationMs: 30 * 60_000 } },
    };
    const d1 = approver.request(granted);
    const st = await http('GET', '/api/native/state', { token: a.token });
    expect((st.json.pending as { display: { allowForMs?: number } }[])[0]?.display.allowForMs).toBe(
      30 * 60_000,
    );
    const s1 = (await post('/api/native/challenge', { id: 'g1' }, a.token)).json
      .statement as ApprovalStatement;
    expect(s1.grant).toEqual({ agentId: 'agt_1', until: s1.issuedAt + 30 * 60_000 });
    await post(
      '/api/native/decide',
      { id: 'g1', decision: 'approve', signature: a.signStatement(s1) },
      a.token,
    );
    expect((await d1).approved).toBe(true);

    const strong: ApprovalRequest = { ...req('s1'), policy: { tier: 'ask-strong' } };
    const d2 = approver.request(strong);
    const s2 = (await post('/api/native/challenge', { id: 's1' }, a.token)).json
      .statement as ApprovalStatement;
    expect(s2.strong).toBe(true);
    expect(s2.expiresAt - s2.issuedAt).toBeLessThanOrEqual(60_000);
    await post('/api/native/decide', { id: 's1', decision: 'deny' }, a.token);
    await d2;

    const bad: ApprovalRequest = {
      ...base,
      binding: {
        ...base.binding,
        requestId: 'b1',
        grant: { agentId: 'agt_1', durationMs: 60_000 },
      },
      display: { ...base.display, allowForMs: 30 * 60_000 },
    };
    expect(await approver.request(bad)).toEqual({
      approved: false,
      reason: 'inconsistent_request',
    });
  });

  it('deny needs only the bearer token; unknown requests are 404', async () => {
    const a = await pairFirst();
    const decision = approver.request(req('r2'));
    expect((await post('/api/native/decide', { id: 'r2', decision: 'deny' })).status).toBe(401);
    expect(
      (await post('/api/native/decide', { id: 'nope', decision: 'deny' }, a.token)).status,
    ).toBe(404);
    expect((await post('/api/native/decide', { id: 'r2', decision: 'deny' }, a.token)).status).toBe(
      200,
    );
    expect(await decision).toEqual({ approved: false, reason: 'user_denied' });
  });

  it('a second app needs approval from the first, with a check code both can recompute', async () => {
    const first = await pairFirst();
    const second = app(origin);
    const code = new URL(approver.startPairing()).hash.slice(1);
    const w = await post('/api/native/pair', second.pairBody(code));
    expect(w.status).toBe(202);
    expect(w.json).toMatchObject({ status: 'waiting', keyId: second.keyId });
    const check = w.json.check as string;
    expect((await post('/api/pair/status', { code }, undefined, { origin })).status).toBe(409);

    const st = await http('GET', '/api/native/state', { token: first.token });
    const pending = st.json.pending as {
      id: string;
      kind: string;
      check: string;
      newDevice: string;
    }[];
    expect(pending).toHaveLength(1);
    expect(pending[0]).toMatchObject({ kind: 'pair', check, newDevice: 'ios-app' });
    const id = pending[0]?.id as string;
    const ch = await post('/api/native/challenge', { id }, first.token);
    const s = ch.json.statement as ApprovalStatement;
    const descriptor = ch.json.descriptor as string;
    expect(s.kind).toBe('approver.add');
    expect(s.credentialId).toBe(second.keyId);
    expect(s.clientDataHash).toBe(sha256B64url(descriptor));
    expect(checkCode(descriptor)).toBe(check);

    expect((await post('/api/native/pair/status', { code })).json).toEqual({ status: 'waiting' });
    expect(
      (
        await post(
          '/api/native/decide',
          { id, decision: 'approve', signature: first.signStatement(s) },
          first.token,
        )
      ).status,
    ).toBe(200);
    let done: Res | null = null;
    for (let i = 0; i < 50 && !done; i++) {
      const r = await post('/api/native/pair/status', { code });
      if (r.json.status === 'paired') done = r;
      else await new Promise((res) => setTimeout(res, 20));
    }
    expect(done?.json).toMatchObject({ status: 'paired', deviceToken: expect.any(String) });
    second.token = done?.json.deviceToken as string;
    expect((await http('GET', '/api/native/state', { token: second.token })).status).toBe(200);
    const listed = (await call({ op: 'list_approvers' })) as { native: { keyId: string }[] };
    expect(listed.native.map((k) => k.keyId).sort()).toEqual([first.keyId, second.keyId].sort());

    const decision = approver.request(req('r3'));
    const ch2 = await post('/api/native/challenge', { id: 'r3' }, second.token);
    const s2 = ch2.json.statement as ApprovalStatement;
    expect(
      (
        await post(
          '/api/native/decide',
          { id: 'r3', decision: 'approve', signature: first.signStatement(s2) },
          second.token,
        )
      ).json,
    ).toEqual({ error: 'bad_signature' });
    await post('/api/native/decide', { id: 'r3', decision: 'deny' }, second.token);
    await decision;

    expect((await post('/api/native/unpair', {}, second.token)).json).toEqual({
      ok: true,
      keyRemoved: true,
    });
    expect((await http('GET', '/api/native/state', { token: second.token })).status).toBe(401);
    expect((await post('/api/native/unpair', {}, first.token)).json).toEqual({
      ok: true,
      keyRemoved: false,
    });
    const after = (await call({ op: 'list_approvers' })) as { native: { keyId: string }[] };
    expect(after.native.map((k) => k.keyId)).toEqual([first.keyId]);
  });

  it('registers an APNs token and pushes the request id and site host, nothing else', async () => {
    await approver.close();
    sender?.close();
    await start(true);
    const a = await pairFirst();
    const token = 'ab'.repeat(32);
    expect(
      (await post('/api/native/apns', { token: 'xyz', environment: 'sandbox' }, a.token)).status,
    ).toBe(400);
    expect(
      (await post('/api/native/apns', { token, environment: 'staging' }, a.token)).status,
    ).toBe(400);
    expect(
      (await post('/api/native/apns', { token, environment: 'sandbox' }, a.token)).json,
    ).toEqual({
      ok: true,
      configured: true,
    });
    expect((await http('GET', '/api/native/state', { token: a.token })).json.apns).toEqual({
      configured: true,
      registered: true,
    });
    const decision = approver.request(req('r9'));
    for (let i = 0; i < 100 && apnsSeen.length === 0; i++)
      await new Promise((r) => setTimeout(r, 20));
    expect(apnsSeen).toHaveLength(1);
    const push = apnsSeen[0] as (typeof apnsSeen)[number];
    expect(push.path).toBe(`/3/device/${token}`);
    expect(push.headers['apns-topic']).toBe('me.example.Keyflap');
    const body = JSON.parse(push.body);
    expect(body.aab).toEqual({ v: 1, rid: 'r9' });
    expect(body.aps.alert.body).toBe('Approve sign-in to example.com?');
    expect(push.body).not.toContain('sign me in');
    expect(push.body).not.toContain('claude');
    await post('/api/native/decide', { id: 'r9', decision: 'deny' }, a.token);
    await decision;
    expect((await post('/api/native/apns', { token: null }, a.token)).status).toBe(200);
    expect((await http('GET', '/api/native/state', { token: a.token })).json.apns).toEqual({
      configured: true,
      registered: false,
    });
  });

  describe('invariant 10: a key is registered only after its pairing row is written', () => {
    const listedNative = async () =>
      ((await call({ op: 'list_approvers' })) as { native: { keyId: string }[] }).native.map(
        (k) => k.keyId,
      );

    it('refuses a first app while the audit log cannot be written, then pairs it once it can', async () => {
      const a = app(origin);
      const code = new URL(approver.startPairing()).hash.slice(1);
      auditDown = true;
      const refused = await post('/api/native/pair', a.pairBody(code));
      expect(refused.status).toBe(409);
      expect(refused.json).toEqual({ error: 'pairing_refused' });
      expect(JSON.stringify(refused.json)).not.toContain('disk full');
      expect(await listedNative()).toEqual([]);

      auditDown = false;
      const paired = await post('/api/native/pair', a.pairBody(code));
      expect(paired.status).toBe(200);
      expect(await listedNative()).toEqual([a.keyId]);
      expect(audited).toEqual([
        [
          'approver.pairing_accepted',
          { origin, credentialId: a.keyId, first: true, kind: 'native' },
        ],
      ]);
      expect(auditedWhenRegistering).toEqual([1]);
    });

    it('does not add a second app when its pairing row cannot be written after the first app approved it', async () => {
      const first = await pairFirst();
      const second = app(origin);
      const code = new URL(approver.startPairing()).hash.slice(1);
      expect((await post('/api/native/pair', second.pairBody(code))).status).toBe(202);
      const st = await http('GET', '/api/native/state', { token: first.token });
      const id = (st.json.pending as { id: string }[])[0]?.id as string;
      const ch = await post('/api/native/challenge', { id }, first.token);
      const statement = ch.json.statement as ApprovalStatement;

      auditDown = true;
      expect(
        (
          await post(
            '/api/native/decide',
            { id, decision: 'approve', signature: first.signStatement(statement) },
            first.token,
          )
        ).status,
      ).toBe(200);
      let final = 'waiting';
      for (let i = 0; i < 50 && final === 'waiting'; i++) {
        final = (await post('/api/native/pair/status', { code })).json.status as string;
        if (final === 'waiting') await new Promise((res) => setTimeout(res, 20));
      }
      expect(final).toBe('failed');
      expect(await listedNative()).toEqual([first.keyId]);
      expect(audited.map(([event]) => event)).toEqual(['approver.pairing_accepted']);
    });
  });
});
