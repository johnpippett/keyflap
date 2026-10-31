import { mkdirSync, mkdtempSync, readFileSync } from 'node:fs';
import { request } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { WebAuthnApproverKey } from '@aab/signer/approval';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { DeviceStore } from '../src/devices.ts';
import { type ApprovalRequest, buildStatement, requestProblem } from '../src/index.ts';
import { PhoneApprover } from '../src/phone.ts';

const strongReq = (over: Partial<ApprovalRequest['display']> = {}): ApprovalRequest => ({
  display: {
    intentText: 'sign me in to my bank',
    intentAt: 1,
    verifiedOrigin: 'https://login.bank.example',
    agentName: 'agent',
    credentialType: 'password',
    action: 'sign-in',
    keepSignedInSite: 'bank.example',
    ...over,
  },
  policy: { tier: 'ask-strong' },
  binding: {
    requestId: 'r1',
    kind: 'fill',
    rpId: 'bank.example',
    credentialId: 'item-1',
    intentHash: 'aA',
    clientDataHash: 'bB',
  },
});

describe('the offer and the statement', () => {
  it("is only valid on a high-risk sign-in, for the verified origin's own site", () => {
    expect(requestProblem(strongReq())).toBeNull();
    expect(requestProblem({ ...strongReq(), policy: { tier: 'ask' } })).toBe(
      'inconsistent_request',
    );
    expect(requestProblem(strongReq({ keepSignedInSite: 'other.example' }))).toBe(
      'inconsistent_request',
    );
    expect(requestProblem(strongReq({ keepSignedInSite: 'ank.example' }))).toBe(
      'inconsistent_request',
    );
    expect(requestProblem(strongReq({ keepSignedInSite: 'BANK.example' }))).toBe(
      'inconsistent_request',
    );
    const reg = strongReq({ action: 'register' });
    reg.binding.kind = 'webauthn.create';
    expect(requestProblem(reg)).toBe('inconsistent_request');
  });

  it('unticked (the default) signs no keepSignedIn; ticked signs exactly the offered site', () => {
    expect(buildStatement(strongReq(), { userVerified: true }).keepSignedIn).toBeUndefined();
    expect(
      buildStatement(strongReq(), { userVerified: true, keepSignedIn: false }).keepSignedIn,
    ).toBeUndefined();
    expect(buildStatement(strongReq(), { userVerified: true, keepSignedIn: true })).toMatchObject({
      strong: true,
      keepSignedIn: { site: 'bank.example' },
    });
    const { keepSignedInSite: _, ...noOffer } = strongReq().display;
    expect(() =>
      buildStatement(
        { ...strongReq(), display: noOffer },
        { userVerified: true, keepSignedIn: true },
      ),
    ).toThrow('keep_not_offered');
  });

  it('the card template has the box unticked, with broker text only', () => {
    const page = (f: string) =>
      readFileSync(fileURLToPath(new URL(`../src/page/${f}`, import.meta.url)), 'utf8');
    const html = page('app.html');
    const box = /<input class="keep-box" type="checkbox"[^>]*>/.exec(html)?.[0];
    expect(box).toBeDefined();
    expect(box).not.toContain('checked');
    const js = page('app.js');
    expect(js).toContain(`Keep me signed in on $${'{'}clean(d.keepSignedInSite)}`);
    expect(js).toContain("!node.querySelector('.keep').hidden && keep.checked");
    expect(js).toContain('keepSignedIn ? { keepSignedIn: true }');
  });
});

describe('phone approver: /api/challenge with keepSignedIn', () => {
  let approver: PhoneApprover;
  let port: number;
  let origin: string;
  let cookie: string;
  let nativeToken: string;

  const http = (
    path: string,
    o: { method?: string; headers?: Record<string, string>; body?: unknown } = {},
  ): Promise<{ status: number; body: Record<string, unknown> }> =>
    new Promise((resolve, reject) => {
      const r = request(
        {
          host: '127.0.0.1',
          port,
          path,
          method: o.method ?? 'GET',
          headers: {
            host: `approver.localhost:${port}`,
            ...(o.body !== undefined ? { origin, 'content-type': 'application/json' } : {}),
            ...o.headers,
          },
        },
        (res) => {
          let b = '';
          res.on('data', (c) => {
            b += c;
          });
          res.on('end', () =>
            resolve({ status: res.statusCode ?? 0, body: JSON.parse(b || '{}') }),
          );
        },
      );
      r.on('error', reject);
      r.end(o.body === undefined ? undefined : JSON.stringify(o.body));
    });

  beforeEach(async () => {
    const dir = join(mkdtempSync(join(tmpdir(), 'keyflap-keep-')), 'approver');
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const { createServer } = await import('node:net');
    port = await new Promise((resolve) => {
      const s = createServer().listen(0, '127.0.0.1', () => {
        const p = (s.address() as { port: number }).port;
        s.close(() => resolve(p));
      });
    });
    origin = `http://approver.localhost:${port}`;
    const key: WebAuthnApproverKey = {
      credentialId: 'k'.repeat(43),
      x: 'x',
      y: 'y',
      rpId: 'approver.localhost',
      origin,
      signCount: 0,
      createdAt: 0,
    };
    const store = new DeviceStore(join(dir, 'devices.json'));
    cookie = `__Host-aab_device=${store.add(key.credentialId).token}`;
    nativeToken = store.add(key.credentialId, Date.now(), 'native').token;
    approver = await PhoneApprover.start({
      dir,
      origin,
      listen: { host: '127.0.0.1', port },
      auditBefore: () => {},
      signer: {
        listApprovers: async () => ({
          approvers: [key],
          native: [
            {
              keyId: key.credentialId,
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
      timeoutMs: 3_000,
    });
  });
  afterEach(() => approver.close());

  const challenge = (body: Record<string, unknown>) =>
    http('/api/challenge', { method: 'POST', headers: { cookie }, body });

  it('ticked: the statement to sign carries it; unticked: it does not', async () => {
    const d = approver.request(strongReq());
    const st = await http('/api/state', { headers: { cookie } });
    const shown = (st.body.pending as { display: Record<string, unknown> }[])[0]?.display;
    expect(shown?.keepSignedInSite).toBe('bank.example');
    const ticked = await challenge({ id: 'r1', keepSignedIn: true });
    expect(ticked.status).toBe(200);
    const unticked = await challenge({ id: 'r1' });
    expect(unticked.status).toBe(200);
    expect(ticked.body.challenge).not.toBe(unticked.body.challenge);
    expect((await challenge({ id: 'r1', keepSignedIn: 'yes' })).status).toBe(400);
    await http('/api/decide', {
      method: 'POST',
      headers: { cookie },
      body: { id: 'r1', decision: 'deny' },
    });
    expect(await d).toEqual({ approved: false, reason: 'user_denied' });
  });

  it('a request that did not offer it refuses keepSignedIn', async () => {
    const { keepSignedInSite: _, ...display } = strongReq().display;
    const d = approver.request({ ...strongReq(), display });
    const r = await challenge({ id: 'r1', keepSignedIn: true });
    expect(r).toEqual({ status: 400, body: { error: 'keep_not_offered' } });
    await http('/api/decide', {
      method: 'POST',
      headers: { cookie },
      body: { id: 'r1', decision: 'deny' },
    });
    await d;
  });

  it('the iOS app never sees the offer (its statements can never carry it)', async () => {
    const d = approver.request(strongReq());
    const st = await http('/api/native/state', {
      headers: { authorization: `Bearer ${nativeToken}` },
    });
    const p = (st.body.pending as { display: Record<string, unknown> }[])[0];
    expect(p?.display.verifiedOrigin).toBe('https://login.bank.example');
    expect(p?.display).not.toHaveProperty('keepSignedInSite');
    const ch = await http('/api/native/challenge', {
      method: 'POST',
      headers: { authorization: `Bearer ${nativeToken}` },
      body: { id: 'r1', keepSignedIn: true },
    });
    expect((ch.body.statement as Record<string, unknown>).keepSignedIn).toBeUndefined();
    await http('/api/decide', {
      method: 'POST',
      headers: { cookie },
      body: { id: 'r1', decision: 'deny' },
    });
    await d;
  });
});
