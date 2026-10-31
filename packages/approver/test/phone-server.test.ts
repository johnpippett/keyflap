import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, statSync } from 'node:fs';
import { request } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { WebAuthnApproverKey } from '@aab/signer/approval';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { ApprovalRequest } from '../src/index.ts';
import { loadPageFiles, versionBrandLinks } from '../src/page-files.ts';
import { PhoneApprover } from '../src/phone.ts';

const ORIGIN_HOST = 'approver.localhost';

function req(over: Partial<ApprovalRequest> = {}): ApprovalRequest {
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
      requestId: 'r1',
      kind: 'webauthn.get',
      rpId: 'example.com',
      credentialId: 'c1',
      intentHash: 'aA',
      clientDataHash: 'bB',
    },
    ...over,
  };
}

interface Res {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
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
        headers: { host: `${ORIGIN_HOST}:${port}`, ...o.headers },
      },
      (res) => {
        let body = '';
        res.on('data', (c) => {
          body += c;
        });
        res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body }));
      },
    );
    r.on('error', reject);
    r.end(o.body);
  });
}

async function freePort(): Promise<number> {
  const { createServer } = await import('node:net');
  return new Promise((resolve) => {
    const s = createServer().listen(0, '127.0.0.1', () => {
      const p = (s.address() as { port: number }).port;
      s.close(() => resolve(p));
    });
  });
}

describe('phone approver server', () => {
  let approver: PhoneApprover;
  let port: number;
  let origin: string;
  let dir: string;
  let keys: WebAuthnApproverKey[];
  const post = (path: string, body: unknown, headers: Record<string, string> = {}) =>
    http(port, path, {
      method: 'POST',
      headers: { origin, 'content-type': 'application/json', ...headers },
      body: JSON.stringify(body),
    });

  beforeEach(async () => {
    dir = join(mkdtempSync(join(tmpdir(), 'keyflap-appr-')), 'approver');
    port = await freePort();
    origin = `http://${ORIGIN_HOST}:${port}`;
    keys = [];
    approver = await PhoneApprover.start({
      dir,
      origin,
      listen: { host: '127.0.0.1', port },
      auditBefore: () => {},
      signer: {
        listApprovers: async () => ({ approvers: keys }),
        addApprover: async ({ key }) => {
          keys.push({ ...key, signCount: 0, createdAt: 0 });
          return { added: true };
        },
      },
      timeoutMs: 2_000,
    });
  });
  afterEach(() => approver.close());

  it('refuses https origins served without TLS on a non-loopback listener, and non-https origins', async () => {
    const signer = {
      listApprovers: async () => ({ approvers: [] }),
      addApprover: async () => ({ added: true as const }),
    };
    await expect(
      PhoneApprover.start({
        dir,
        origin: 'https://a.example',
        listen: { host: '0.0.0.0', port: 0 },
        auditBefore: () => {},
        signer,
      }),
    ).rejects.toThrow(/loopback/);
    await expect(
      PhoneApprover.start({
        dir,
        origin: 'http://a.example',
        listen: { host: '127.0.0.1', port: 0 },
        auditBefore: () => {},
        signer,
      }),
    ).rejects.toThrow(/https/);
    await expect(
      PhoneApprover.start({
        dir,
        origin: 'http://approver.localhost:1',
        listen: { host: '0.0.0.0', port: 0 },
        auditBefore: () => {},
        signer,
      }),
    ).rejects.toThrow(/loopback/);
  });

  it('serves the page with a strict CSP, no framing, no caching', async () => {
    const r = await http(port, '/');
    expect(r.status).toBe(200);
    expect(r.headers['content-security-policy']).toContain("frame-ancestors 'none'");
    expect(r.headers['content-security-policy']).toContain("script-src 'self'");
    expect(r.headers['content-security-policy']).not.toContain('unsafe');
    expect(r.headers['x-frame-options']).toBe('DENY');
    expect(r.headers['cache-control']).toBe('no-store');
    expect(r.headers['referrer-policy']).toBe('no-referrer');
  });

  it('answers HEAD for page files (iOS checks the home-screen icon with HEAD)', async () => {
    for (const path of ['/brand/apple-touch-icon.png', '/apple-touch-icon.png']) {
      const r = await http(port, path, { method: 'HEAD' });
      expect(r.status).toBe(200);
      expect(r.headers['content-type']).toBe('image/png');
      expect(r.headers['cross-origin-resource-policy']).toBe('same-origin');
    }
    expect((await http(port, '/api/state', { method: 'HEAD' })).status).not.toBe(200);
  });

  it('versions icon links by content, so a changed icon gets a new URL', async () => {
    const files = loadPageFiles();
    const hash = createHash('sha256')
      .update(files.get('brand/apple-touch-icon.png') as Buffer)
      .digest('hex')
      .slice(0, 12);
    const page = (await http(port, '/')).body;
    expect(page).toContain(`href="/brand/apple-touch-icon.png?v=${hash}"`);
    expect(page).not.toMatch(/"\/brand\/[a-z0-9.-]+"/);
    const manifest = JSON.parse((await http(port, '/manifest.webmanifest')).body);
    for (const icon of manifest.icons)
      expect(icon.src).toMatch(/^\/brand\/[a-z0-9-]+\.png\?v=[0-9a-f]{12}$/);
    const r = await http(port, `/brand/apple-touch-icon.png?v=${hash}`, { method: 'HEAD' });
    expect(r.status).toBe(200);
    expect(versionBrandLinks('"/brand/nope.png"', files)).toBe('"/brand/nope.png"');
  });

  it('rejects other Host headers (DNS rebinding) and cross-origin POSTs', async () => {
    expect((await http(port, '/', { headers: { host: 'evil.example' } })).status).toBe(421);
    expect(
      (await post('/api/challenge', { id: 'x' }, { origin: 'http://evil.localhost' })).status,
    ).toBe(403);
    expect(
      (await post('/api/challenge', { id: 'x' }, { 'sec-fetch-site': 'cross-site' })).status,
    ).toBe(403);
    const noOrigin = await http(port, '/api/challenge', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{}',
    });
    expect(noOrigin.status).toBe(403);
    expect((await post('/api/challenge', 'x', { 'content-type': 'text/plain' })).status).toBe(415);
  });

  it('without a device cookie nothing about pending requests is visible or decidable', async () => {
    keys.push({
      credentialId: 'k'.repeat(22),
      x: 'x',
      y: 'y',
      rpId: ORIGIN_HOST,
      origin,
      signCount: 0,
      createdAt: 0,
    });
    const decision = approver.request(req());
    const state = await http(port, '/api/state');
    expect(state.status).toBe(401);
    expect(state.body).not.toContain('sign me in');
    expect((await post('/api/decide', { id: 'r1', decision: 'deny' })).status).toBe(401);
    expect(
      (
        await post(
          '/api/decide',
          { id: 'r1', decision: 'deny' },
          { cookie: '__Host-aab_device=AAAA' },
        )
      ).status,
    ).toBe(401);
    expect(await decision).toEqual({ approved: false, reason: 'timeout' });
  });

  it('denies at once when no phone is paired', async () => {
    expect(await approver.request(req())).toEqual({
      approved: false,
      reason: 'no_approver_paired',
    });
  });

  it('honours abort', async () => {
    keys.push({
      credentialId: 'k'.repeat(22),
      x: 'x',
      y: 'y',
      rpId: ORIGIN_HOST,
      origin,
      signCount: 0,
      createdAt: 0,
    });
    const ctl = new AbortController();
    const d = approver.request(req(), { signal: ctl.signal });
    ctl.abort();
    expect(await d).toEqual({ approved: false, reason: 'aborted' });
  });

  it('pairing needs the one-time code, which lives only in a 0600 file', async () => {
    const url = approver.startPairing();
    const code = new URL(url).hash.slice(1);
    expect(url.startsWith(`${origin}/pair#`)).toBe(true);
    const file = join(dir, 'pairing-url');
    expect(readFileSync(file, 'utf8').trim()).toBe(url);
    expect(statSync(file).mode & 0o777).toBe(0o600);
    expect(statSync(dir).mode & 0o777).toBe(0o700);
    expect((await post('/api/pair/options', { code: 'A'.repeat(43) })).status).toBe(403);
    expect((await post('/api/pair/options', {})).status).toBe(403);
    const ok = await post('/api/pair/options', { code });
    expect(ok.status).toBe(200);
    const o = JSON.parse(ok.body);
    expect(o.rp.id).toBe(ORIGIN_HOST);
    expect(o.authenticatorSelection.userVerification).toBe('required');
    expect(o.pubKeyCredParams).toEqual([{ type: 'public-key', alg: -7 }]);
    const fin = await post('/api/pair/finish', { code, response: { id: 'x', response: {} } });
    expect(fin.status).toBe(400);
    expect(fin.headers['set-cookie']).toBeUndefined();
    expect(keys).toHaveLength(0);
  });

  it('the VAPID key is private to the approver dir', () => {
    expect(statSync(join(dir, 'vapid.json')).mode & 0o777).toBe(0o600);
  });
});
