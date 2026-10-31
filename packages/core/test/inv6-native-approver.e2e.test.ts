import { generateKeyPairSync, sign } from 'node:crypto';
import { request } from 'node:http';
import { createServer as createNetServer } from 'node:net';
import { join } from 'node:path';
import {
  type ApprovalDecision,
  type ApprovalRequest,
  type Approver,
  PhoneApprover,
} from '@aab/approver';
import {
  type ApprovalStatement,
  nativeApprovalSigningBytes,
  nativeApproverDescriptor,
  nativeKeyId,
  nativePairingProofBytes,
  type SignedApproval,
} from '@aab/signer/approval';
import { startTestRp, type TestRp } from '@aab/test-rp';
import type { Page } from 'playwright';
import { afterEach, describe, expect, it } from 'vitest';
import { type Daemon, startDaemon } from '../src/daemon.ts';
import { tmpDir } from './harness.ts';

async function freePort(): Promise<number> {
  return new Promise((resolve) => {
    const s = createNetServer().listen(0, '127.0.0.1', () => {
      const p = (s.address() as { port: number }).port;
      s.close(() => resolve(p));
    });
  });
}

class Recording implements Approver {
  readonly decisions: ApprovalDecision[] = [];
  readonly requests: ApprovalRequest[] = [];
  inner: Approver | null = null;
  async request(req: ApprovalRequest, o?: { signal?: AbortSignal }) {
    this.requests.push(req);
    const d = await (this.inner as Approver).request(req, o);
    this.decisions.push(d);
    return d;
  }
}

function nativeApp(port: number, host: string, origin: string) {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' });
  const x = jwk.x as string;
  const y = jwk.y as string;
  const keyId = nativeKeyId(x, y);
  let token = '';
  const call = (method: string, path: string, body?: unknown) =>
    new Promise<{ status: number; json: Record<string, unknown> }>((resolve, reject) => {
      const r = request(
        {
          host: '127.0.0.1',
          port,
          path,
          method,
          headers: {
            host,
            ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
            ...(token ? { authorization: `Bearer ${token}` } : {}),
          },
        },
        (res) => {
          let data = '';
          res.on('data', (c) => {
            data += c;
          });
          res.on('end', () =>
            resolve({ status: res.statusCode ?? 0, json: data ? JSON.parse(data) : {} }),
          );
        },
      );
      r.on('error', reject);
      r.end(body === undefined ? undefined : JSON.stringify(body));
    });
  return {
    keyId,
    async pair(link: string) {
      const code = new URL(link).hash.slice(1);
      const descriptor = nativeApproverDescriptor({
        keyId,
        x,
        y,
        origin,
        userVerification: 'biometry',
      });
      const proof = sign('sha256', nativePairingProofBytes(descriptor), {
        key: privateKey,
        dsaEncoding: 'der',
      }).toString('base64url');
      const r = await call('POST', '/api/native/pair', {
        code,
        key: { x, y },
        userVerification: 'biometry',
        proof,
      });
      expect(r.status).toBe(200);
      token = r.json.deviceToken as string;
    },
    async approveNext(): Promise<{
      display: Record<string, unknown>;
      statement: ApprovalStatement;
    }> {
      for (let i = 0; i < 300; i++) {
        const st = await call('GET', '/api/native/state');
        const p = (st.json.pending as { id: string; display: Record<string, unknown> }[])[0];
        if (p) {
          const ch = await call('POST', '/api/native/challenge', { id: p.id });
          const statement = ch.json.statement as ApprovalStatement;
          const signature = sign('sha256', nativeApprovalSigningBytes(statement), {
            key: privateKey,
            dsaEncoding: 'der',
          }).toString('base64url');
          const d = await call('POST', '/api/native/decide', {
            id: p.id,
            decision: 'approve',
            signature,
          });
          expect(d.status).toBe(200);
          return { display: p.display, statement };
        }
        await new Promise((r) => setTimeout(r, 50));
      }
      throw new Error('no request reached the app');
    },
  };
}

const rpStatus = (p: Page) =>
  p
    .waitForFunction(() => document.querySelector('#status')?.textContent !== 'working')
    .then(() => p.textContent('#status'));

describe('invariant 6: the native iOS approver approves high-risk sign-ins with its own signature', () => {
  let rp: TestRp | null = null;
  let daemon: Daemon | null = null;
  afterEach(async () => {
    await daemon?.stop();
    await rp?.close();
    daemon = null;
    rp = null;
  });

  it('pairs, then approves a high-risk registration and sign-in; the signer verified the app key', async () => {
    rp = await startTestRp({ host: 'rp.localhost', userVerification: 'required' });
    const dataDir = tmpDir();
    const port = await freePort();
    const origin = `http://approver.localhost:${port}`;
    const recording = new Recording();
    let approver: PhoneApprover | null = null;
    daemon = await startDaemon({
      dataDir,
      passphrase: 'test-passphrase',
      trustedApproverKeys: {},
      highRiskDomains: ['rp.localhost'],
      approvalTimeoutMs: 30_000,
      makeApprover: async ({ signer, audit, auditBefore }) => {
        approver = await PhoneApprover.start({
          dir: join(dataDir, 'approver'),
          origin,
          listen: { host: '127.0.0.1', port },
          signer,
          onEvent: audit,
          auditBefore,
          timeoutMs: 25_000,
        });
        recording.inner = approver;
        const a = approver;
        return { approver: recording, close: () => a.close() };
      },
    });
    const app = nativeApp(port, `approver.localhost:${port}`, origin);
    await app.pair((approver as unknown as PhoneApprover).startPairing());
    const listed = await daemon.signer.client.listApprovers();
    expect(listed.approvers).toHaveLength(0);
    expect(listed.native?.map((k) => k.keyId)).toEqual([app.keyId]);

    const agent = daemon.registry.add('test-agent');
    daemon.broker.intents.record(agent.id, 'sign me in to the test site');
    const page = await (await daemon.sessions.get(agent)).newPage();
    await page.goto(`${rp.url}signup`);
    await page.fill('#username', 'nia');
    await page.click('#signup');
    await page.click('#add-passkey');
    const reg = await app.approveNext();
    expect(await rpStatus(page)).toBe('passkey added');
    expect(reg.display).toEqual({
      intentText: 'sign me in to the test site',
      intentAt: expect.any(Number),
      verifiedOrigin: rp.origin,
      agentName: 'test-agent',
      credentialType: 'passkey',
      action: 'register',
    });
    expect(reg.statement.kind).toBe('webauthn.create');

    await page.click('#logout');
    await page.goto(`${rp.url}login`);
    await page.click('#passkey-login');
    await app.approveNext();
    await page.waitForURL('**/account');
    expect(await page.textContent('#whoami')).toBe('Signed in as nia');

    expect(recording.requests.map((r) => r.policy.tier)).toEqual(['ask-strong', 'ask-strong']);
    for (const d of recording.decisions) {
      expect(d.approved).toBe(true);
      const a = (d as { approval: SignedApproval }).approval;
      expect(a.native).toBeDefined();
      expect(a.webauthn).toBeUndefined();
      expect(a.signature).toBeUndefined();
      expect(a.approverKeyId).toBe(app.keyId);
      expect(a.statement.userVerified).toBe(true);
      expect(a.statement.strong).toBe(true);
      expect(a.statement.expiresAt - a.statement.issuedAt).toBeLessThanOrEqual(60_000);
    }
    expect(daemon.broker.audit.verify()).toBeNull();
  });
});
