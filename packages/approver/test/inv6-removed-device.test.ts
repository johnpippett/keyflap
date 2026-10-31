import { createHash, randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { PhoneApprover } from '../src/phone.ts';

describe('invariant 6: a removed phone loses access without a core restart', () => {
  it('GET /api/state and deny answer 401 once the signer no longer trusts the device', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'a06-'));
    const token = randomBytes(32).toString('base64url');
    writeFileSync(
      join(dir, 'devices.json'),
      JSON.stringify({
        devices: [
          {
            id: 'dev_1',
            tokenHash: createHash('sha256').update(token).digest('base64url'),
            credentialId: 'CRED1',
            createdAt: 0,
            kind: 'web',
          },
        ],
      }),
    );
    const ORIGIN = 'http://approver.localhost';
    const key = (id: string) => ({
      credentialId: id,
      x: 'x',
      y: 'y',
      rpId: 'approver.localhost',
      origin: ORIGIN,
      signCount: 0,
      createdAt: 0,
    });
    let approvers = [key('CRED1'), key('CRED2')];
    let signerUp = true;
    const signer = {
      async listApprovers() {
        if (!signerUp) throw new Error('signer down');
        return { approvers };
      },
      async addApprover() {
        return { added: true };
      },
    };
    const a = await PhoneApprover.start({
      dir,
      origin: ORIGIN,
      listen: { host: '127.0.0.1', port: 0 },
      signer,
    } as never);
    try {
      const port = new URL(a.listenUrl).port;
      const headers = { host: `approver.localhost:${port}`, cookie: `__Host-aab_device=${token}` };
      const pending = a.request({
        display: {
          intentText: 'my private words',
          intentAt: Date.now(),
          verifiedOrigin: 'https://bank.example',
          agentName: 'agent',
          credentialType: 'password',
          action: 'sign-in',
        },
        policy: { tier: 'ask' },
        binding: {
          requestId: 'req-1',
          kind: 'fill',
          rpId: 'bank.example',
          credentialId: 'i',
          intentHash: 'h',
          clientDataHash: 'c',
        },
      } as never);
      await new Promise((r) => setTimeout(r, 50));
      expect((await fetch(`http://127.0.0.1:${port}/api/state`, { headers })).status).toBe(200);
      signerUp = false;
      const down = await fetch(`http://127.0.0.1:${port}/api/state`, { headers });
      expect(down.status).toBe(503);
      expect(await down.text()).not.toContain('my private words');
      signerUp = true;
      approvers = [key('CRED2')];
      const after = await fetch(`http://127.0.0.1:${port}/api/state`, { headers });
      const body = await after.text();
      expect(after.status).toBe(401);
      expect(body).not.toContain('my private words');
      const deny = await fetch(`http://127.0.0.1:${port}/api/decide`, {
        method: 'POST',
        headers: { ...headers, origin: ORIGIN, 'content-type': 'application/json' },
        body: JSON.stringify({ id: 'req-1', decision: 'deny' }),
      });
      expect(deny.status).toBe(401);
      const push = await fetch(`http://127.0.0.1:${port}/api/push`, {
        method: 'POST',
        headers: { ...headers, origin: ORIGIN, 'content-type': 'application/json' },
        body: JSON.stringify({ subscription: null }),
      });
      expect(push.status).toBe(401);
      expect(readFileSync(join(dir, 'devices.json'), 'utf8')).not.toContain('dev_1');
      approvers = [key('CRED1'), key('CRED2')];
      expect((await fetch(`http://127.0.0.1:${port}/api/state`, { headers })).status).toBe(401);
      void pending;
    } finally {
      await a.close();
    }
  });
});
