import { createECDH, randomBytes } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { request } from 'node:http';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { WebAuthnApproverKey } from '@aab/signer/approval';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { DeviceStore } from '../src/devices.ts';
import { PhoneApprover } from '../src/phone.ts';

const HOST = 'approver.localhost';

const freePort = (): Promise<number> =>
  new Promise((resolve) => {
    const s = createServer().listen(0, '127.0.0.1', () => {
      const { port } = s.address() as { port: number };
      s.close(() => resolve(port));
    });
  });

describe('a phone approver started the way the daemon starts it', () => {
  let root: string;
  let approver: PhoneApprover;
  let port: number;
  let origin: string;
  let cookie: string;
  let subscription: (endpoint: string) => unknown;

  const post = (path: string, body: unknown): Promise<number> =>
    new Promise((resolve, reject) => {
      const r = request(
        {
          host: '127.0.0.1',
          port,
          path,
          method: 'POST',
          headers: {
            host: `${HOST}:${port}`,
            origin,
            cookie,
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

  beforeEach(async () => {
    root = mkdtempSync(join(tmpdir(), 'keyflap-pushdef-'));
    const dir = join(root, 'approver');
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    port = await freePort();
    origin = `http://${HOST}:${port}`;
    const key: WebAuthnApproverKey = {
      credentialId: randomBytes(32).toString('base64url'),
      x: 'x',
      y: 'y',
      rpId: HOST,
      origin,
      signCount: 0,
      createdAt: 0,
    };
    cookie = `__Host-aab_device=${new DeviceStore(join(dir, 'devices.json')).add(key.credentialId).token}`;
    const phone = createECDH('prime256v1');
    phone.generateKeys();
    subscription = (endpoint) => ({
      subscription: {
        endpoint,
        keys: {
          p256dh: phone.getPublicKey().toString('base64url'),
          auth: Buffer.alloc(16, 3).toString('base64url'),
        },
      },
    });
    approver = await PhoneApprover.start({
      auditBefore: () => {},
      dir,
      origin,
      listen: { host: '127.0.0.1', port },
      signer: {
        listApprovers: async () => ({ approvers: [key] }),
        addApprover: async () => ({ added: true }),
      },
    });
  });
  afterEach(async () => {
    await approver.close();
    rmSync(root, { recursive: true, force: true });
  });

  it('takes push subscriptions only for real push services, never for a plain-http or internal endpoint', async () => {
    expect(await post('/api/push', subscription('https://fcm.googleapis.com/fcm/send/abc'))).toBe(
      200,
    );
    expect(await post('/api/push', subscription('http://127.0.0.1:9/push'))).toBe(400);
    expect(await post('/api/push', subscription('https://127.0.0.1/push'))).toBe(400);
    expect(await post('/api/push', subscription('https://internal.example.net/push'))).toBe(400);
  });
});
