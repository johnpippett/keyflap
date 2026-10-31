import { createECDH } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { sendPush, VapidKey } from '../src/webpush.ts';

describe('web push: production sends draw fresh randomness', () => {
  let server: Server;
  let endpoint: string;
  let bodies: Buffer[];

  beforeEach(async () => {
    bodies = [];
    server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (c: Buffer) => chunks.push(c));
      req.on('end', () => {
        bodies.push(Buffer.concat(chunks));
        res.writeHead(201).end();
      });
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
    endpoint = `http://127.0.0.1:${(server.address() as { port: number }).port}/push/1`;
  });
  afterEach(() => new Promise<void>((resolve) => server.close(() => resolve())));

  it('the same message to the same phone has a new salt and a new ephemeral key every time', async () => {
    const phone = createECDH('prime256v1');
    phone.generateKeys();
    const sub = {
      endpoint,
      keys: {
        p256dh: phone.getPublicKey().toString('base64url'),
        auth: Buffer.alloc(16, 7).toString('base64url'),
      },
    };
    const vapid = VapidKey.generate();
    const payload = Buffer.from('{"t":"approval"}');
    for (let i = 0; i < 3; i++) {
      expect(await sendPush(sub, vapid, { subject: 'mailto:a@b', payload })).toBe('sent');
    }
    expect(bodies).toHaveLength(3);
    const salts = bodies.map((b) => b.subarray(0, 16).toString('hex'));
    const ephemeralKeys = bodies.map((b) => b.subarray(21, 21 + (b[20] as number)).toString('hex'));
    expect(new Set(salts).size).toBe(3);
    expect(new Set(ephemeralKeys).size).toBe(3);
    expect(new Set(bodies.map((b) => b.toString('hex'))).size).toBe(3);
  });
});
