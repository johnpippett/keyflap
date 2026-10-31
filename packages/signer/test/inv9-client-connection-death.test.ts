import { randomBytes } from 'node:crypto';
import { createServer, type Server, type Socket } from 'node:net';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { SignerClient } from '../src/client.ts';
import { readFrames, writeFrame } from '../src/protocol.ts';
import { tmpDir } from './helpers.ts';

const key = randomBytes(32);
const HUNG = Symbol('hung');
const GONE = /signer connection closed|ECONNRESET|EPIPE/;

const within = <T>(p: Promise<T>, ms: number): Promise<T | typeof HUNG> =>
  Promise.race([p, new Promise<typeof HUNG>((r) => setTimeout(() => r(HUNG), ms))]);

describe('invariant 9: a signer connection that dies never leaves callers waiting', () => {
  let server: Server | undefined;
  let client: SignerClient | undefined;
  afterEach(async () => {
    client?.close();
    client = undefined;
    await new Promise<void>((r) => (server ? server.close(() => r()) : r()));
    server = undefined;
  });

  async function fakeSigner(onConnection: (s: Socket) => void): Promise<string> {
    const path = join(tmpDir(), 's.sock');
    server = createServer((s) => {
      s.on('error', () => {});
      onConnection(s);
    });
    await new Promise<void>((r) => server?.listen(path, () => r()));
    return path;
  }
  const rejection = (p: Promise<unknown>) =>
    p.then(
      () => 'resolved',
      (e: Error) => e.message,
    );

  it('dies before the hello: ping rejects promptly instead of waiting', async () => {
    const path = await fakeSigner((s) => s.destroy());
    client = new SignerClient(path, key);
    expect(await within(rejection(client.ping()), 1000)).toMatch(GONE);
  });

  it('nothing listens at the path: ping rejects promptly', async () => {
    const path = join(tmpDir(), 'nobody.sock');
    client = new SignerClient(path, key);
    const outcome = await within(rejection(client.ping()), 1000);
    expect(outcome).not.toBe(HUNG);
    expect(outcome).toMatch(/ENOENT|ECONNREFUSED/);
  });

  it('dies after the hello with a call in flight: that call and every later one reject', async () => {
    const path = await fakeSigner((s) => {
      readFrames(
        s,
        () => s.destroy(),
        () => {},
      );
      writeFrame(s, { t: 'hello', nonce: 'bm9uY2U' });
    });
    client = new SignerClient(path, key);
    const closed: string[] = [];
    client.onUnexpectedClose((e) => closed.push(e.message));
    expect(await within(rejection(client.ping()), 1000)).toMatch(GONE);
    expect(await within(rejection(client.ping()), 1000)).toMatch(GONE);
    expect(closed).toHaveLength(1);
    expect(closed[0]).toMatch(GONE);
  });

  it('a deliberate close() is not reported as an unexpected close', async () => {
    const path = await fakeSigner((s) => {
      writeFrame(s, { t: 'hello', nonce: 'bm9uY2U' });
    });
    client = new SignerClient(path, key);
    const closed: string[] = [];
    client.onUnexpectedClose((e) => closed.push(e.message));
    await new Promise((r) => setTimeout(r, 50));
    client.close();
    await new Promise((r) => setTimeout(r, 50));
    expect(closed).toEqual([]);
  });
});
