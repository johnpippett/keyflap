import { randomBytes } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import { connect, type Server, type Socket } from 'node:net';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { SignerClient, type SpawnedSigner, spawnSigner } from '../src/client.ts';
import { KeyStore } from '../src/keystore.ts';
import { type Frame, macFor, readFrames, writeFrame } from '../src/protocol.ts';
import { SignerHandler, startSignerServer } from '../src/server.ts';
import { testApprover, tmpDir } from './helpers.ts';

async function rawConnect(path: string) {
  const socket: Socket = connect(path);
  const frames: Frame[] = [];
  let closed = false;
  socket.on('close', () => {
    closed = true;
  });
  socket.on('error', () => {});
  readFrames(
    socket,
    (f) => frames.push(f),
    () => {},
  );
  await new Promise<void>((r) => socket.once('connect', () => r()));
  await waitFor(() => frames.length > 0);
  const hello = frames.shift() as Extract<Frame, { t: 'hello' }>;
  return {
    socket,
    nonce: hello.nonce,
    frames,
    isClosed: () => closed,
    send: (seq: number, body: string, mac: string) =>
      writeFrame(socket, { t: 'req', seq, body, mac }),
  };
}

async function waitFor(cond: () => boolean, ms = 2000): Promise<void> {
  const start = Date.now();
  while (!cond()) {
    if (Date.now() - start > ms) throw new Error('timeout');
    await new Promise((r) => setTimeout(r, 10));
  }
}

describe('invariant 9: authenticated signer channel', () => {
  const key = randomBytes(32);
  let server: Server | undefined;
  let spawned: SpawnedSigner | undefined;
  afterEach(async () => {
    await new Promise<void>((r) => (server ? server.close(() => r()) : r()));
    server = undefined;
    await spawned?.stop();
    spawned = undefined;
  });

  async function start(handshakeTimeoutMs?: number) {
    const dir = tmpDir();
    const socketPath = join(dir, 'run', 'signer.sock');
    server = await startSignerServer({
      socketPath,
      channelKey: key,
      handshakeTimeoutMs,
      handler: new SignerHandler({
        store: KeyStore.open(join(dir, 'keys'), 'pw'),
        trustedApproverKeys: {},
      }),
    });
    return { dir, socketPath };
  }

  const ping = JSON.stringify({ op: 'ping' });

  it('serves a correctly authenticated request', async () => {
    const { socketPath } = await start();
    const c = await rawConnect(socketPath);
    c.send(1, ping, macFor(key, 'req', c.nonce, 1, ping));
    await waitFor(() => c.frames.length === 1);
    const res = c.frames[0] as Extract<Frame, { t: 'res' }>;
    expect(JSON.parse(res.body)).toEqual({ ok: true, result: { pong: true } });
    expect(res.mac).toBe(macFor(key, 'res', c.nonce, 1, res.body));
    c.socket.destroy();
  });

  it('drops a caller that does not hold the channel key', async () => {
    const { socketPath } = await start();
    const c = await rawConnect(socketPath);
    c.send(1, ping, macFor(randomBytes(32), 'req', c.nonce, 1, ping));
    await waitFor(c.isClosed);
    expect(c.frames).toHaveLength(0);
  });

  it('drops a request with no MAC at all', async () => {
    const { socketPath } = await start();
    const c = await rawConnect(socketPath);
    writeFrame(c.socket, { t: 'req', seq: 1, body: ping } as unknown as Frame);
    await waitFor(c.isClosed);
    expect(c.frames).toHaveLength(0);
  });

  it('browser_state_key: answered on the authenticated channel, refused without a valid MAC', async () => {
    const { socketPath } = await start();
    const body = JSON.stringify({ op: 'browser_state_key' });
    const bad = await rawConnect(socketPath);
    bad.send(1, body, macFor(randomBytes(32), 'req', bad.nonce, 1, body));
    await waitFor(bad.isClosed);
    expect(bad.frames).toHaveLength(0);
    const unmaced = await rawConnect(socketPath);
    writeFrame(unmaced.socket, { t: 'req', seq: 1, body } as unknown as Frame);
    await waitFor(unmaced.isClosed);
    expect(unmaced.frames).toHaveLength(0);
    const good = await rawConnect(socketPath);
    good.send(1, body, macFor(key, 'req', good.nonce, 1, body));
    await waitFor(() => good.frames.length === 1);
    const res = JSON.parse((good.frames[0] as Extract<Frame, { t: 'res' }>).body);
    expect(res.ok).toBe(true);
    expect(Buffer.from(res.result.key, 'base64url')).toHaveLength(32);
    good.socket.destroy();
  });

  it('P3b accept_handoff_grant / drop_grant: refused without a valid MAC', async () => {
    const { socketPath } = await start();
    for (const body of [
      JSON.stringify({ op: 'accept_handoff_grant', approval: {} }),
      JSON.stringify({ op: 'drop_grant', grantId: 'g-1' }),
    ]) {
      const bad = await rawConnect(socketPath);
      bad.send(1, body, macFor(randomBytes(32), 'req', bad.nonce, 1, body));
      await waitFor(bad.isClosed);
      expect(bad.frames).toHaveLength(0);
      const unmaced = await rawConnect(socketPath);
      writeFrame(unmaced.socket, { t: 'req', seq: 1, body } as unknown as Frame);
      await waitFor(unmaced.isClosed);
      expect(unmaced.frames).toHaveLength(0);
      const good = await rawConnect(socketPath);
      good.send(1, body, macFor(key, 'req', good.nonce, 1, body));
      await waitFor(() => good.frames.length === 1);
      const res = JSON.parse((good.frames[0] as Extract<Frame, { t: 'res' }>).body);
      expect(res).toEqual(
        body.includes('drop_grant')
          ? { ok: true, result: { dropped: false } }
          : { ok: false, error: 'bad_statement' },
      );
      good.socket.destroy();
    }
  });

  it('rejects a replayed frame on the same connection', async () => {
    const { socketPath } = await start();
    const c = await rawConnect(socketPath);
    const mac = macFor(key, 'req', c.nonce, 1, ping);
    c.send(1, ping, mac);
    await waitFor(() => c.frames.length === 1);
    c.send(1, ping, mac);
    await waitFor(c.isClosed);
    expect(c.frames).toHaveLength(1);
  });

  it('rejects a frame captured from another connection (fresh nonce per connection)', async () => {
    const { socketPath } = await start();
    const a = await rawConnect(socketPath);
    const captured = macFor(key, 'req', a.nonce, 1, ping);
    const b = await rawConnect(socketPath);
    expect(b.nonce).not.toBe(a.nonce);
    b.send(1, ping, captured);
    await waitFor(b.isClosed);
    expect(b.frames).toHaveLength(0);
    a.socket.destroy();
  });

  it('rejects a body altered after MACing', async () => {
    const { socketPath } = await start();
    const c = await rawConnect(socketPath);
    const forged = JSON.stringify({ op: 'sign', credentialId: 'x' });
    c.send(1, forged, macFor(key, 'req', c.nonce, 1, ping));
    await waitFor(c.isClosed);
    expect(c.frames).toHaveLength(0);
  });

  it('rejects oversized frames', async () => {
    const { socketPath } = await start();
    const c = await rawConnect(socketPath);
    const header = Buffer.alloc(4);
    header.writeUInt32BE(10 * 1024 * 1024);
    c.socket.write(header);
    await waitFor(c.isClosed);
    expect(c.frames).toHaveLength(0);
  });

  it('closes a connection that never authenticates within the handshake timeout', async () => {
    const { socketPath } = await start(200);
    const c = await rawConnect(socketPath);
    const t0 = Date.now();
    await waitFor(c.isClosed, 2000);
    expect(Date.now() - t0).toBeGreaterThanOrEqual(150);
    expect(c.frames).toHaveLength(0);
  });

  it('handshake timeout is a hard deadline: trickling bytes does not extend it', async () => {
    const { socketPath } = await start(200);
    const c = await rawConnect(socketPath);
    const header = Buffer.alloc(4);
    header.writeUInt32BE(64);
    c.socket.write(header);
    const drip = setInterval(() => c.socket.write('a'), 50);
    try {
      await waitFor(c.isClosed, 2000);
    } finally {
      clearInterval(drip);
    }
  });

  it('an authenticated connection stays usable after idling past the handshake timeout', async () => {
    const { socketPath } = await start(200);
    const c = await rawConnect(socketPath);
    c.send(1, ping, macFor(key, 'req', c.nonce, 1, ping));
    await waitFor(() => c.frames.length === 1);
    await new Promise((r) => setTimeout(r, 500));
    expect(c.isClosed()).toBe(false);
    c.send(2, ping, macFor(key, 'req', c.nonce, 2, ping));
    await waitFor(() => c.frames.length === 2);
    const res = c.frames[1] as Extract<Frame, { t: 'res' }>;
    expect(JSON.parse(res.body)).toEqual({ ok: true, result: { pong: true } });
    c.socket.destroy();
  });

  it('SignerClient stays usable after idling past the handshake timeout', async () => {
    const { socketPath } = await start(200);
    const client = new SignerClient(socketPath, key);
    expect(await client.ping()).toEqual({ pong: true });
    await new Promise((r) => setTimeout(r, 500));
    expect(await client.ping()).toEqual({ pong: true });
    client.close();
  });

  it('keeps the socket private to its owner (0700 dir, 0600 socket)', async () => {
    const { socketPath, dir } = await start();
    expect(statSync(join(dir, 'run')).mode & 0o777).toBe(0o700);
    expect(statSync(socketPath).mode & 0o777).toBe(0o600);
  });

  it('client refuses a response that is not MACed by the real signer', async () => {
    const { createServer } = await import('node:net');
    const dir = tmpDir();
    const path = join(dir, 'fake.sock');
    server = createServer((s) => {
      const nonce = 'n';
      writeFrame(s, { t: 'hello', nonce });
      readFrames(
        s,
        (f) => {
          if (f.t === 'req') {
            writeFrame(s, {
              t: 'res',
              seq: f.seq,
              body: '{"ok":true,"result":{"pong":true}}',
              mac: 'forged',
            });
          }
        },
        () => {},
      );
    });
    await new Promise<void>((r) => server?.listen(path, () => r()));
    const client = new SignerClient(path, key);
    await expect(client.ping()).rejects.toThrow(/authentication/);
    client.close();
  });

  it('spawned signer: secrets are not in argv or environment, and a keyless client is refused', async () => {
    const dir = tmpDir();
    const passphrase = `pp-${randomBytes(8).toString('hex')}`;
    const socketPath = join(dir, 'run', 'signer.sock');
    spawned = await spawnSigner({
      socketPath,
      storePath: join(dir, 'keys'),
      passphrase,
      trustedApproverKeys: testApprover().trusted,
    });
    expect(await spawned.client.ping()).toEqual({ pong: true });

    const pid = spawned.process.pid as number;
    if (process.platform === 'linux') {
      const cmdline = readFileSync(`/proc/${pid}/cmdline`, 'utf8');
      const environ = readFileSync(`/proc/${pid}/environ`, 'utf8');
      expect(cmdline).not.toContain(passphrase);
      expect(environ).not.toContain(passphrase);
      expect(
        environ
          .split('\0')
          .filter(Boolean)
          .map((e) => e.split('=')[0]),
      ).toEqual(['PATH']);
    }

    const intruder = new SignerClient(socketPath, randomBytes(32));
    await expect(intruder.ping()).rejects.toThrow();
    intruder.close();
    expect(await spawned.client.ping()).toEqual({ pong: true });
  });

  it('spawned signer survives non-object frames; each bad connection is dropped', async () => {
    const dir = tmpDir();
    const socketPath = join(dir, 'run', 'signer.sock');
    const logs: string[] = [];
    spawned = await spawnSigner({
      socketPath,
      storePath: join(dir, 'keys'),
      passphrase: 'pw',
      trustedApproverKeys: testApprover().trusted,
      onLog: (l) => logs.push(l),
    });
    const payloads = ['null', '[]', '1', '"x"', 'true', '{}', '{"t":"req","seq":1}'];
    for (const raw of payloads) {
      const c = await rawConnect(socketPath);
      const body = Buffer.from(raw, 'utf8');
      const header = Buffer.alloc(4);
      header.writeUInt32BE(body.length);
      c.socket.write(Buffer.concat([header, body]));
      await waitFor(c.isClosed);
      expect(c.frames, raw).toHaveLength(0);
      expect(spawned.process.exitCode, raw).toBeNull();
      expect(spawned.process.signalCode, raw).toBeNull();
    }
    expect(await spawned.client.ping()).toEqual({ pong: true });
    expect(logs.some((l) => l.includes('"fatal"'))).toBe(false);
  });

  it('client fails closed on non-object or malformed frames from the server', async () => {
    const { createServer } = await import('node:net');
    for (const raw of ['null', '[]', '1', '"x"', 'true', '{"t":"hello","nonce":5}']) {
      const dir = tmpDir();
      const path = join(dir, 'fake.sock');
      const fake = createServer((s) => {
        const body = Buffer.from(raw, 'utf8');
        const header = Buffer.alloc(4);
        header.writeUInt32BE(body.length);
        s.on('error', () => {});
        s.write(Buffer.concat([header, body]));
      });
      await new Promise<void>((r) => fake.listen(path, () => r()));
      const client = new SignerClient(path, key);
      await expect(client.ping(), raw).rejects.toThrow();
      client.close();
      await new Promise<void>((r) => fake.close(() => r()));
    }
  });
});
