import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import type { Server } from 'node:net';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { type SpawnedSigner, spawnSigner } from '../src/client.ts';
import { KeyStore } from '../src/keystore.ts';
import { acquireLock, LockHeldError } from '../src/lock.ts';
import { SignerHandler, startSignerServer } from '../src/server.ts';
import { testApprover, tmpDir } from './helpers.ts';

function deadPid(): number {
  const r = spawnSync(process.execPath, ['-e', '']);
  return r.pid as number;
}

async function staleSocket(path: string): Promise<void> {
  const child = spawn(
    process.execPath,
    [
      '-e',
      `require('node:net').createServer().listen(${JSON.stringify(path)}, () => console.log('up'))`,
    ],
    { stdio: ['ignore', 'pipe', 'ignore'] },
  );
  await new Promise<void>((resolve) => child.stdout?.once('data', () => resolve()));
  await new Promise<void>((resolve) => {
    child.once('exit', () => resolve());
    child.kill('SIGKILL');
  });
  expect(statSync(path).isSocket()).toBe(true);
}

function handler(dir: string) {
  return new SignerHandler({
    store: KeyStore.open(join(dir, 'keys'), 'pw'),
    trustedApproverKeys: {},
  });
}

describe('signer: one live instance per key store', () => {
  const signers: SpawnedSigner[] = [];
  const servers: Server[] = [];
  afterEach(async () => {
    for (const s of signers.splice(0)) await s.stop();
    for (const s of servers.splice(0)) await new Promise<void>((r) => s.close(() => r()));
  });

  async function spawnOn(dir: string, socketName = 'signer.sock') {
    const s = await spawnSigner({
      socketPath: join(dir, 'run', socketName),
      storePath: join(dir, 'keys'),
      passphrase: 'pw',
      trustedApproverKeys: testApprover().trusted,
    });
    signers.push(s);
    return s;
  }

  it('refuses a second signer on the same data dir while the first is alive', async () => {
    const dir = tmpDir();
    const first = await spawnOn(dir);
    expect(readFileSync(join(dir, 'keys.lock'), 'utf8').trim()).toBe(String(first.process.pid));

    await expect(spawnOn(dir)).rejects.toThrow(/exited early/);
    await expect(spawnOn(dir, 'other.sock')).rejects.toThrow(/exited early/);

    expect(first.process.exitCode).toBeNull();
    expect(await first.client.ping()).toEqual({ pong: true });
    expect(statSync(join(dir, 'run', 'signer.sock')).isSocket()).toBe(true);
  });

  it('releases the store lock on clean shutdown so a new signer can start', async () => {
    const dir = tmpDir();
    const first = await spawnOn(dir);
    await first.stop();
    expect(existsSync(join(dir, 'keys.lock'))).toBe(false);
    const second = await spawnOn(dir);
    expect(await second.client.ping()).toEqual({ pong: true });
  });

  it('reclaims a stale lock left by a dead process', async () => {
    const dir = tmpDir();
    writeFileSync(join(dir, 'keys.lock'), `${deadPid()}\n`);
    const s = await spawnOn(dir);
    expect(await s.client.ping()).toEqual({ pong: true });
    expect(readFileSync(join(dir, 'keys.lock'), 'utf8').trim()).toBe(String(s.process.pid));
  });

  it('reclaims a stale socket file with nothing listening', async () => {
    const dir = tmpDir();
    const socketPath = join(dir, 'run', 'signer.sock');
    mkdirSync(join(dir, 'run'), { mode: 0o700 });
    await staleSocket(socketPath);
    const s = await spawnOn(dir);
    expect(await s.client.ping()).toEqual({ pong: true });
  });

  it('startSignerServer throws if another server is live on the socket path', async () => {
    const dir = tmpDir();
    const socketPath = join(dir, 'run', 'signer.sock');
    const channelKey = randomBytes(32);
    servers.push(await startSignerServer({ socketPath, channelKey, handler: handler(dir) }));
    await expect(
      startSignerServer({ socketPath, channelKey, handler: handler(tmpDir()) }),
    ).rejects.toThrow(/already listening/);
    expect(statSync(socketPath).isSocket()).toBe(true);
  });

  it('startSignerServer refuses a socket path that is not a socket', async () => {
    const dir = tmpDir();
    const socketPath = join(dir, 'not-a-socket');
    writeFileSync(socketPath, 'x');
    await expect(
      startSignerServer({ socketPath, channelKey: randomBytes(32), handler: handler(dir) }),
    ).rejects.toThrow(/not a socket/);
  });
});

describe('key store lock', () => {
  it('is exclusive while the holder is alive and released only by its owner', () => {
    const path = join(tmpDir(), 'keys.lock');
    const lock = acquireLock(path);
    expect(readFileSync(path, 'utf8')).toBe(`${process.pid}\n`);
    expect(() => acquireLock(path)).toThrow(LockHeldError);
    lock.release();
    expect(existsSync(path)).toBe(false);
    const again = acquireLock(path);
    again.release();
  });

  it('refuses when the lock names another live process', () => {
    const path = join(tmpDir(), 'keys.lock');
    writeFileSync(path, '1\n');
    expect(() => acquireLock(path)).toThrow(LockHeldError);
    expect(readFileSync(path, 'utf8')).toBe('1\n');
  });

  it('treats a dead pid or unreadable content as stale', () => {
    for (const content of [`${deadPid()}\n`, 'garbage', '']) {
      const path = join(tmpDir(), 'keys.lock');
      writeFileSync(path, content);
      const lock = acquireLock(path);
      expect(readFileSync(path, 'utf8')).toBe(`${process.pid}\n`);
      lock.release();
    }
  });

  it('does not remove a lock that has been taken over by someone else', () => {
    const path = join(tmpDir(), 'keys.lock');
    const lock = acquireLock(path);
    writeFileSync(path, '1\n');
    lock.release();
    expect(readFileSync(path, 'utf8')).toBe('1\n');
  });
});
