import { chmodSync, lstatSync, mkdirSync, unlinkSync } from 'node:fs';
import { connect, type Server } from 'node:net';
import { dirname } from 'node:path';
import { assertUnixSocketPath } from '@aab/signer/platform';

export async function removeStaleSocket(path: string, what: string): Promise<void> {
  let isSocket: boolean;
  try {
    isSocket = lstatSync(path).isSocket();
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return;
    throw err;
  }
  if (!isSocket) throw new Error(`${what}: socket path exists and is not a socket`);
  const state = await new Promise<'live' | 'stale'>((resolve, reject) => {
    const probe = connect(path);
    const timer = setTimeout(() => {
      probe.destroy();
      resolve('live');
    }, 2_000);
    probe.once('connect', () => {
      clearTimeout(timer);
      probe.destroy();
      resolve('live');
    });
    probe.once('error', (err: NodeJS.ErrnoException) => {
      clearTimeout(timer);
      probe.destroy();
      if (err.code === 'ECONNREFUSED' || err.code === 'ENOENT') resolve('stale');
      else reject(err);
    });
  });
  if (state === 'live') throw new Error(`${what}: something is already listening on ${path}`);
  try {
    unlinkSync(path);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
  }
}

export async function listenUnix(server: Server, path: string, what: string): Promise<void> {
  assertUnixSocketPath(path, what);
  const dir = dirname(path);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  chmodSync(dir, 0o700);
  await removeStaleSocket(path, what);
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(path, () => {
      server.off('error', reject);
      resolve();
    });
  });
  chmodSync(path, 0o600);
}
