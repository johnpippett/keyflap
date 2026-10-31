import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { maxUnixSocketPathBytes } from '@aab/signer/platform';
import { describe, expect, it } from 'vitest';
import { type DaemonOptions, startDaemon } from '../src/daemon.ts';
import { listenUnix } from '../src/unix-socket.ts';

function deepDir(): { base: string; dir: string } {
  const base = mkdtempSync(join(tmpdir(), 'keyflap-sp-'));
  const pad = 'd'.repeat(Math.max(1, maxUnixSocketPathBytes() - Buffer.byteLength(base)));
  return { base, dir: join(base, pad) };
}

describe('unix socket paths too long for this platform', () => {
  it('startDaemon refuses before creating the data dir or starting anything', async () => {
    const { base, dir } = deepDir();
    try {
      await expect(startDaemon({ dataDir: dir } as DaemonOptions)).rejects.toThrow(
        /intent socket: .*limited to \d+ bytes/,
      );
      expect(existsSync(dir)).toBe(false);
    } finally {
      rmSync(base, { recursive: true, force: true });
    }
  });

  it('listenUnix refuses instead of binding a truncated path', async () => {
    const { base, dir } = deepDir();
    const server = createServer();
    try {
      await expect(
        listenUnix(server, join(dir, 'run', 'intent.sock'), 'intent socket'),
      ).rejects.toThrow(/intent socket: .*limited to/);
      expect(server.listening).toBe(false);
      expect(existsSync(dir)).toBe(false);
    } finally {
      server.close();
      rmSync(base, { recursive: true, force: true });
    }
  });
});
