import { randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { AdminCallError, AdminOps, adminCall, startAdminServer } from '../src/admin-wire.ts';
import { SignerClient, spawnSigner } from '../src/client.ts';
import {
  assertUnixSocketPath,
  maxUnixSocketPathBytes,
  SERVICE_PLATFORMS,
  servicePlatform,
  servicePlatformProblem,
  unixSocketPathProblem,
} from '../src/platform.ts';
import { startSignerServer } from '../src/server.ts';
import { tmpDir } from './helpers.ts';

function tooLong(name: string): { dir: string; path: string } {
  const dir = tmpDir();
  const max = maxUnixSocketPathBytes();
  const base = join(dir, 'run', name);
  const pad = 'p'.repeat(Math.max(1, max + 1 - Buffer.byteLength(base) - 1));
  const path = join(dir, pad, 'run', name);
  expect(Buffer.byteLength(path)).toBeGreaterThan(max);
  return { dir, path };
}

describe('unix socket path limits', () => {
  it('108 bytes on Linux (no NUL needed), 103 on macOS and the BSDs (104 with the NUL)', () => {
    expect(maxUnixSocketPathBytes('linux')).toBe(108);
    expect(maxUnixSocketPathBytes('darwin')).toBe(103);
    expect(maxUnixSocketPathBytes('freebsd')).toBe(103);
  });

  it('counts bytes, not characters, and names the limit and the platform', () => {
    expect(unixSocketPathProblem(`/${'a'.repeat(102)}`, 'x', 'darwin')).toBeNull();
    const msg = unixSocketPathProblem(`/${'a'.repeat(103)}`, 'intent socket', 'darwin');
    expect(msg).toMatch(/^intent socket: .* is 104 bytes, .*limited to 103 bytes on darwin/);
    expect(unixSocketPathProblem(`/${'é'.repeat(52)}`, 'x', 'darwin')).not.toBeNull();
    expect(unixSocketPathProblem(`/${'a'.repeat(107)}`, 'x', 'linux')).toBeNull();
    expect(unixSocketPathProblem(`/${'a'.repeat(108)}`, 'x', 'linux')).not.toBeNull();
    expect(() => assertUnixSocketPath(`/${'a'.repeat(200)}`, 'x')).toThrow(/limited to/);
  });

  it('the signer server refuses a too-long path before creating anything', async () => {
    const { dir, path } = tooLong('signer.sock');
    await expect(
      startSignerServer({
        socketPath: path,
        channelKey: randomBytes(32),
        handler: {} as never,
      }),
    ).rejects.toThrow(/signer socket: .*limited to/);
    expect(existsSync(join(dir, 'p'))).toBe(false);
  });

  it('spawnSigner refuses before spawning; the client refuses to connect', async () => {
    const { path } = tooLong('signer.sock');
    await expect(
      spawnSigner({
        socketPath: path,
        storePath: join(tmpDir(), 'keys'),
        passphrase: 'pw',
        trustedApproverKeys: {},
      }),
    ).rejects.toThrow(/signer socket: .*limited to/);
    expect(() => new SignerClient(path, randomBytes(32))).toThrow(/limited to/);
  });

  it('the admin socket refuses a too-long path, on both ends', async () => {
    const { path } = tooLong('admin.sock');
    await expect(startAdminServer({ listen: { path }, ops: new AdminOps() })).rejects.toThrow(
      /admin socket: .*limited to/,
    );
    const err = await adminCall(path, 'status').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AdminCallError);
    expect((err as AdminCallError).code).toBe('unreachable');
  });
});

describe('service mode runs on Linux (systemd) and macOS (launchd)', () => {
  it('names the service manager for each supported platform', () => {
    expect(servicePlatform('linux')).toBe('linux');
    expect(servicePlatform('darwin')).toBe('darwin');
    expect(SERVICE_PLATFORMS.linux.manager).toBe('systemd');
    expect(SERVICE_PLATFORMS.darwin.manager).toBe('launchd');
    expect(servicePlatformProblem('linux')).toBeNull();
    expect(servicePlatformProblem('darwin')).toBeNull();
  });

  it('refuses every other platform with a pointer to dev mode', () => {
    for (const p of ['freebsd', 'win32', 'sunos', 'hasOwnProperty', 'constructor']) {
      expect(servicePlatform(p)).toBeNull();
      expect(servicePlatformProblem(p)).toMatch(
        new RegExp(
          `needs Linux with systemd or macOS with launchd; .* ${p} .*keyflap daemon --unprotected`,
        ),
      );
    }
  });
});
