import { existsSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { maxUnixSocketPathBytes } from '@aab/signer/platform';
import { describe, expect, it } from 'vitest';
import { runCli, tmpDir } from './helpers.ts';

describe('keyflap daemon: socket path length', () => {
  it('refuses a data dir whose sockets would not fit, without prompting', async () => {
    const base = tmpDir();
    const dir = join(base, 'd'.repeat(Math.max(1, maxUnixSocketPathBytes() - base.length)));
    try {
      const r = await runCli(['daemon', '--unprotected', '--data-dir', dir], {
        env: { KEYFLAP_PASSPHRASE: undefined },
      });
      expect(r.code).toBe(1);
      expect(r.stderr).toMatch(/keyflap: intent socket: .*limited to \d+ bytes on \w+/);
      expect(r.stderr).not.toMatch(/passphrase/i);
      expect(existsSync(dir)).toBe(false);
    } finally {
      rmSync(base, { recursive: true, force: true });
    }
  });
});
