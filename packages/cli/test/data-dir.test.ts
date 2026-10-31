import { existsSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { defaultDataDir, legacyDataDirNotice } from '../src/data-dir.ts';
import { runCli, tmpDir } from './helpers.ts';

describe('data dir default and the pre-rename ~/.aab fallback', () => {
  const homes: string[] = [];
  const home = (...dirs: string[]) => {
    const h = tmpDir();
    homes.push(h);
    for (const d of dirs) mkdirSync(join(h, d));
    return h;
  };
  afterEach(() => {
    for (const h of homes.splice(0)) rmSync(h, { recursive: true, force: true });
  });

  it('prefers ~/.keyflap; uses ~/.aab only when it is the only one', () => {
    expect(defaultDataDir(home())).toMatch(/\/\.keyflap$/);
    expect(defaultDataDir(home('.keyflap'))).toMatch(/\/\.keyflap$/);
    expect(defaultDataDir(home('.keyflap', '.aab'))).toMatch(/\/\.keyflap$/);
    expect(defaultDataDir(home('.aab'))).toMatch(/\/\.aab$/);
  });

  it('notice only for the legacy dir', () => {
    const h = home();
    expect(legacyDataDirNotice(join(h, '.keyflap'), h)).toBeNull();
    expect(legacyDataDirNotice('/elsewhere/.aab', h)).toBeNull();
    expect(legacyDataDirNotice(join(h, '.aab'), h)).toContain('mv ~/.aab ~/.keyflap');
  });

  it('the CLI uses ~/.aab and says once on stderr how to move it', async () => {
    const h = home('.aab');
    const env = { HOME: h, KEYFLAP_MODE: undefined };
    const r = await runCli(['agent', 'list'], { env });
    expect(r.code).toBe(0);
    expect(r.stdout).not.toContain('.aab');
    expect(r.stderr.match(/mv ~\/\.aab ~\/\.keyflap/g)).toHaveLength(1);
    expect(existsSync(join(h, '.aab', 'broker.sqlite'))).toBe(true);
    expect(existsSync(join(h, '.keyflap'))).toBe(false);

    const e = await runCli(['agent', 'list', '--data-dir', join(h, '.aab')], { env });
    expect(e.code).toBe(0);
    expect(e.stderr).not.toContain('mv ~/.aab');

    const both = home('.aab', '.keyflap');
    const n = await runCli(['agent', 'list'], { env: { HOME: both, KEYFLAP_MODE: undefined } });
    expect(n.code).toBe(0);
    expect(n.stderr).not.toContain('.aab');
    expect(existsSync(join(both, '.keyflap', 'broker.sqlite'))).toBe(true);
  });

  it('the hook stays silent about it (nothing on stdout, no notice)', async () => {
    const h = home('.aab');
    const r = await runCli(['hook', 'claude-code', '--agent', 'some-agent'], {
      input: JSON.stringify({ prompt: 'hi', session_id: 's', hook_event_name: 'UserPromptSubmit' }),
      env: { HOME: h, KEYFLAP_MODE: undefined },
    });
    expect(r.code).toBe(0);
    expect(r.stdout).toBe('');
    expect(r.stderr).not.toContain('mv ~/.aab');
  });
});

describe('KEYFLAP_PASSPHRASE, with AAB_PASSPHRASE as a deprecated fallback', () => {
  it('accepts AAB_PASSPHRASE with a note on stderr, and prefers KEYFLAP_PASSPHRASE', async () => {
    const dir = tmpDir();
    try {
      const legacy = await runCli(['approver', 'list', '--data-dir', dir], {
        env: { KEYFLAP_PASSPHRASE: undefined, AAB_PASSPHRASE: 'old-name-passphrase' },
      });
      expect(legacy.code).toBe(0);
      expect(legacy.stderr).toContain('AAB_PASSPHRASE is deprecated; set KEYFLAP_PASSPHRASE');
      expect(legacy.stderr).not.toContain('old-name-passphrase');

      const both = await runCli(['approver', 'list', '--data-dir', dir], {
        env: { KEYFLAP_PASSPHRASE: 'old-name-passphrase', AAB_PASSPHRASE: 'wrong' },
      });
      expect(both.code).toBe(0);
      expect(both.stderr).not.toContain('deprecated');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
