import {
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  renameSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { saveState } from '../src/setup/state.ts';
import { applyPlan, planClaudeConfig } from '../src/setup/steps.ts';
import { realSystem, type System } from '../src/setup/system.ts';
import {
  asOwner,
  checkUserPath,
  readUserFile,
  UnsafePathError,
  writeUserFile,
} from '../src/setup/user-files.ts';

const me = { uid: process.geteuid?.() ?? 0, gid: process.getegid?.() ?? 0 };
const SECRET = 'SECRET-MARKER';

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'inv1-setup-'));
  const secretDir = join(root, 'root-only');
  mkdirSync(secretDir);
  const secret = join(secretDir, 'keys.enc.json');
  writeFileSync(secret, JSON.stringify({ ciphertext: SECRET }), { mode: 0o600 });
  const home = join(root, 'home');
  mkdirSync(join(home, '.claude'), { recursive: true });
  return { root, secret, secretDir, home };
}

function plan(sys: System, home: string) {
  return planClaudeConfig({
    sys,
    scope: 'user',
    project: home,
    home,
    cfg: {
      mcpUrl: 'http://127.0.0.1:8765/mcp',
      headersCommand: 'h',
      hookCommand: 'keyflap hook claude-code --agent x',
      denyDir: '/var/lib/keyflap/hook',
      home,
    },
    claudeCli: null,
    cliHasEntry: false,
    owner: me,
  });
}

function leaks(dir: string): string[] {
  return readdirSync(dir).filter((f) => {
    const p = join(dir, f);
    return lstatSync(p).isFile() && readFileSync(p, 'utf8').includes(SECRET);
  });
}

describe('invariant 1 (service mode): keyflap setup never follows a planted link', () => {
  it('refuses a symlinked ~/.claude/settings.json: nothing is read, copied or backed up', async () => {
    const f = fixture();
    symlinkSync(f.secret, join(f.home, '.claude', 'settings.json'));
    expect(() => plan(realSystem(), f.home)).toThrow(/symbolic link/);
    expect(leaks(join(f.home, '.claude'))).toEqual([]);
    expect(leaks(f.home)).toEqual([]);
  });

  it('refuses a symlinked directory on the way (~/.claude -> elsewhere)', () => {
    const f = fixture();
    const home2 = join(f.root, 'home2');
    mkdirSync(home2);
    symlinkSync(f.secretDir, join(home2, '.claude'));
    writeFileSync(join(f.secretDir, 'settings.json'), JSON.stringify({ x: SECRET }));
    expect(() => plan(realSystem(), home2)).toThrow(/symbolic link in a directory you can change/);
  });

  it('a link swapped in after the preview is refused at apply time; the target is untouched', async () => {
    const f = fixture();
    const settings = join(f.home, '.claude', 'settings.json');
    writeFileSync(settings, '{}\n');
    const actions = plan(realSystem(), f.home);
    const tmp = join(f.home, '.claude', '.swap');
    symlinkSync(f.secret, tmp);
    renameSync(tmp, settings);
    const out: string[] = [];
    const ok = await applyPlan(realSystem(), actions, {
      stamp: 'S',
      owner: me,
      out: (t) => out.push(t),
    });
    expect(ok).toBe(false);
    expect(out.join('')).toMatch(/settings\.json not written: .*symbolic link/);
    expect(readFileSync(f.secret, 'utf8')).toContain(SECRET);
    expect(JSON.parse(readFileSync(f.secret, 'utf8'))).toEqual({ ciphertext: SECRET });
    expect(leaks(join(f.home, '.claude'))).toEqual([]);
    expect(lstatSync(settings).isSymbolicLink()).toBe(true);
  });

  it('the backup is the previewed text in a new file, never a copy of a path', async () => {
    const f = fixture();
    const settings = join(f.home, '.claude', 'settings.json');
    writeFileSync(settings, '{"a": 1}\n', { mode: 0o640 });
    const actions = plan(realSystem(), f.home);
    symlinkSync(f.secret, `${settings}.keyflap-backup-S`);
    const out: string[] = [];
    const ok = await applyPlan(realSystem(), actions, {
      stamp: 'S',
      owner: me,
      out: (t) => out.push(t),
    });
    expect(ok).toBe(false);
    expect(JSON.parse(readFileSync(f.secret, 'utf8'))).toEqual({ ciphertext: SECRET });
    expect(readFileSync(settings, 'utf8')).toBe('{"a": 1}\n');
  });

  it('applies normally: backup, then the new file, both regular files with the old mode', async () => {
    const f = fixture();
    const settings = join(f.home, '.claude', 'settings.json');
    writeFileSync(settings, '{"a": 1}\n', { mode: 0o640 });
    const actions = plan(realSystem(), f.home);
    const ok = await applyPlan(realSystem(), actions, { stamp: 'S', owner: me, out: () => {} });
    expect(ok).toBe(true);
    expect(readFileSync(`${settings}.keyflap-backup-S`, 'utf8')).toBe('{"a": 1}\n');
    expect(lstatSync(settings).mode & 0o777).toBe(0o640);
    expect(JSON.parse(readFileSync(settings, 'utf8')).a).toBe(1);
    expect(readdirSync(join(f.home, '.claude')).filter((n) => n.includes('keyflap-tmp'))).toEqual(
      [],
    );
  });
});

describe('invariant 1 (service mode): the hook dir is written as its owner, never chowned', () => {
  it('saveState never chowns, and refuses a link planted at setup.json (a03b)', () => {
    const f = fixture();
    const hookDir = join(f.root, 'hook');
    mkdirSync(hookDir);
    const real = realSystem();
    const sys = {
      ...real,
      chown() {
        throw new Error('chown called');
      },
    } as System;
    saveState(sys, hookDir, { version: 1 } as never, me);
    expect(JSON.parse(readFileSync(join(hookDir, 'setup.json'), 'utf8'))).toEqual({ version: 1 });
    const victim = join(f.root, 'victim');
    writeFileSync(victim, 'x');
    const tmp = join(hookDir, '.x');
    symlinkSync(victim, tmp);
    renameSync(tmp, join(hookDir, 'setup.json'));
    expect(() => saveState(sys, hookDir, { version: 1 } as never, me)).toThrow(UnsafePathError);
    expect(readFileSync(victim, 'utf8')).toBe('x');
  });

  it('a file owned by someone else is refused (checked on the opened fd)', () => {
    if (me.uid === 0) return;
    const target = '/etc/passwd';
    expect(() => readUserFile(target, me)).toThrow(/owned by uid 0/);
    expect(() => writeUserFile(target, 'x', 0o644, me)).toThrow();
  });
});

describe('user-files: links and credentials', () => {
  it('follows links only through root-only directories (e.g. /bin -> usr/bin)', () => {
    let binIsLink = false;
    try {
      binIsLink = lstatSync('/bin').isSymbolicLink() && lstatSync('/usr/bin/env').isFile();
    } catch {
      binIsLink = false;
    }
    if (!binIsLink) return;
    expect(() => checkUserPath('/bin/env')).not.toThrow();
  });

  it('refuses paths with .. or a trailing slash', () => {
    expect(() => checkUserPath('/home/../etc/passwd')).toThrow(UnsafePathError);
    expect(() => checkUserPath('/tmp/')).toThrow(UnsafePathError);
    expect(() => checkUserPath('relative')).toThrow(UnsafePathError);
  });

  it('cannot act for another uid without root', () => {
    if (me.uid === 0) return;
    expect(() => asOwner({ uid: me.uid + 1, gid: me.gid }, () => 1)).toThrow(UnsafePathError);
    expect(asOwner(me, () => 2)).toBe(2);
  });
});
