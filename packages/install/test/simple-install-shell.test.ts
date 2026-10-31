import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

const MACOS = join(import.meta.dirname, '..', 'macos');
const LINUX = join(import.meta.dirname, '..', 'linux');
const CAN_BE_ROOT = spawnSync('unshare', ['-r', 'true']).status === 0;
const FULL = '| sudo bash';

let root = '';
let home = '';
let release = '';
let fakes = '';

function fake(name: string, body: string) {
  writeFileSync(join(fakes, name), `#!/bin/sh\n${body}\n`, { mode: 0o755 });
}

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'kf-simple-sh-'));
  home = join(root, 'home');
  release = join(root, 'keyflap-1.0.0-darwin-arm64');
  fakes = join(root, 'bin');
  for (const d of [home, release, fakes]) mkdirSync(d, { recursive: true });
  for (const f of ['install-simple.sh', 'uninstall-simple.sh']) {
    writeFileSync(join(release, f), spawnSync('cat', [join(MACOS, f)]).stdout, { mode: 0o755 });
  }
  writeFileSync(
    join(release, 'runtime-pins.sh'),
    spawnSync('cat', [join(LINUX, 'runtime-pins.sh')]).stdout,
  );
  writeFileSync(join(release, 'RELEASE'), 'name=keyflap\nversion=1.0.0\nos=darwin\narch=arm64\n');
  mkdirSync(join(release, 'bundle', 'app', 'packages', 'cli', 'src'), { recursive: true });
  writeFileSync(join(release, 'bundle', '.keyflap-bundle'), '');
  writeFileSync(join(release, 'bundle', 'app', 'packages', 'cli', 'src', 'main.ts'), '');
  fake(
    'uname',
    'case $1 in -s) echo "${FAKE_UNAME_S:-Darwin}" ;; -m) echo "${FAKE_UNAME_M:-arm64}" ;; esac',
  );
  fake('sw_vers', 'echo "${FAKE_MACOS:-26.0}"');
  for (const t of ['launchctl', 'plutil', 'xattr', 'fdesetup']) fake(t, 'exit 1');
  fake('shasum', 'exec sha256sum "$3"');
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

function run(
  script: string,
  args: string[] = [],
  env: Record<string, string> = {},
  asRoot = false,
) {
  const argv = ['bash', join(release, script), ...args];
  const r = spawnSync(
    asRoot ? 'unshare' : (argv[0] as string),
    asRoot ? ['-r', ...argv] : argv.slice(1),
    {
      env: { PATH: `${fakes}:/usr/bin:/bin`, HOME: home, ...env },
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    },
  );
  return { code: r.status, out: r.stdout + r.stderr };
}

describe('install-simple.sh refuses before it changes anything', () => {
  it.runIf(CAN_BE_ROOT)('under sudo, naming the full install', () => {
    const r = run('install-simple.sh', ['--confirmed'], {}, true);
    expect(r.code).toBe(1);
    expect(r.out).toContain(
      'the simple install runs as you, without sudo: run it again without sudo.',
    );
    expect(r.out).toContain(FULL);
  });

  it.each([
    [{ FAKE_UNAME_S: 'Linux' }, 'the simple install is for macOS; on Linux use the full install'],
    [{ FAKE_UNAME_M: 'x86_64' }, 'Intel Macs are not supported yet'],
    [{ FAKE_MACOS: '13.6' }, 'macOS 13.6 is too old'],
  ])('on %j', (env, why) => {
    const r = run('install-simple.sh', ['--confirmed'], env);
    expect(r.code).toBe(1);
    expect(r.out).toContain(why);
    expect(readdirSync(home)).toEqual([]);
  });

  it('over a key store a passphrase unlocks, saying how to move it away', () => {
    mkdirSync(join(home, '.keyflap', 'signer'), { recursive: true });
    writeFileSync(join(home, '.keyflap', 'signer', 'keys.enc.json'), '{}');
    const r = run('install-simple.sh', ['--confirmed']);
    expect(r.code).toBe(1);
    expect(r.out).toContain('a key store that a passphrase unlocks');
    expect(r.out).toContain('mv ~/.keyflap ~/.keyflap.dev');
    expect(readdirSync(home)).toEqual(['.keyflap']);
  });

  it('for another platform release, or without a bundle', () => {
    writeFileSync(join(release, 'RELEASE'), 'version=1.0.0\nos=linux\narch=x64\n');
    rmSync(join(release, 'bundle'), { recursive: true });
    const r = run('install-simple.sh', ['--confirmed']);
    expect(r.code).toBe(1);
    expect(r.out).toContain('download keyflap-1.0.0-darwin-arm64.tar.xz');
    expect(r.out).toContain('no bundle');
    expect(readdirSync(home)).toEqual([]);
  });

  it('without --confirmed and no terminal to ask on', () => {
    const r = spawnSync('bash', [join(release, 'install-simple.sh')], {
      env: { PATH: `${fakes}:/usr/bin:/bin`, HOME: home },
      encoding: 'utf8',
      detached: true,
    } as Parameters<typeof spawnSync>[2] & { detached: boolean });
    expect(r.status).toBe(1);
    expect(`${r.stdout}${r.stderr}`).toContain('it needs a terminal to ask you first');
    expect(readdirSync(home)).toEqual([]);
  });
});

describe('uninstall-simple.sh', () => {
  function installed() {
    const app = join(home, 'Library', 'Application Support', 'Keyflap');
    mkdirSync(join(app, 'bin'), { recursive: true });
    mkdirSync(join(home, 'Library', 'LaunchAgents'), { recursive: true });
    mkdirSync(join(home, 'Library', 'Logs', 'Keyflap'), { recursive: true });
    writeFileSync(join(home, 'Library', 'LaunchAgents', 'com.keyflap.simple.plist'), '');
    writeFileSync(join(home, 'Library', 'Logs', 'Keyflap', 'daemon.log'), '');
    mkdirSync(join(home, '.keyflap'), { recursive: true });
    writeFileSync(join(home, '.keyflap', 'unlock.key'), '');
    return app;
  }

  it('removes the code, the LaunchAgent and the log, and keeps the data', () => {
    const app = installed();
    const r = run('uninstall-simple.sh');
    expect(r.code, r.out).toBe(0);
    expect(existsSync(app)).toBe(false);
    expect(readdirSync(join(home, 'Library', 'LaunchAgents'))).toEqual([]);
    expect(readdirSync(join(home, 'Library', 'Logs'))).toEqual([]);
    expect(existsSync(join(home, '.keyflap', 'unlock.key'))).toBe(true);
    expect(r.out).toContain('Kept');
  });

  it('--purge deletes the data too', () => {
    installed();
    expect(run('uninstall-simple.sh', ['--purge']).code).toBe(0);
    expect(readdirSync(home)).toEqual(['Library']);
    expect(readdirSync(join(home, 'Library', 'Application Support'))).toEqual([]);
  });

  it.runIf(CAN_BE_ROOT)('refuses sudo: the install belongs to your account', () => {
    const app = installed();
    const r = run('uninstall-simple.sh', [], {}, true);
    expect(r.code).toBe(1);
    expect(r.out).toContain('run it without sudo');
    expect(existsSync(app)).toBe(true);
  });
});
