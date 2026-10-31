import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

const MACOS = join(import.meta.dirname, '..', 'macos');
const LINUX = join(import.meta.dirname, '..', 'linux');
const SCRIPTS = ['install.sh', 'uninstall.sh', 'install-simple.sh', 'uninstall-simple.sh'].map(
  (f) => join(MACOS, f),
);
const SOURCED = [join(LINUX, 'runtime-pins.sh'), join(LINUX, 'progress.sh')];

const code = (text: string) =>
  text
    .split('\n')
    .filter((l) => !/^\s*#/.test(l))
    .join('\n');

const BASH4_ONLY: [string, RegExp][] = [
  ['declare -A (associative arrays)', /declare -A/],
  ['associative-array key expansion', /\$\{![a-z_]+\[@\]\}/],
  ['mapfile/readarray', /\b(mapfile|readarray)\b/],
  ['[[ -v', /\[\[ -v /],
  ['|& pipe', /\|&/],
  [';;& / ;& case fallthrough', /;;&|;&(?!&)/],
  ['&>> redirect', /&>>/],
  ['local -n (namerefs)', /local -n /],
  ['case-changing expansions', /\$\{[a-z_]+(,,|\^\^)\}/],
  ['arr+=(…) (empty arrays break set -u in bash 3.2; index assignment is used instead)', /\+=\(/],
];

const GNU_ONLY: [string, RegExp][] = [
  ['stat -c (BSD stat is -f)', /\bstat -c\b/],
  ['sha256sum (shasum -a 256 on macOS)', /\bsha256sum\b/],
  ['runuser (sudo -u on macOS)', /\brunuser\b/],
  ['cp --no-preserve', /--no-preserve/],
  ['install -D', /\binstall -D\b/],
  ['find -perm /mode', /-perm \//],
  ['chown root:root (gid 0 is wheel on macOS)', /root:root/],
  ['systemd', /systemd|systemctl/],
];

describe('the macOS installer scripts stay inside bash 3.2 and BSD userland', () => {
  for (const script of [...SCRIPTS, ...SOURCED]) {
    const name = script.split('/').slice(-2).join('/');
    const text = code(readFileSync(script, 'utf8'));

    it(`${name} parses`, () => {
      execFileSync('bash', ['-n', script], { stdio: 'pipe' });
    });

    it(`${name} uses no bash 4 construct`, () => {
      for (const [what, re] of BASH4_ONLY) expect(text, what).not.toMatch(re);
    });

    it(`${name} uses no GNU-only command`, () => {
      for (const [what, re] of GNU_ONLY) expect(text, what).not.toMatch(re);
    });
  }

  it('the macOS scripts take their pins from the shared runtime-pins.sh, by function', () => {
    const install = readFileSync(SCRIPTS[0] as string, 'utf8');
    expect(install).toContain('pins=$here/runtime-pins.sh');
    expect(install).toContain('pins=$here/../linux/runtime-pins.sh');
    expect(install).toContain('source "$pins"');
    expect(install).toContain('node_sha256 darwin arm64');
    expect(install).not.toMatch(/NODE_SHA256\[/);
  });

  it('the wrapper is POSIX sh and passes only what the CLI needs', () => {
    const wrapper = join(MACOS, 'keyflap-wrapper.sh');
    execFileSync('sh', ['-n', wrapper], { stdio: 'pipe' });
    const text = readFileSync(wrapper, 'utf8');
    expect(text).toMatch(/^#!\/bin\/sh$/m);
    const passed = [...text.matchAll(/\b([A-Z_]+)=/g)].map((m) => m[1]);
    expect(new Set(passed)).toEqual(
      new Set(['KEYFLAP_MODE', 'PATH', 'SUDO_UID', 'SUDO_GID', 'SUDO_USER', 'TERM', 'LANG']),
    );
  });

  it('the plists are the templates install.sh fills in, and each placeholder has a sed line', () => {
    const install = readFileSync(SCRIPTS[0] as string, 'utf8');
    for (const f of ['com.keyflap.signer', 'com.keyflap.core', 'com.keyflap.approver']) {
      const xml = readFileSync(join(MACOS, 'launchd', `${f}.plist`), 'utf8');
      for (const m of xml.matchAll(/@([A-Z_]+)@/g)) {
        expect(install, `${f}: ${m[0]}`).toContain(`s|${m[0]}|`);
      }
    }
  });
});
