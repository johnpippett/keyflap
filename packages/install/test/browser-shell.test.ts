import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

const LINUX = join(import.meta.dirname, '..', 'linux');
const PINS = join(LINUX, 'runtime-pins.sh');
const BROWSER = join(LINUX, 'browser.sh');
const pins = readFileSync(PINS, 'utf8');
const CFT = /CHROME_FOR_TESTING_VERSION=(\S+)/.exec(pins)?.[1] as string;
const REVISION = /CHROMIUM_REVISION=(\S+)/.exec(pins)?.[1] as string;

let root = '';
let bin = '';
let browsers = '';
let log = '';

function fake(name: string, body: string) {
  writeFileSync(join(bin, name), `#!/bin/sh\n${body}\n`, { mode: 0o755 });
}

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'kf-cft-'));
  bin = join(root, 'bin');
  browsers = join(root, 'browsers');
  log = join(root, 'curl.log');
  mkdirSync(bin, { recursive: true });
  mkdirSync(browsers, { recursive: true });
  writeFileSync(log, '');
  cpSync(PINS, join(root, 'runtime-pins.sh'));
  cpSync(BROWSER, join(root, 'browser.sh'));
  chmodSync(join(root, 'browser.sh'), 0o644);
  fake(
    'curl',
    `out='' url=''
while [ $# -gt 0 ]; do
  case $1 in
    -o) out=$2; shift 2 ;;
    --proto) shift 2 ;;
    -fSL|-fsSL|--tlsv1.2) shift ;;
    -*) shift ;;
    *) url=$1; shift ;;
  esac
done
[ -n "$out" ] || exit 2
printf '%s\\n' "$url" >>"$FAKE_CURL_LOG"
printf '%s' "$url" >"$out"`,
  );
  fake(
    'unzip',
    `dir='' zip=''
while [ $# -gt 0 ]; do
  case $1 in
    -d) dir=$2; shift 2 ;;
    -q) shift ;;
    *) zip=$1; shift ;;
  esac
done
[ -n "$dir" ] && [ -n "$zip" ] || exit 2
inner=$(basename "$zip" .zip)
case $inner in
  chrome-headless-shell-*) exe=chrome-headless-shell ;;
  chrome-mac-*) exe='Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing' ;;
  *) exe=chrome ;;
esac
mkdir -p "$dir/$inner/$(dirname "$exe")"
printf '#!/bin/sh\\necho "Google Chrome for Testing %s"\\n' "$FAKE_CFT_VERSION" >"$dir/$inner/$exe"
chmod 0755 "$dir/$inner/$exe"`,
  );
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

function run(code: string, env: Record<string, string> = {}) {
  const r = spawnSync(
    'bash',
    [
      '-c',
      `set -euo pipefail
source "${join(root, 'runtime-pins.sh')}"
source "${join(root, 'browser.sh')}"
${code}`,
    ],
    {
      env: {
        PATH: `${bin}:/usr/bin:/bin`,
        FAKE_CURL_LOG: log,
        FAKE_CFT_VERSION: CFT,
        ...env,
      },
      encoding: 'utf8',
    },
  );
  return { code: r.status, out: r.stdout + r.stderr };
}

const versions = (file: string) => readFileSync(file, 'utf8').split('\n').filter(Boolean);

describe('browser.sh names the Chrome for Testing build for each platform', () => {
  it.each([
    ['linux', 'x64', 'linux64'],
    ['linux', 'x86_64', 'linux64'],
    ['linux', 'arm64', 'linux-arm64'],
    ['linux', 'aarch64', 'linux-arm64'],
    ['darwin', 'arm64', 'mac-arm64'],
    ['darwin', 'x64', 'mac-x64'],
    ['Darwin', 'ARM64', 'mac-arm64'],
  ])('cft_platform %s %s -> %s', (os, arch, platform) => {
    expect(run(`cft_platform ${os} ${arch}`).out).toBe(`${platform}\n`);
  });

  it('cft_platform fails for a platform with no Chrome for Testing build', () => {
    for (const os of ['freebsd', 'plan9']) {
      const r = run(`cft_platform ${os} x64 || echo unsupported`);
      expect(r.out, os).toBe('unsupported\n');
    }
  });

  it.each([
    ['linux64', 'full', 'chrome-linux64.zip', 'chrome-linux64', 'chrome'],
    [
      'linux64',
      'shell',
      'chrome-headless-shell-linux64.zip',
      'chrome-headless-shell-linux64',
      'chrome-headless-shell',
    ],
    ['linux-arm64', 'full', 'chrome-linux-arm64.zip', 'chrome-linux-arm64', 'chrome'],
    [
      'linux-arm64',
      'shell',
      'chrome-headless-shell-linux-arm64.zip',
      'chrome-headless-shell-linux-arm64',
      'chrome-headless-shell',
    ],
    [
      'mac-arm64',
      'full',
      'chrome-mac-arm64.zip',
      'chrome-mac-arm64',
      'Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing',
    ],
    [
      'mac-arm64',
      'shell',
      'chrome-headless-shell-mac-arm64.zip',
      'chrome-headless-shell-mac-arm64',
      'chrome-headless-shell',
    ],
    [
      'mac-x64',
      'full',
      'chrome-mac-x64.zip',
      'chrome-mac-x64',
      'Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing',
    ],
    [
      'mac-x64',
      'shell',
      'chrome-headless-shell-mac-x64.zip',
      'chrome-headless-shell-mac-x64',
      'chrome-headless-shell',
    ],
  ])('%s %s: asset, inner directory and executable', (platform, kind, asset, inner, exe) => {
    const r = run(
      `printf '%s\\n' "$(cft_asset ${platform} ${kind})" "$(cft_inner ${platform} ${kind})" "$(cft_exe ${platform} ${kind} /x/${inner})"`,
    );
    expect(r.out).toBe(`${asset}\n${inner}\n/x/${inner}/${exe}\n`);
  });
});

describe('browser.sh refreshes exactly the browser Playwright cannot', () => {
  const marker = () => join(browsers, '.chrome-for-testing-version');
  const full = () => join(browsers, `chromium-${REVISION}`, 'chrome-linux64');
  const shell = () =>
    join(browsers, `chromium_headless_shell-${REVISION}`, 'chrome-headless-shell-linux64');

  it('is not current without a marker, so an older install refreshes', () => {
    mkdirSync(full(), { recursive: true });
    mkdirSync(shell(), { recursive: true });
    const r = run(`browser_is_current ${browsers} both && echo yes || echo no`);
    expect(r.out).toBe('no\n');
  });

  it('is not current with the marker of another version', () => {
    writeFileSync(marker(), '156.0.8078.4\n');
    mkdirSync(full(), { recursive: true });
    mkdirSync(shell(), { recursive: true });
    const r = run(`browser_is_current ${browsers} both && echo yes || echo no`);
    expect(r.out).toBe('no\n');
  });

  it('is not current when the marker is right but a directory is missing', () => {
    writeFileSync(marker(), `${CFT}\n`);
    mkdirSync(full(), { recursive: true });
    expect(run(`browser_is_current ${browsers} both && echo yes || echo no`).out).toBe('no\n');
    expect(run(`browser_is_current ${browsers} full && echo yes || echo no`).out).toBe('yes\n');
  });

  it('becomes current after installing both, replacing what Playwright left behind', () => {
    mkdirSync(full(), { recursive: true });
    mkdirSync(shell(), { recursive: true });
    writeFileSync(join(full(), 'stale'), '');
    const r = run(`install_chrome_for_testing ${browsers} linux x64 both`);
    expect(r.code, r.out).toBe(0);
    expect(existsSync(join(full(), 'stale'))).toBe(false);
    expect(existsSync(join(full(), 'chrome'))).toBe(true);
    expect(existsSync(join(shell(), 'chrome-headless-shell'))).toBe(true);
    expect(readFileSync(marker(), 'utf8')).toBe(`${CFT}\n`);
    for (const dir of [`chromium-${REVISION}`, `chromium_headless_shell-${REVISION}`]) {
      expect(existsSync(join(browsers, dir, 'INSTALLATION_COMPLETE'))).toBe(true);
      expect(existsSync(join(browsers, dir, 'DEPENDENCIES_VALIDATED'))).toBe(true);
    }
    expect(run(`browser_is_current ${browsers} both && echo yes || echo no`).out).toBe('yes\n');
    expect(versions(log)).toEqual([
      `https://storage.googleapis.com/chrome-for-testing-public/${CFT}/linux64/chrome-linux64.zip`,
      `https://storage.googleapis.com/chrome-for-testing-public/${CFT}/linux64/chrome-headless-shell-linux64.zip`,
    ]);
  });

  it('installs only the shell for the simple Mac install', () => {
    const r = run(`install_chrome_for_testing ${browsers} darwin arm64 shell`);
    expect(r.code, r.out).toBe(0);
    expect(
      existsSync(
        join(browsers, `chromium_headless_shell-${REVISION}`, 'chrome-headless-shell-mac-arm64'),
      ),
    ).toBe(true);
    expect(existsSync(join(browsers, `chromium-${REVISION}`))).toBe(false);
    expect(versions(log)).toEqual([
      `https://storage.googleapis.com/chrome-for-testing-public/${CFT}/mac-arm64/chrome-headless-shell-mac-arm64.zip`,
    ]);
  });

  it('refuses a build whose --version is not the pin', () => {
    const r = run(`install_chrome_for_testing ${browsers} linux x64 full`, {
      FAKE_CFT_VERSION: '156.0.8078.4',
    });
    expect(r.code).toBe(1);
    expect(r.out).toContain(`is not ${CFT}`);
    expect(existsSync(marker())).toBe(false);
  });
});
