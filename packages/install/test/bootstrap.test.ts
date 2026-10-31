import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { render } from './screen.ts';

const BOOTSTRAP = join(import.meta.dirname, '..', 'bootstrap');
const MAKE = join(BOOTSTRAP, 'make-bootstrap.sh');
const PROGRESS = join(BOOTSTRAP, '..', 'linux', 'progress.sh');
const TEMPLATE = join(BOOTSTRAP, 'install-keyflap.sh.in');
const VERSION = '0.9.1';
const KEYS = ['linux-x64', 'linux-arm64', 'darwin-arm64'] as const;
type Key = (typeof KEYS)[number];

const sha256 = (b: Buffer | string) => createHash('sha256').update(b).digest('hex');
const SIMPLE_COMMAND =
  'curl -fsSL https://github.com/johnpippett/keyflap/releases/latest/download/install-keyflap.sh | bash -s -- --simple';
const CAN_BE_ROOT = spawnSync('unshare', ['-r', 'true']).status === 0;
const HAS_PTY = process.platform === 'linux' && spawnSync('script', ['--version']).status === 0;
const q = (a: string) => `'${a.replaceAll("'", `'\\''`)}'`;

interface Release {
  dir: string;
  marker: string;
}

function fakeRelease(root: string, keys: readonly Key[], version = VERSION): Release {
  const dir = join(root, `dist-${keys.join('_')}-${version}`);
  const src = join(root, `src-${keys.join('_')}-${version}`);
  const marker = join(root, `installed-${keys.join('_')}`);
  mkdirSync(dir, { recursive: true });
  const sums: string[] = [];
  for (const k of keys) {
    const name = `keyflap-${version}-${k}`;
    mkdirSync(join(src, name), { recursive: true });
    writeFileSync(join(src, name, 'install.sh'), `#!/bin/sh\ntouch '${marker}'\n`, { mode: 0o755 });
    if (k.startsWith('darwin')) {
      writeFileSync(join(src, name, 'install-simple.sh'), `#!/bin/sh\ntouch '${marker}'\n`, {
        mode: 0o755,
      });
    }
    const r = spawnSync('tar', ['-cJf', join(dir, `${name}.tar.xz`), '-C', src, name]);
    expect(r.status, r.stderr.toString()).toBe(0);
    sums.push(`${sha256(readFileSync(join(dir, `${name}.tar.xz`)))}  ${name}.tar.xz`);
  }
  writeFileSync(join(dir, 'SHA256SUMS'), `${sums.join('\n')}\n`);
  return { dir, marker };
}

function make(dir: string, version = VERSION) {
  const r = spawnSync('bash', [MAKE, dir, version], { encoding: 'utf8' });
  return { code: r.status, out: r.stdout + r.stderr };
}

interface Served {
  base: string;
  requests: string[];
  tamper: Set<string>;
}

let root = '';
let server: Server;
let served: Served;
let fakeBin = '';
let release: Release;

function serve(dir: string): Promise<Served> {
  const s: Served = { base: '', requests: [], tamper: new Set() };
  server = createServer((req, res) => {
    const path = decodeURIComponent(new URL(req.url ?? '/', 'http://x').pathname);
    s.requests.push(path);
    const m = path.match(/^\/v([^/]+)\/([^/]+)$/);
    const file = m ? join(dir, m[2] as string) : '';
    if (!m || m[1] !== VERSION || !existsSync(file)) {
      res.writeHead(404).end();
      return;
    }
    const body = readFileSync(file);
    if (s.tamper.has(m[2] as string)) body.writeUInt8((body.at(-1) ?? 0) ^ 0xff, body.length - 1);
    res.writeHead(200, { 'content-length': body.length }).end(body);
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      s.base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
      resolve(s);
    });
  });
}

const TAILSCALE_OK = JSON.stringify(
  {
    BackendState: 'Running',
    Self: { HostName: 'laptop', DNSName: 'laptop.tail1234.ts.net.' },
    CurrentTailnet: { MagicDNSSuffix: 'tail1234.ts.net', MagicDNSEnabled: true },
    CertDomains: ['laptop.tail1234.ts.net'],
    Peer: null,
  },
  null,
  2,
);

function writeFakes(dir: string) {
  mkdirSync(dir, { recursive: true, mode: 0o755 });
  const script = (name: string, body: string) =>
    writeFileSync(join(dir, name), `#!/bin/sh\n${body}\n`, { mode: 0o755 });
  script(
    'uname',
    'case $1 in -s) echo "$FAKE_UNAME_S" ;; -m) echo "$FAKE_UNAME_M" ;; *) exec /usr/bin/uname "$@" ;; esac',
  );
  script('sysctl', 'if [ -n "$FAKE_ARM64" ]; then echo "$FAKE_ARM64"; else echo 0; fi');
  script(
    'tailscale',
    '[ "$1 $2 $3" = "status --json --peers=false" ] || exit 2\ncat "$FAKE_TAILSCALE_JSON"',
  );
  const hostXz = spawnSync('sh', ['-c', 'command -v xz'], { encoding: 'utf8' }).stdout.trim();
  script(
    'xz',
    hostXz
      ? `exec ${q(hostXz)} "$@"`
      : 'echo "fake xz: this host has no xz, so tar must unpack .xz itself" >&2\nexit 1',
  );
  writeFileSync(join(dir, 'tailscale.json'), TAILSCALE_OK);
}

interface Run {
  code: number | null;
  out: string;
  requests: string[];
  leftovers: string[];
}

function run(
  bootstrap: string,
  o: {
    s?: string;
    m?: string;
    arm64?: string;
    args?: string[];
    base?: string;
    tailscaleJson?: string;
    viaPipe?: boolean;
    script?: string;
    asRoot?: boolean;
    noTty?: boolean;
    pty?: boolean;
    env?: NodeJS.ProcessEnv;
  } = {},
): Promise<Run> {
  const tmp = mkdtempSync(join(root, 'run-'));
  const before = served.requests.length;
  const env: NodeJS.ProcessEnv = {
    PATH: `${fakeBin}:/usr/bin:/bin:/usr/sbin:/sbin`,
    HOME: tmp,
    TMPDIR: tmp,
    FAKE_UNAME_S: o.s ?? 'Linux',
    FAKE_UNAME_M: o.m ?? 'x86_64',
    FAKE_ARM64: o.arm64 ?? '0',
    FAKE_TAILSCALE_JSON: o.tailscaleJson ?? join(fakeBin, 'tailscale.json'),
    KEYFLAP_RELEASE_BASE: o.base ?? served.base,
    TERM: 'xterm-256color',
    ...o.env,
  };
  const args = o.viaPipe
    ? ['-s', '--', ...(o.args ?? ['--dry-run'])]
    : [bootstrap, ...(o.args ?? ['--dry-run'])];
  return new Promise((resolve) => {
    const p = o.pty
      ? spawn('script', ['-qfec', ['bash', ...args].map(q).join(' '), '/dev/null'], {
          env,
          stdio: ['pipe', 'pipe', 'pipe'],
        })
      : o.asRoot
        ? spawn('unshare', ['-r', 'bash', ...args], { env, stdio: ['pipe', 'pipe', 'pipe'] })
        : spawn('bash', args, { env, stdio: ['pipe', 'pipe', 'pipe'], detached: o.noTty === true });
    let out = '';
    p.stdout.on('data', (d) => {
      out += d;
    });
    p.stderr.on('data', (d) => {
      out += d;
    });
    p.stdin.end(o.viaPipe ? (o.script ?? readFileSync(bootstrap, 'utf8')) : '');
    p.on('close', (code) => {
      resolve({
        code,
        out,
        requests: served.requests.slice(before),
        leftovers: readdirSync(tmp),
      });
    });
  });
}

function functions(code: string, env: Record<string, string> = {}) {
  const defs = readFileSync(bootstrapOf(release), 'utf8').replace(/^main "\$@"; exit \$\?\n$/m, '');
  return spawnSync('bash', ['-c', `${defs}\n${code}`], {
    env: { PATH: '/usr/bin:/bin', ...env },
    encoding: 'utf8',
  });
}

const asset = (k: Key) => `/v${VERSION}/keyflap-${VERSION}-${k}.tar.xz`;
const bootstrapOf = (r: Release) => join(r.dir, 'install-keyflap.sh');

describe.skipIf(process.getuid?.() === 0)('one-command bootstrap (install-keyflap.sh)', () => {
  beforeAll(async () => {
    root = mkdtempSync(join(tmpdir(), 'kf-bootstrap-'));
    fakeBin = join(root, 'bin');
    writeFakes(fakeBin);
    release = fakeRelease(root, KEYS);
    expect(make(release.dir).code).toBe(0);
    served = await serve(release.dir);
  });

  afterAll(() => {
    server?.close();
    if (root) rmSync(root, { recursive: true, force: true });
  });

  describe('make-bootstrap.sh', () => {
    it("pins every tarball's SHA-256 and adds the installer itself to SHA256SUMS", () => {
      const text = readFileSync(bootstrapOf(release), 'utf8');
      for (const k of KEYS) {
        const tarball = readFileSync(join(release.dir, `keyflap-${VERSION}-${k}.tar.xz`));
        expect(text).toContain(`    ${k}) echo ${sha256(tarball)} ;;`);
      }
      expect(text).toContain(`local version='${VERSION}'`);
      expect(text).not.toContain('@KEYFLAP_');
      const sums = readFileSync(join(release.dir, 'SHA256SUMS'), 'utf8').trim().split('\n');
      expect(sums).toContain(`${sha256(readFileSync(bootstrapOf(release)))}  install-keyflap.sh`);
      expect(sums).toHaveLength(KEYS.length + 1);
    });

    it('is idempotent: a second run writes the same installer and the same SHA256SUMS', () => {
      const r = fakeRelease(root, ['linux-x64'], '0.9.2');
      expect(make(r.dir, '0.9.2').code).toBe(0);
      const first = readFileSync(bootstrapOf(r), 'utf8');
      const firstSums = readFileSync(join(r.dir, 'SHA256SUMS'), 'utf8');
      expect(make(r.dir, '0.9.2').code).toBe(0);
      expect(readFileSync(bootstrapOf(r), 'utf8')).toBe(first);
      expect(readFileSync(join(r.dir, 'SHA256SUMS'), 'utf8')).toBe(firstSums);
    });

    it('refuses a tarball that does not match its SHA256SUMS line, and writes nothing', () => {
      const r = fakeRelease(root, ['linux-arm64'], '0.9.3');
      writeFileSync(join(r.dir, `keyflap-0.9.3-linux-arm64.tar.xz`), 'not the tarball');
      const m = make(r.dir, '0.9.3');
      expect(m.code).toBe(1);
      expect(m.out).toContain('does not match its SHA256SUMS line');
      expect(existsSync(bootstrapOf(r))).toBe(false);
    });

    it('refuses a SHA256SUMS that lists another version, or none of this one', () => {
      const r = fakeRelease(root, ['linux-x64'], '0.9.4');
      expect(make(r.dir, '0.9.5').out).toContain('not a 0.9.5 tarball');
      writeFileSync(join(r.dir, 'SHA256SUMS'), '');
      expect(make(r.dir, '0.9.4').out).toContain('lists no keyflap-0.9.4-*.tar.xz');
      expect(make(r.dir, 'v0.9.4').out).toContain('bad version');
    });
  });

  describe('picks the tarball for this machine', () => {
    it.each([
      ['Linux', 'x86_64', '0', 'linux-x64', 'Linux on x86_64'],
      ['Linux', 'aarch64', '0', 'linux-arm64', 'Linux on arm64'],
      ['Darwin', 'arm64', '0', 'darwin-arm64', 'macOS on Apple silicon'],
      ['Darwin', 'x86_64', '1', 'darwin-arm64', 'macOS on Apple silicon'],
    ] as const)('%s %s (arm64 sysctl %s) -> %s', async (s, m, arm64, key, label) => {
      const r = await run(bootstrapOf(release), { s, m, arm64 });
      expect(r.out).toContain(`Keyflap ${VERSION} for ${label}.`);
      expect(r.requests).toEqual([asset(key)]);
      expect(r.out).toContain(`matches the pinned SHA-256`);
      expect(r.out).toContain(
        `Would run: /opt/keyflap-release/keyflap-${VERSION}-${key}/install.sh --approver-origin https://laptop.tail1234.ts.net:8766`,
      );
      expect(r.out).toContain('Nothing was installed.');
      expect(r.code).toBe(0);
      expect(r.leftovers).toEqual([]);
      expect(existsSync(release.marker)).toBe(false);
    });

    it.each([
      ['Darwin', 'x86_64', 'Intel Macs are not supported yet'],
      ['FreeBSD', 'amd64', 'not FreeBSD'],
      ['Linux', 'riscv64', 'not riscv64'],
    ] as const)('refuses %s %s before downloading anything', async (s, m, why) => {
      const r = await run(bootstrapOf(release), { s, m });
      expect(r.code).toBe(1);
      expect(r.out).toContain(why);
      expect(r.requests).toEqual([]);
      expect(r.leftovers).toEqual([]);
    });

    it('refuses a machine the release has no build for, before downloading anything', async () => {
      const linuxOnly = fakeRelease(root, ['linux-x64', 'linux-arm64'], VERSION);
      expect(make(linuxOnly.dir).code).toBe(0);
      const r = await run(bootstrapOf(linuxOnly), { s: 'Darwin', m: 'arm64' });
      expect(r.code).toBe(1);
      expect(r.out).toContain(
        `Keyflap ${VERSION} has no build for macOS on Apple silicon. Supported: Linux on x86_64, Linux on arm64.`,
      );
      expect(r.requests).toEqual([]);
    });
  });

  describe('changes nothing unless the download matches the pinned hash', () => {
    it('refuses a tampered tarball: deleted unopened, nothing unpacked, install.sh never run', async () => {
      served.tamper.add(`keyflap-${VERSION}-linux-x64.tar.xz`);
      try {
        const r = await run(bootstrapOf(release));
        expect(r.requests).toEqual([asset('linux-x64')]);
        expect(r.code).toBe(1);
        expect(r.out).toContain(
          `keyflap-${VERSION}-linux-x64.tar.xz does not match the SHA-256 pinned in this installer, so it was deleted unopened.`,
        );
        expect(r.out).toContain('Nothing was installed.');
        expect(r.out).not.toContain('Would run');
        expect(r.leftovers).toEqual([]);
        expect(existsSync(release.marker)).toBe(false);
      } finally {
        served.tamper.clear();
      }
    });

    it('a missing tarball (HTTP 404) is a refusal too', async () => {
      const r = await run(bootstrapOf(release), { base: `${served.base}/elsewhere` });
      expect(r.code).toBe(1);
      expect(r.out).toContain('the download failed; nothing was installed');
      expect(r.leftovers).toEqual([]);
    });
  });

  describe('the test override cannot point anywhere but this machine', () => {
    it.each([
      'https://evil.example/releases',
      'http://127.0.0.1:1@evil.example',
      'http://127.0.0.1.evil.example:80',
      'http://localhost:8000',
      'file:///tmp/release',
    ])('refuses KEYFLAP_RELEASE_BASE=%s before downloading anything', async (base) => {
      const r = await run(bootstrapOf(release), { base });
      expect(r.code).toBe(1);
      expect(r.out).toContain('KEYFLAP_RELEASE_BASE is only for tests');
      expect(r.requests).toEqual([]);
    });
  });

  describe('runs as `curl … | sudo bash`', () => {
    it('without --dry-run it needs root, and refuses before downloading anything', async () => {
      const r = await run(bootstrapOf(release), { args: [] });
      expect(r.code).toBe(1);
      expect(r.out).toContain('it needs root');
      expect(r.out).toContain(
        'curl -fsSL https://github.com/johnpippett/keyflap/releases/latest/download/install-keyflap.sh | sudo bash',
      );
      expect(r.out).toContain(`the simple install runs as you without sudo, and protects less:
  ${SIMPLE_COMMAND}`);
      expect(r.requests).toEqual([]);
    });

    it('works with the script on stdin (the pipe), as bash -s', async () => {
      const r = await run(bootstrapOf(release), { viaPipe: true });
      expect(r.code).toBe(0);
      expect(r.requests).toEqual([asset('linux-x64')]);
      expect(r.out).toContain('Dry run: stopped before installing.');
    });

    it('a download cut off before its last line runs nothing', async () => {
      const text = readFileSync(bootstrapOf(release), 'utf8');
      const cut = text.slice(0, text.lastIndexOf('main "$@"; exit $?'));
      for (const at of [cut.length, Math.floor(cut.length / 2), 200]) {
        const r = await run(bootstrapOf(release), { viaPipe: true, script: cut.slice(0, at) });
        expect(r.requests).toEqual([]);
        expect(r.out).not.toContain('Keyflap');
      }
    });
  });

  describe('the simple Mac install (--simple, no sudo)', () => {
    it('downloads the Mac build as the user and would run install-simple.sh, then setup', async () => {
      const r = await run(bootstrapOf(release), {
        s: 'Darwin',
        m: 'arm64',
        args: ['--simple', '--dry-run'],
      });
      expect(r.code, r.out).toBe(0);
      expect(r.requests).toEqual([asset('darwin-arm64')]);
      expect(r.out).toMatch(
        /Would run: \S+\/keyflap-dry-run\.\w+\/keyflap-[\d.]+-darwin-arm64\/install-simple\.sh --confirmed/,
      );
      expect(r.out).toContain("Then:      '");
      expect(r.out).toContain("/Library/Application Support/Keyflap/bin/keyflap' setup");
      expect(r.out).not.toContain('/opt/keyflap-release');
      expect(r.leftovers).toEqual([]);
      expect(existsSync(release.marker)).toBe(false);
    });

    it.runIf(CAN_BE_ROOT)(
      'refuses --simple under sudo, naming the command without sudo and the full install',
      async () => {
        const r = await run(bootstrapOf(release), {
          s: 'Darwin',
          m: 'arm64',
          args: ['--simple'],
          asRoot: true,
        });
        expect(r.code).toBe(1);
        expect(r.out).toContain(`the simple install runs as you, without sudo. Run it like this:
  ${SIMPLE_COMMAND}
The full install, which protects more, is the one that uses sudo:`);
        expect(r.requests).toEqual([]);
      },
    );

    it('is for Macs only', async () => {
      const r = await run(bootstrapOf(release), { args: ['--simple', '--dry-run'] });
      expect(r.code).toBe(1);
      expect(r.out).toContain('the simple install is for Macs. On Linux, use the full install:');
      expect(r.requests).toEqual([]);
    });

    it('asks first, so it refuses without a terminal, before downloading anything', async () => {
      const r = await run(bootstrapOf(release), {
        s: 'Darwin',
        m: 'arm64',
        args: ['--simple'],
        noTty: true,
      });
      expect(r.code).toBe(1);
      expect(r.out).toContain('it needs a terminal to ask you first');
      expect(r.requests).toEqual([]);
      expect(r.leftovers).toEqual([]);
    });

    it('the full install refuses over a simple install, and says what to do', () => {
      const home = mkdtempSync(join(root, 'home-'));
      mkdirSync(join(home, 'Library', 'LaunchAgents'), { recursive: true });
      writeFileSync(join(home, 'Library', 'LaunchAgents', 'com.keyflap.simple.plist'), '');
      const fakes = mkdtempSync(join(root, 'dscl-'));
      writeFileSync(join(fakes, 'dscl'), `#!/bin/sh\necho "NFSHomeDirectory: ${home}"\n`, {
        mode: 0o755,
      });
      const p = functions('simple_install_absent alice', { PATH: `${fakes}:/usr/bin:/bin` });
      expect(p.status).toBe(1);
      expect(p.stderr).toContain('alice has the simple install of Keyflap. Remove it first');
      expect(p.stderr).toContain(`'${home}/Library/Application Support/Keyflap/uninstall.sh'`);
      expect(p.stderr).toContain('Nothing moves across');
      const none = functions('simple_install_absent bob && echo clear', {
        PATH: `${fakes}:/usr/bin:/bin`,
      });
      expect(none.stdout).toBe('');
      rmSync(join(home, 'Library'), { recursive: true });
      expect(
        functions('simple_install_absent bob && echo clear', { PATH: `${fakes}:/usr/bin:/bin` })
          .stdout,
      ).toBe('clear\n');
    });
  });

  describe('finds the approver origin from Tailscale', () => {
    it.each([
      [{ BackendState: 'NeedsLogin' }, 'not connected (NeedsLogin)'],
      [
        { BackendState: 'Running', Self: { DNSName: 'laptop.tail1234.ts.net.' }, CertDomains: [] },
        'HTTPS certificates are off',
      ],
      [{ BackendState: 'Running', Self: { DNSName: '' } }, 'no MagicDNS name'],
    ])('says what is missing when it cannot (%j)', async (status, why) => {
      const json = join(root, `ts-${sha256(JSON.stringify(status)).slice(0, 8)}.json`);
      writeFileSync(json, JSON.stringify(status, null, 2));
      const r = await run(bootstrapOf(release), { tailscaleJson: json });
      expect(r.out).toContain(why);
      expect(r.out).toContain('No approver origin found: the installer would ask for one.');
      expect(r.code).toBe(0);
    });

    it('does not run a tailscale that someone other than its owner could change', () => {
      const loose = join(root, 'loose-bin');
      writeFakes(loose);
      chmodSync(join(loose, 'tailscale'), 0o777);
      const p = functions(`approver_port=8766; tailscale_origin`, {
        PATH: `${loose}:/usr/bin:/bin`,
        FAKE_TAILSCALE_JSON: join(loose, 'tailscale.json'),
      });
      expect(p.stderr).toContain(`Not running ${join(loose, 'tailscale')}`);
      expect(p.stdout).not.toContain('laptop.tail1234');
    });

    it('trusts a file only if root or this user owns it and its directories, and no one else can write them', () => {
      const d = mkdtempSync(join(root, 'trust-'));
      const file = (name: string, mode: number) => {
        writeFileSync(join(d, name), '', { mode });
        chmodSync(join(d, name), mode);
        return join(d, name);
      };
      const ok = file('ok', 0o755);
      const loose = file('loose', 0o775);
      const sub = join(d, 'shared');
      mkdirSync(sub);
      chmodSync(sub, 0o777);
      writeFileSync(join(sub, 'f'), '', { mode: 0o755 });
      const sticky = join(d, 'sticky');
      mkdirSync(sticky);
      chmodSync(sticky, 0o1777);
      writeFileSync(join(sticky, 'f'), '', { mode: 0o755 });
      const verdict = (path: string) =>
        functions(`trusted '${path}' && echo yes || echo no`).stdout.trim();
      expect(verdict(ok)).toBe('yes');
      expect(verdict(loose)).toBe('no');
      expect(verdict(join(sub, 'f'))).toBe('no');
      expect(verdict(join(sticky, 'f'))).toBe('yes');
      expect(verdict(join(d, 'missing'))).toBe('no');
    });
  });

  describe('an upgrade offers the answers recorded in bootstrap.conf', () => {
    const offered = (source: string) => {
      const conf = join(mkdtempSync(join(root, 'conf-')), 'bootstrap.conf');
      writeFileSync(
        conf,
        `origin=https://kf.example.ts.net:8766\npassword_source=${source}\nvault=Agent\n`,
        {
          mode: 0o600,
        },
      );
      return functions(
        `os=linux; conf_source=''; conf_origin=''; conf_vault=''; pw_source=''; pw_choice=none
ask() { echo "offered $2"; answer=$2; }
read_conf '${conf}'; choose_password_source; echo "chose \${pw_source:-$pw_choice}"`,
      ).stdout;
    };

    it.each([
      ['import', '3'],
      ['none', '4'],
    ])('password_source=%s is offered as choice %s and recorded again', (source, choice) => {
      const out = offered(source);
      expect(out).toContain(`offered ${choice}`);
      expect(out).toContain(`chose ${source}`);
    });
  });

  describe('an upgrade keeps the password manager that is connected now', () => {
    const SIGNER = (source: string) =>
      JSON.stringify({
        storePath: '/k',
        ...(source === 'proton-pass' ? { sources: { protonPass: { bin: '/b', env: {} } } } : {}),
        ...(source === '1password' ? { sources: { onePassword: { bin: '/b', env: {} } } } : {}),
      });
    function decide(o: { connected: string; conf: string; answer: string }) {
      const dir = mkdtempSync(join(root, 'conn-'));
      const cfg = join(dir, 'signer.json');
      writeFileSync(cfg, `${SIGNER(o.connected)}\n`, { mode: 0o644 });
      const conf = join(dir, 'bootstrap.conf');
      writeFileSync(
        conf,
        `origin=https://kf.example.ts.net:8766\npassword_source=${o.conf}\nvault=Old\n`,
        { mode: 0o600 },
      );
      return functions(
        `os=linux; conf_source=''; conf_origin=''; conf_vault=''; pw_source=''; pw_choice=none
ask() { echo "offered $2"; answer=${o.answer}; }
tool_present() { return 0; }
read_conf '${conf}'; read_connected '${cfg}'; echo "connected=$connected"
choose_password_source; echo "chose \${pw_source:-$pw_choice}"`,
      ).stdout;
    }

    it('offers what is connected, not what the install first recorded', () => {
      const out = decide({ connected: '1password', conf: 'proton-pass', answer: '1' });
      expect(out).toContain('connected=1password');
      expect(out).toContain('offered 1');
      expect(out).toContain('chose 1password');
    });

    it('a manager disconnected since is offered as none', () => {
      const out = decide({ connected: '', conf: 'proton-pass', answer: '4' });
      expect(out).toContain('connected=\n');
      expect(out).toContain('offered 4');
    });

    it('an import choice stays an import', () => {
      expect(decide({ connected: '', conf: 'import', answer: '3' })).toContain('offered 3');
    });

    it('a settings file anyone could change is not believed', () => {
      const dir = mkdtempSync(join(root, 'conn-'));
      const cfg = join(dir, 'signer.json');
      writeFileSync(cfg, SIGNER('1password'));
      chmodSync(cfg, 0o666);
      chmodSync(dir, 0o777);
      const r = functions(
        `os=linux; conf_source=proton-pass; read_connected '${cfg}'; echo "connected=$connected source=$conf_source"`,
      );
      expect(r.stdout).toContain('connected= source=proton-pass');
    });

    function flags(o: { connected: string; answers: string[]; toolPresent?: boolean }) {
      const dir = mkdtempSync(join(root, 'conn-'));
      const cfg = join(dir, 'signer.json');
      writeFileSync(cfg, `${SIGNER(o.connected)}\n`, { mode: 0o644 });
      const r = functions(
        `os=linux; conf_source=''; conf_origin=''; conf_vault=''; pw_source=''; pw_choice=none
disconnect=0; vault=''
answers=(${o.answers.map((a) => `'${a}'`).join(' ')})
ask() { answer=\${answers[0]-}; answers=("\${answers[@]:1}"); echo "asked: $1" >&2; }
tool_present() { return ${o.toolPresent === false ? 1 : 0}; }
read_connected '${cfg}'
choose_password_source >/dev/null
if [ "$pw_source" != "$connected" ] && [ -n "$pw_source" ]; then vault=Agent; fi
args=()
source_args
echo "flags=\${args[*]-}"
echo "kept=\${pw_source:-none} disconnect=$disconnect"`,
      );
      expect(r.status, r.stderr).toBe(0);
      return { out: r.stdout, err: r.stderr };
    }

    it('importing, or going on without the tool, keeps the connected manager', () => {
      const imported = flags({ connected: '1password', answers: ['3'] });
      expect(imported.out).toContain('flags=\n');
      expect(imported.out).toContain('kept=1password disconnect=0');
      const without = flags({ connected: 'proton-pass', answers: ['1', 'y'], toolPresent: false });
      expect(without.out).toContain('flags=\n');
      expect(without.out).toContain('kept=proton-pass disconnect=0');
    });

    it('choosing the connected manager again passes nothing', () => {
      expect(flags({ connected: '1password', answers: ['1'] }).out).toContain('flags=\n');
    });

    it('choosing another manager replaces it with an explicit flag', () => {
      expect(flags({ connected: '1password', answers: ['2'] }).out).toContain(
        'flags=--password-source proton-pass --proton-pass-vault Agent',
      );
    });

    it('disconnecting needs an explicit choice and an explicit yes, and then passes none', () => {
      const yes = flags({ connected: '1password', answers: ['4', 'y'] });
      expect(yes.err).toContain('Disconnect 1Password? Agents stop using its logins.');
      expect(yes.out).toContain('flags=--password-source none');
      const no = flags({ connected: '1password', answers: ['4', 'n', '3'] });
      expect(no.out).toContain('flags=\n');
      expect(no.out).toContain('disconnect=0');
    });

    it('with nothing connected, choosing none passes nothing', () => {
      expect(flags({ connected: '', answers: ['4'] }).out).toContain('flags=\n');
    });
  });

  describe.runIf(HAS_PTY)('on a terminal', () => {
    it('shows the download, the check and the unpacking under one bar, then what it would run', async () => {
      const r = await run(bootstrapOf(release));
      const t = await run(bootstrapOf(release), { pty: true });
      expect(t.code, t.out).toBe(0);
      expect(t.requests).toEqual([asset('linux-x64')]);
      const text = render(t.out).text();
      expect(text).toContain(`  K  KEYFLAP  install · ${VERSION}\n     ${'━'.repeat(73)}`);
      expect(text).toContain(`   ✓ Downloaded and checked Keyflap ${VERSION}`);
      expect(text).toContain(
        `     Would run: /opt/keyflap-release/keyflap-${VERSION}-linux-x64/install.sh --approver-origin https://laptop.tail1234.ts.net:8766`,
      );
      expect(text).toContain('     Dry run: stopped before installing. Nothing was installed.');
      expect(text).not.toContain('Downloading http');
      expect(r.out).toContain(
        `Downloading ${served.base}/v${VERSION}/keyflap-${VERSION}-linux-x64.tar.xz`,
      );
      expect(t.leftovers).toEqual([]);
    });

    it('a tampered download stops on the check and prints the full reason', async () => {
      served.tamper.add(`keyflap-${VERSION}-linux-x64.tar.xz`);
      try {
        const t = await run(bootstrapOf(release), { pty: true });
        expect(t.code).toBe(1);
        const text = render(t.out).text();
        expect(text).toContain('   ✗ Checking the download');
        expect(text).toContain(
          `keyflap install: keyflap-${VERSION}-linux-x64.tar.xz does not match the SHA-256 pinned in this installer, so it was deleted unopened.`,
        );
        expect(text).toContain('Nothing was installed. Try again later');
        expect(text).not.toContain('Details:');
        expect(render(t.out).cursorVisible).toBe(true);
        expect(t.leftovers).toEqual([]);
      } finally {
        served.tamper.clear();
      }
    });

    it("a failed download says why, with curl's own error", async () => {
      const t = await run(bootstrapOf(release), { pty: true, base: `${served.base}/elsewhere` });
      expect(t.code).toBe(1);
      const text = render(t.out).text();
      expect(text).toContain('   ✗ Downloading Keyflap');
      expect(text).toContain('keyflap install: the download failed; nothing was installed');
      expect(text).toMatch(/curl: \(22\) The requested URL returned error: 404/);
    });

    it('NO_COLOR keeps the frame and drops the colour', async () => {
      const t = await run(bootstrapOf(release), { pty: true, env: { NO_COLOR: '1' } });
      expect(t.code, t.out).toBe(0);
      const sgr = t.out.split('\u001b[').filter((after) => /^[0-9;]*m/.test(after));
      expect(sgr).toEqual([]);
      expect(render(t.out).text()).toContain(` [K] KEYFLAP  install · ${VERSION}`);
    });
  });

  it('stays within bash 3.2 (macOS root bash)', () => {
    const text =
      readFileSync(TEMPLATE, 'utf8') + readFileSync(MAKE, 'utf8') + readFileSync(PROGRESS, 'utf8');
    for (const bash4 of [
      /declare -A/,
      /\bmapfile\b/,
      /\breadarray\b/,
      /\$\{[A-Za-z_]+(,,|\^\^)\}/,
      /\|&/,
      /&>>/,
      /\bcoproc\b/,
      /\[\[ -v /,
      /\$\{[A-Za-z_]+@[QEPAa]\}/,
    ]) {
      expect(text, String(bash4)).not.toMatch(bash4);
    }
  });
});
