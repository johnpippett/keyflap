import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
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
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

const INSTALL = join(import.meta.dirname, '..');
const NODE_PREFIX = dirname(dirname(process.execPath));
export const VERSION = '0.9.1';
export const RELEASE = `/opt/keyflap-release/keyflap-${VERSION}-darwin-arm64`;
const NODE_VERSION = /NODE_VERSION=([\d.]+)/.exec(
  readFileSync(join(INSTALL, 'linux', 'runtime-pins.sh'), 'utf8'),
)?.[1] as string;

const q = (a: string) => `'${a.replaceAll("'", `'\\''`)}'`;
const SBIN_PATH = 'PATH="$PATH:/usr/sbin:/sbin"';
const HOST_NODE_RUNS_IN_A_USR_ONLY_ROOT = [
  'set -e',
  SBIN_PATH,
  'mount -t tmpfs t /mnt',
  'test "$(id -u)" = 0',
  'mkdir /mnt/usr /mnt/hostnode',
  'mount --rbind /usr /mnt/usr',
  `mount --bind ${q(NODE_PREFIX)} /mnt/hostnode`,
  'for l in bin sbin lib lib64; do ln -s usr/$l /mnt/$l; done',
  'chroot /mnt /hostnode/bin/node -e 0',
].join('\n');

export const canFakeMac =
  process.platform === 'linux' &&
  spawnSync('unshare', ['-rm', 'sh', '-c', HOST_NODE_RUNS_IN_A_USR_ONLY_ROOT]).status === 0 &&
  spawnSync('script', ['--version']).status === 0;

const FAKES: Record<string, string> = {
  uname: `case $1 in -m) echo arm64 ;; -s) echo Darwin ;; *) exec /realbin/uname "$@" ;; esac`,
  sw_vers: 'echo 15.1',
  fdesetup: '[ -n "$FAKE_FILEVAULT" ] || FAKE_FILEVAULT=On; echo "FileVault is $FAKE_FILEVAULT."',
  dscacheutil: 'exit 0',
  plutil: 'exit 0',
  pkill: 'exit 0',
  chown: 'exit 0',
  xattr: 'case $1 in -p) exit 1 ;; *) exit 0 ;; esac',
  shasum: '[ "$1" = -a ] && shift 2; exec sha256sum "$@"',
  tailscale: `[ "$1" = status ] || exit 2
echo '{"BackendState": "Running", "Self": {"DNSName": "mac.tail1234.ts.net."}, "CertDomains": ["mac.tail1234.ts.net"]}'`,
  chmod: 'case $1 in +a|-a*) exit 0 ;; *) exec /realbin/chmod "$@" ;; esac',
  stat: `[ "$1" = -f ] || exec /realbin/stat "$@"
case $2 in
  %u) exec /realbin/stat -c %u "$3" ;;
  %Lp) exec /realbin/stat -c %a "$3" ;;
  %Su) exec /realbin/stat -c %U "$3" ;;
  %p) printf '%o\\n' "0x$(/realbin/stat -c %f "$3")" ;;
  *) echo "fake stat: $2" >&2; exit 2 ;;
esac`,
  install: `args=''
while [ $# -gt 0 ]; do
  case $1 in -o|-g) shift 2 ;; *) args="$args
$1"; shift ;; esac
done
IFS='
'
exec /realbin/install $args`,
  sudo: `while [ $# -gt 0 ]; do case $1 in -u) shift 2 ;; -n|--) shift ;; *) break ;; esac; done
exec "$@"`,
  launchctl: `d=/fakestate/launchd
mkdir -p $d
sleep "\${FAKE_DELAY:-0}"
case $1 in
  print) [ -f "$d/\${2#system/}" ] ;;
  bootstrap) [ -z "\${FAKE_LAUNCHCTL_FAIL:-}" ] || { echo "Bootstrap failed: 5: Input/output error" >&2; exit 5; }
    l=$(basename "$3" .plist); sleep "\${FAKE_DELAY:-0}"; : >"$d/$l" ;;
  bootout) rm -f "$d/\${2#system/}" ;;
  *) exit 0 ;;
esac`,
  dscl: `d=/fakestate/dscl
shift
op=$1 rec=$2 key=\${3:-} val=\${4:-}
case $op in
  -read)
    [ -d "$d$rec" ] || { echo "Data source (.) is not valid." >&2; exit 56; }
    if [ -z "$key" ]; then echo "RecordName: $(cat "$d$rec/RecordName" 2>/dev/null)"; exit 0; fi
    if [ -f "$d$rec/$key" ]; then echo "$key: $(cat "$d$rec/$key")"; else echo "No such key: $key" >&2; fi ;;
  -create)
    mkdir -p "$d$rec"
    [ -f "$d$rec/RecordName" ] || basename "$rec" >"$d$rec/RecordName"
    [ -z "$key" ] || printf '%s' "$val" >"$d$rec/$key" ;;
  -append) printf ' %s' "$val" >>"$d$rec/$key" ;;
  -list)
    for r in "$d$rec"/*; do [ -f "$r/$key" ] && echo "$(basename "$r") $(cat "$r/$key")"; done; exit 0 ;;
esac`,
  id: `case "$1 \${2:-}" in
  "-u alice") echo 501 ;;
  "-gn alice") echo staff ;;
  "-u ") exec /realbin/id -u ;;
  -u*)
    for r in /fakestate/dscl/Users/*; do
      for n in $(cat "$r/RecordName" 2>/dev/null); do
        if [ "$n" = "$2" ] && [ -f "$r/UniqueID" ]; then cat "$r/UniqueID"; echo; exit 0; fi
      done
    done
    echo "id: $2: no such user" >&2; exit 1 ;;
  *) exec /realbin/id "$@" ;;
esac`,
};

const INSTALL_CONFIG = `import { writeFileSync } from 'node:fs';
const a = process.argv.slice(2);
const out = a[a.indexOf('--out-dir') + 1];
for (const n of ['core', 'signer']) writeFileSync(\`\${out}/\${n}.json\`, '{}');
writeFileSync(\`\${out}/approver.json\`, JSON.stringify({ listen: { host: '127.0.0.1', port: 8766 } }));
console.log('wrote', out);
`;

const SETUP = `console.log('(keyflap setup runs here: your phone, your agent, your passwords)');
`;

const PLAYWRIGHT = `const { mkdirSync, writeFileSync } = require('node:fs');
const dir = process.env.PLAYWRIGHT_BROWSERS_PATH + '/chromium-1248';
const delay = Number(process.env.FAKE_DELAY || 0) * 1000;
console.log('Downloading Chromium 140.0.7339.16 (playwright build v1248) from https://cdn.playwright.dev/fake');
let row = 0;
const tick = () => {
  console.log('|' + '\\u25A0'.repeat(row * 8) + ' '.repeat((10 - row) * 8) + '| ' + String(row * 10).padStart(3) + '% of 162.5 MiB');
  if (row === 3 && process.env.FAKE_PLAYWRIGHT_FAIL) {
    console.error('Error: Download failure, code=1');
    process.exit(1);
  }
  if (row++ < 10) return setTimeout(tick, delay);
  mkdirSync(dir, { recursive: true });
  writeFileSync(dir + '/INSTALLATION_COMPLETE', '');
  console.log('Chromium downloaded to ' + dir);
};
tick();
`;

function sha256(file: string): string {
  return createHash('sha256').update(readFileSync(file)).digest('hex');
}

export interface FakeMac {
  root: string;
  log: string;
}

function stageRelease(rel: string): void {
  mkdirSync(rel, { recursive: true });
  for (const f of ['install.sh', 'keyflap-wrapper.sh']) {
    cpSync(join(INSTALL, 'macos', f), join(rel, f));
    chmodSync(join(rel, f), 0o755);
  }
  cpSync(join(INSTALL, 'macos', 'launchd'), join(rel, 'launchd'), { recursive: true });
  cpSync(join(INSTALL, 'linux', 'progress.sh'), join(rel, 'progress.sh'));
  writeFileSync(join(rel, 'keyflap-launch'), Buffer.from([0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0]));
  const app = join(rel, 'bundle', 'app');
  mkdirSync(join(app, 'packages/cli/src/service'), { recursive: true });
  mkdirSync(join(app, 'packages/shim/node_modules/playwright'), { recursive: true });
  writeFileSync(join(rel, 'bundle', '.keyflap-bundle'), '');
  writeFileSync(join(app, 'VERSION'), `${VERSION}\n`);
  writeFileSync(join(app, 'packages/cli/src/main.ts'), SETUP);
  writeFileSync(join(app, 'packages/cli/src/service/install-config.ts'), INSTALL_CONFIG);
  writeFileSync(join(app, 'packages/shim/node_modules/playwright/cli.js'), PLAYWRIGHT);

  const nodeName = `node-v${NODE_VERSION}-darwin-arm64`;
  const nodeSrc = mkdtempSync(join(tmpdir(), 'kf-fakenode-'));
  mkdirSync(join(nodeSrc, nodeName, 'bin'), { recursive: true });
  writeFileSync(
    join(nodeSrc, nodeName, 'bin', 'node'),
    '#!/bin/sh\nexec /hostnode/bin/node "$@"\n',
    {
      mode: 0o755,
    },
  );
  const tarball = join(rel, `${nodeName}.tar.xz`);
  spawnSync('tar', ['-cJf', tarball, '-C', nodeSrc, nodeName]);
  rmSync(nodeSrc, { recursive: true, force: true });
  const pins = readFileSync(join(INSTALL, 'linux', 'runtime-pins.sh'), 'utf8');
  writeFileSync(
    join(rel, 'runtime-pins.sh'),
    `${pins}\nnode_sha256() { echo ${sha256(tarball)}; }\n`,
  );
}

export function fakeMac(o: { staged: boolean } = { staged: true }): FakeMac {
  const root = mkdtempSync(join(tmpdir(), 'kf-fakemac-'));
  const at = (p: string) => join(root, p);
  for (const d of ['usr', 'etc', 'dev', 'proc', 'opt', 'Library', 'hostnode', 'fake', 'realbin']) {
    mkdirSync(at(d), { recursive: true, mode: 0o755 });
  }
  mkdirSync(at('tmp'), { mode: 0o700 });
  mkdirSync(at('fakestate/dscl/Users/alice'), { recursive: true });
  writeFileSync(at('fakestate/dscl/Users/alice/NFSHomeDirectory'), '/Users/alice');
  writeFileSync(at('fakestate/dscl/Users/alice/UniqueID'), '501');
  writeFileSync(at('fakestate/dscl/Users/alice/RecordName'), 'alice');
  mkdirSync(at('fakestate/dscl/Groups'), { recursive: true });
  for (const [name, body] of Object.entries(FAKES)) {
    writeFileSync(at(`fake/${name}`), `#!/bin/sh\n${body}\n`, { mode: 0o755 });
  }
  mkdirSync(at('Library/Tailscale'));
  mkdirSync(at('Library/LaunchDaemons'));
  spawnSync('ln', ['-s', '49152', at('Library/Tailscale/ipnport')]);
  writeFileSync(at('Library/Tailscale/sameuserproof-49152'), 'token', { mode: 0o600 });
  if (o.staged) stageRelease(at(RELEASE.slice(1)));
  return { root, log: at('Library/Keyflap/log/install.log') };
}

export interface Served {
  base: string;
  bootstrap: string;
  close: () => void;
}

export async function serveRelease(mac: FakeMac): Promise<Served> {
  const dist = mkdtempSync(join(tmpdir(), 'kf-fakedist-'));
  const name = `keyflap-${VERSION}-darwin-arm64`;
  stageRelease(join(dist, 'src', name));
  spawnSync('tar', [
    '--owner=0',
    '--group=0',
    '--numeric-owner',
    '-cJf',
    join(dist, `${name}.tar.xz`),
    '-C',
    join(dist, 'src'),
    name,
  ]);
  writeFileSync(
    join(dist, 'SHA256SUMS'),
    `${sha256(join(dist, `${name}.tar.xz`))}  ${name}.tar.xz\n`,
  );
  const made = spawnSync('bash', [join(INSTALL, 'bootstrap', 'make-bootstrap.sh'), dist, VERSION]);
  if (made.status !== 0) throw new Error(made.stderr.toString());
  cpSync(join(dist, 'install-keyflap.sh'), join(mac.root, 'tmp', 'install-keyflap.sh'));
  const server = createServer((req, res) => {
    const file = join(dist, (req.url ?? '').replace(`/v${VERSION}/`, ''));
    if (!req.url?.startsWith(`/v${VERSION}/`) || !existsSync(file)) {
      res.writeHead(404).end();
      return;
    }
    const body = readFileSync(file);
    res.writeHead(200, { 'content-length': body.length });
    let at = 0;
    const step = Math.ceil(body.length / 8);
    const send = () => {
      res.write(body.subarray(at, at + step));
      at += step;
      if (at < body.length) setTimeout(send, Number(process.env.FAKE_DOWNLOAD_MS ?? 0) / 8);
      else res.end();
    };
    send();
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  return {
    base: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    bootstrap: '/tmp/install-keyflap.sh',
    close: () => {
      server.close();
      rmSync(dist, { recursive: true, force: true });
    },
  };
}

function inner(mac: FakeMac, argv: string[], env: Record<string, string>): string {
  const R = mac.root;
  const vars = Object.entries({
    PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
    HOME: '/var/root',
    TMPDIR: '/tmp',
    SUDO_USER: 'alice',
    ...env,
  }).map(([k, v]) => `${k}=${q(v)}`);
  return [
    'set -e',
    SBIN_PATH,
    `R=${q(R)}`,
    'for d in etc dev proc; do mount --rbind /$d "$R/$d"; done',
    'for d in /usr/*; do',
    '  n=$(basename "$d")',
    '  if [ -L "$d" ]; then ln -sfn "$(readlink "$d")" "$R/usr/$n"',
    '  elif [ "$n" != local ] && [ "$n" != bin ] && [ -d "$d" ]; then mkdir -p "$R/usr/$n" && mount --rbind "$d" "$R/usr/$n"; fi',
    'done',
    'mount --rbind /usr/bin "$R/realbin"',
    'mkdir -p "$R/usr/bin"',
    'mount -t overlay overlay -o "lowerdir=$R/fake:/usr/bin" "$R/usr/bin"',
    'mkdir -p "$R/usr/local"',
    `mount --bind ${q(NODE_PREFIX)} "$R/hostnode"`,
    'for l in bin sbin lib lib64; do [ -e "$R/$l" ] || ln -s usr/$l "$R/$l"; done',
    `exec chroot "$R" /usr/bin/env -i ${vars.join(' ')} /bin/bash ${argv.map(q).join(' ')}`,
  ].join('\n');
}

export interface Ran {
  code: number | null;
  out: string;
  chunks: { t: number; data: string }[];
}

export function runInFakeMac(
  mac: FakeMac,
  argv: string[],
  o: {
    tty: boolean;
    env?: Record<string, string>;
    cols?: number;
    answers?: [RegExp, string][];
  },
): Promise<Ran> {
  const script = inner(mac, argv, { TERM: 'xterm-256color', ...o.env });
  const unshare = `unshare -rm bash -c ${q(script)}`;
  const sized = `stty cols ${o.cols ?? 100} rows 40 2>/dev/null; ${unshare}`;
  const p = o.tty
    ? spawn('script', ['-qfec', sized, '/dev/null'], { stdio: ['pipe', 'pipe', 'pipe'] })
    : spawn('bash', ['-c', unshare], { stdio: ['pipe', 'pipe', 'pipe'] });
  const start = Date.now();
  const chunks: Ran['chunks'] = [];
  let out = '';
  const answers = [...(o.answers ?? [])];
  let answeredUpTo = 0;
  const take = (d: Buffer) => {
    const data = d.toString('utf8');
    out += data;
    chunks.push({ t: Date.now() - start, data });
    const next = answers[0];
    if (next?.[0].test(out.slice(answeredUpTo))) {
      answers.shift();
      answeredUpTo = out.length;
      setTimeout(() => p.stdin.write(next[1]), 400);
    }
  };
  p.stdout.on('data', take);
  p.stderr.on('data', take);
  if (answers.length === 0) p.stdin.end();

  return new Promise((resolve) => p.on('close', (code) => resolve({ code, out, chunks })));
}
