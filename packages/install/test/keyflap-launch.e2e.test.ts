import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

type Plist = string | number | boolean | Plist[] | { [key: string]: Plist };

const SOURCE = join(import.meta.dirname, '..', 'macos', 'launcher', 'keyflap-launch.c');
const LABEL = `com.keyflap.launchtest.${process.pid}`;
const SHOW_FDS =
  'echo "$$ $LISTEN_PID $LISTEN_FDS $LISTEN_FDNAMES $(id -un)"; ' +
  'for f in 3 4 5 6 7 8 9 10 11 12; do [ -e /dev/fd/$f ] && echo "fd $f"; done; echo end';
const SYSTEMD_TS = join(import.meta.dirname, '..', '..', 'signer', 'src', 'systemd.ts');
const SERVE = `
import net from 'node:net';
import { listenFds } from ${JSON.stringify(SYSTEMD_TS)};
const fds = [...listenFds()];
const info = { pid: process.pid, fds, uid: process.getuid() };
setTimeout(() => fds.forEach(([name, fd]) => {
  net.createServer((c) => { c.end(JSON.stringify({ ...info, name })); setTimeout(() => process.exit(0), 50); })
    .listen({ fd });
}), 1000);
`;

const xml = (s: string) => s.replaceAll('&', '&amp;').replaceAll('<', '&lt;');
function plistXml(v: Plist): string {
  if (typeof v === 'string') return `<string>${xml(v)}</string>`;
  if (typeof v === 'number') return `<integer>${v}</integer>`;
  if (typeof v === 'boolean') return v ? '<true/>' : '<false/>';
  if (Array.isArray(v)) return `<array>${v.map(plistXml).join('')}</array>`;
  const entries = Object.entries(v).map(([k, x]) => `<key>${xml(k)}</key>${plistXml(x)}`);
  return `<dict>${entries.join('')}</dict>`;
}
const plistDocument = (v: Plist) =>
  '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" ' +
  `"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0">${plistXml(v)}</plist>\n`;

const run = (cmd: string, args: string[]) => spawnSync(cmd, args, { encoding: 'utf8' });

function findLauncher(): { path: string; built: string | null } | { skip: string } {
  if (process.platform !== 'darwin') return { skip: 'needs macOS: launchd hands over the sockets' };
  const given = process.env.KEYFLAP_LAUNCH;
  if (given) return { path: given, built: null };
  if (run('xcode-select', ['-p']).status !== 0) {
    return { skip: 'set KEYFLAP_LAUNCH to a build.sh output, or install the Command Line Tools' };
  }
  const dir = mkdtempSync(join(tmpdir(), 'keyflap-launch-cc-'));
  const path = join(dir, 'keyflap-launch');
  execFileSync('xcrun', ['clang', '-O2', '-fno-builtin', '-Werror', '-o', path, SOURCE]);
  return { path, built: dir };
}

const launcher = findLauncher();
afterAll(() => {
  if ('built' in launcher && launcher.built) rmSync(launcher.built, { recursive: true });
});
const launcherSkip = 'skip' in launcher ? launcher.skip : null;
const LAUNCHER = 'path' in launcher ? launcher.path : '';
const uid = process.getuid?.() ?? -1;
const gid = process.getgid?.() ?? -1;

function rootSkipReason(): string | null {
  if (launcherSkip) return launcherSkip;
  if (process.env.KEYFLAP_LAUNCH_SUDO !== '1') {
    return 'set KEYFLAP_LAUNCH_SUDO=1 to run the LaunchDaemon checks (uses sudo -n)';
  }
  return run('sudo', ['-n', 'true']).status === 0 ? null : 'sudo -n does not work here';
}

async function waitFor<T>(what: string, probe: () => T | undefined, ms = 15_000): Promise<T> {
  const until = Date.now() + ms;
  for (;;) {
    const v = probe();
    if (v !== undefined) return v;
    if (Date.now() > until) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 100));
  }
}

function connectOnce(
  target: { path: string } | { port: number },
): Promise<{ connectMs: number; totalMs: number; body: string }> {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    let connectMs = -1;
    let body = '';
    const c = 'path' in target ? net.connect(target.path) : net.connect(target.port, '127.0.0.1');
    c.setTimeout(15_000, () => c.destroy(new Error('no reply')));
    c.on('connect', () => {
      connectMs = Date.now() - start;
    });
    c.on('data', (d) => {
      body += d;
    });
    c.on('end', () => resolve({ connectMs, totalMs: Date.now() - start, body }));
    c.on('error', reject);
  });
}

function connectError(path: string): Promise<string | null> {
  return new Promise((resolve) => {
    const c = net.connect(path);
    c.on('connect', () => {
      c.destroy();
      resolve(null);
    });
    c.on('error', (e: NodeJS.ErrnoException) => resolve(e.code ?? e.message));
  });
}

function bindError(port: number): Promise<string | null> {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.on('error', (e: NodeJS.ErrnoException) => resolve(e.code ?? e.message));
    s.listen(port, '127.0.0.1', () => s.close(() => resolve(null)));
  });
}

function freePort(): Promise<number> {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => {
      const { port } = s.address() as net.AddressInfo;
      s.close(() => resolve(port));
    });
  });
}

const cli = (sockets: string[], program: string[]) => [
  ...sockets.flatMap((s) => ['--socket', s]),
  '--',
  ...program,
];
const launch = (sockets: string[], program: string[]) => [LAUNCHER, ...cli(sockets, program)];

class Domain {
  readonly labels: string[] = [];
  readonly target: string;
  readonly dir: string;
  readonly asRoot: boolean;

  constructor(target: string, dir: string, asRoot: boolean) {
    this.target = target;
    this.dir = dir;
    this.asRoot = asRoot;
  }

  launchctl(args: string[]) {
    return this.asRoot ? run('sudo', ['-n', 'launchctl', ...args]) : run('launchctl', args);
  }

  load(name: string, job: { [key: string]: Plist }): { out: string; err: string; label: string } {
    const label = `${LABEL}.${name}`;
    const out = join(this.dir, `${name}.out`);
    const err = join(this.dir, `${name}.err`);
    const file = join(this.dir, `${name}.plist`);
    const doc = plistDocument({
      Label: label,
      StandardOutPath: out,
      StandardErrorPath: err,
      ...job,
    });
    if (this.asRoot) {
      execFileSync('sudo', ['-n', 'install', '-m', '0666', '/dev/null', out]);
      execFileSync('sudo', ['-n', 'install', '-m', '0666', '/dev/null', err]);
      execFileSync('sudo', ['-n', 'tee', file], {
        input: doc,
        stdio: ['pipe', 'ignore', 'inherit'],
      });
    } else {
      writeFileSync(file, doc);
    }
    const r = this.launchctl(['bootstrap', this.target, file]);
    expect(r.status, `bootstrap ${label}: ${r.stderr}`).toBe(0);
    this.labels.push(label);
    return { out, err, label };
  }

  state(label: string): { running: boolean; lastExit: string | null } {
    const text = this.launchctl(['print', `${this.target}/${label}`]).stdout;
    return {
      running: /^\tstate = running$/m.test(text),
      lastExit: /^\tlast exit code = (\d+)$/m.exec(text)?.[1] ?? null,
    };
  }

  exited(label: string): Promise<string> {
    return waitFor(`${label} to exit`, () => {
      const s = this.state(label);
      return !s.running && s.lastExit !== null ? s.lastExit : undefined;
    });
  }

  unloadAll() {
    for (const l of this.labels) this.launchctl(['bootout', `${this.target}/${l}`]);
  }
}

const read = (path: string) => readFileSync(path, 'utf8');

describe('keyflap-launch outside launchd', () => {
  it.skipIf(launcherSkip !== null)(
    `refuses bad arguments and never runs the program (${launcherSkip ?? 'macOS'})`,
    () => {
      const echo = ['/bin/echo', 'RAN'];
      const cases: [string[], string][] = [
        [[], 'no --socket given'],
        [['--bogus', 'x', '--', ...echo], 'usage: keyflap-launch'],
        [cli(['a'], ['bin/echo', 'RAN']), 'program path must be absolute'],
        [cli(['a'], []), 'program path must be absolute'],
        [cli(['a', 'a'], echo), 'socket named twice: a'],
        [cli(['.a'], echo), 'bad socket name'],
        [cli(['a:b'], echo), 'bad socket name'],
        [cli(['x'.repeat(129)], echo), 'bad socket name'],
        [cli(['x'.repeat(128)], echo), `launchd socket ${'x'.repeat(128)}: not in`],
        [
          cli(
            Array.from({ length: 65 }, (_, i) => `s${i}`),
            echo,
          ),
          'too many sockets',
        ],
        [cli(['a'], echo), 'launchd socket a: not in this launchd job'],
      ];
      for (const [args, message] of cases) {
        const r = run(LAUNCHER, args);
        expect(r.status, args.join(' ')).toBe(1);
        expect(r.stdout, args.join(' ')).toBe('');
        expect(r.stderr).toMatch(new RegExp(`^keyflap-launch: ${message}[^\\n]*\\n$`));
      }
    },
  );
});

describe.skipIf(launcherSkip !== null)(
  `keyflap-launch in a per-user launchd domain (${launcherSkip ?? `uid ${uid}`})`,
  () => {
    let domain: Domain;
    let serve: string;

    beforeAll(() => {
      const dir = mkdtempSync(join(tmpdir(), 'keyflap-launch-'));
      serve = join(dir, 'serve.mjs');
      writeFileSync(serve, SERVE);
      const gui = run('launchctl', ['print', `gui/${uid}`]).status === 0;
      domain = new Domain(gui ? `gui/${uid}` : `user/${uid}`, dir, false);
    });

    afterAll(() => {
      domain?.unloadAll();
      if (domain) rmSync(domain.dir, { recursive: true, force: true });
    });

    const serveJob = (name: string, port: number) => {
      const path = join(domain.dir, `${name}.sock`);
      const job = domain.load(name, {
        ProgramArguments: launch(['unix', 'tcp'], [process.execPath, serve]),
        Sockets: {
          unix: { SockPathName: path, SockPathMode: 0o600 },
          tcp: { SockNodeName: '127.0.0.1', SockServiceName: String(port), SockFamily: 'IPv4' },
        },
        ThrottleInterval: 1,
      });
      return { ...job, path };
    };

    it('hands each named socket over at fds 3.. as systemd does, and queues until the program is up', async () => {
      const port = await freePort();
      const job = serveJob('serve', port);
      expect(domain.state(job.label).running, 'launchd starts the job on demand').toBe(false);

      const viaUnix = await connectOnce({ path: job.path });
      expect(viaUnix.connectMs, 'launchd accepted the connection itself').toBeLessThan(500);
      expect(viaUnix.totalMs, 'the reply waited for the program').toBeGreaterThanOrEqual(1000);
      const a = JSON.parse(viaUnix.body);
      const handed = [
        ['unix', 3],
        ['tcp', 4],
      ];
      expect(a, 'signer/src/systemd.ts listenFds reads them').toMatchObject({
        name: 'unix',
        fds: handed,
        uid,
      });

      await domain.exited(job.label);
      const b = JSON.parse((await connectOnce({ port })).body);
      expect(b).toMatchObject({ name: 'tcp', fds: handed, uid });
      expect(b.pid).not.toBe(a.pid);
    });

    it('keeps the listeners while the program is down and relaunches it on the next connection', async () => {
      const port = await freePort();
      const job = serveJob('restart', port);
      const first = JSON.parse((await connectOnce({ port })).body);
      expect(await domain.exited(job.label)).toBe('0');
      expect(await bindError(port), 'launchd still holds the port').toBe('EADDRINUSE');
      const second = JSON.parse((await connectOnce({ port })).body);
      expect(second.pid).not.toBe(first.pid);
      expect(second.name).toBe('tcp');
    });

    it('passes exactly the named sockets, with close-on-exec cleared', async () => {
      const port = await freePort();
      const job = domain.load('fds', {
        ProgramArguments: launch(['first', 'second'], ['/bin/sh', '-c', SHOW_FDS]),
        Sockets: {
          first: { SockPathName: join(domain.dir, 'fds.sock') },
          second: { SockNodeName: '127.0.0.1', SockServiceName: String(port), SockFamily: 'IPv4' },
        },
        RunAtLoad: true,
      });
      expect(await domain.exited(job.label)).toBe('0');
      const [head, ...fds] = read(job.out).trim().split('\n');
      const [pid, listenPid, ...rest] = (head ?? '').split(' ');
      expect(listenPid).toBe(pid);
      expect(rest.slice(0, 2)).toEqual(['2', 'first:second']);
      expect(fds).toEqual(['fd 3', 'fd 4', 'end']);
    });

    it('fails closed without running the program: a name the job lacks, a socket with two fds', async () => {
      const port = await freePort();
      const missing = domain.load('missing', {
        ProgramArguments: launch(['other'], ['/bin/echo', 'RAN']),
        Sockets: { mine: { SockPathName: join(domain.dir, 'missing.sock') } },
        RunAtLoad: true,
      });
      const dual = domain.load('dual', {
        ProgramArguments: launch(['tcp'], ['/bin/echo', 'RAN']),
        Sockets: { tcp: { SockNodeName: 'localhost', SockServiceName: String(port) } },
        RunAtLoad: true,
      });
      expect(await domain.exited(missing.label)).toBe('1');
      expect(await domain.exited(dual.label)).toBe('1');
      expect(read(missing.out) + read(dual.out)).toBe('');
      expect(read(missing.err)).toBe(
        'keyflap-launch: launchd socket other: not in this launchd job\n',
      );
      expect(read(dual.err)).toBe('keyflap-launch: launchd socket tcp: want exactly one fd\n');
    });
  },
);

const rootSkip = rootSkipReason();

describe.skipIf(rootSkip !== null)(
  `keyflap-launch in the system domain, as root's LaunchDaemon (${rootSkip ?? 'sudo'})`,
  () => {
    let domain: Domain;
    let bin: string;

    beforeAll(() => {
      const dir = mkdtempSync(join(tmpdir(), 'keyflap-launch-root-'));
      domain = new Domain('system', dir, true);
      execFileSync('sudo', ['-n', 'chown', 'root:wheel', dir]);
      execFileSync('sudo', ['-n', 'chmod', '0755', dir]);
      bin = join(dir, 'keyflap-launch');
      execFileSync('sudo', ['-n', 'install', '-m', '0755', LAUNCHER, bin]);
    });

    afterAll(() => {
      if (!domain) return;
      domain.unloadAll();
      run('sudo', ['-n', 'rm', '-rf', domain.dir]);
    });

    const asDaemon = (args: string[]) => [bin, ...args.slice(1)];

    it('launchd sets each socket owner, group and mode, and the program runs as UserName', async () => {
      const port = await freePort();
      const sock = (n: string) => join(domain.dir, `${n}.sock`);
      const job = domain.load('daemon', {
        UserName: 'nobody',
        ProgramArguments: asDaemon(
          launch(
            ['admin', 'mine', 'group', 'tcp'],
            ['/bin/sh', '-c', `${SHOW_FDS}; exec /bin/sleep 60`],
          ),
        ),
        Sockets: {
          admin: {
            SockPathName: sock('admin'),
            SockPathOwner: 0,
            SockPathGroup: 0,
            SockPathMode: 0o600,
          },
          mine: {
            SockPathName: sock('mine'),
            SockPathOwner: uid,
            SockPathGroup: 0,
            SockPathMode: 0o600,
          },
          group: {
            SockPathName: sock('group'),
            SockPathOwner: 0,
            SockPathGroup: gid,
            SockPathMode: 0o660,
          },
          tcp: { SockNodeName: '127.0.0.1', SockServiceName: String(port), SockFamily: 'IPv4' },
        },
        RunAtLoad: true,
      });
      const modes = run('stat', ['-f', '%u %g %Lp', sock('admin'), sock('mine'), sock('group')]);
      const [admin, mine, group] = modes.stdout.trim().split('\n');
      expect(admin, 'root owns it, 0600 (launchd ignores SockPathGroup 0)').toMatch(/^0 \d+ 600$/);
      expect(mine).toBe(`${uid} 0 600`);
      expect(group).toBe(`0 ${gid} 660`);
      expect(await connectError(sock('admin')), 'a root:wheel 0600 socket refuses us').toBe(
        'EACCES',
      );
      expect(await connectError(sock('mine'))).toBeNull();
      expect(await connectError(sock('group'))).toBeNull();

      const shown = await waitFor('the program output', () => {
        const text = read(job.out);
        return text.endsWith('end\n') ? text : undefined;
      });
      const [head, ...fds] = shown.trim().split('\n');
      const [pid, listenPid, count, names, user] = (head ?? '').split(' ');
      expect({ listenPid, count, names, user }).toEqual({
        listenPid: pid,
        count: '4',
        names: 'admin:mine:group:tcp',
        user: 'nobody',
      });
      expect(fds).toEqual(['fd 3', 'fd 4', 'fd 5', 'fd 6', 'end']);
    });

    it('refuses to run the program as root, from a LaunchDaemon with no UserName', async () => {
      const port = await freePort();
      const job = domain.load('asroot', {
        ProgramArguments: asDaemon(launch(['tcp'], ['/bin/echo', 'RAN'])),
        Sockets: { tcp: { SockNodeName: '127.0.0.1', SockServiceName: String(port) } },
        RunAtLoad: true,
      });
      const exit = await domain.exited(job.label);
      expect({ exit, out: read(job.out), err: read(job.err) }).toEqual({
        exit: '1',
        out: '',
        err: 'keyflap-launch: refusing to run as root\n',
      });
    });

    it('refuses group 0 as the real or effective group of a non-root user', () => {
      const nobody = Number(run('id', ['-u', 'nobody']).stdout.trim());
      const drop = (setGroups: string) => `
        process.setgroups([]); ${setGroups}; process.setuid(${nobody});
        const r = require('node:child_process').spawnSync(${JSON.stringify(bin)},
          ['--socket', 'a', '--', '/bin/echo', 'RAN'], { encoding: 'utf8' });
        process.stdout.write(JSON.stringify({ status: r.status, out: r.stdout, err: r.stderr }));`;
      for (const setGroups of [
        'process.setgid(0)',
        `process.setgid(${nobody}); process.setegid(0)`,
      ]) {
        const r = run('sudo', ['-n', process.execPath, '-e', drop(setGroups)]);
        expect(JSON.parse(r.stdout), setGroups).toEqual({
          status: 1,
          out: '',
          err: 'keyflap-launch: refusing to run as root\n',
        });
      }
    });
  },
);
