import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';

const JXA = `
ObjC.bindFunction('task_for_pid', ['int', ['unsigned int', 'int', 'unsigned int *']]);
ObjC.bindFunction('mach_task_self', ['unsigned int', []]);
ObjC.bindFunction('getpid', ['int', []]);
function run(argv) {
  const out = {};
  for (const p of argv) {
    const pid = p === 'self' ? $.getpid() : Number(p);
    out[p] = $.task_for_pid($.mach_task_self(), pid, Ref('I'));
  }
  return JSON.stringify(out);
}`;

const targets = process.argv.slice(2).map(Number);
const marker = `keyflap-probe-${randomBytes(8).toString('hex')}`;
const child = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 120000)'], {
  env: { ...process.env, KEYFLAP_PROBE_MARKER: marker },
  stdio: 'ignore',
});
await new Promise((r) => setTimeout(r, 500));

const run = (cmd: string, args: string[]) => {
  const r = spawnSync(cmd, args, { encoding: 'utf8', timeout: 60_000, maxBuffer: 64 << 20 });
  return { status: r.status, out: `${r.stdout ?? ''}${r.stderr ?? ''}` };
};

const denied = (out: string) => /do not have appropriate privileges/.test(out);

function memoryTool(cmd: string, args: string[], pid: number, works: RegExp): string {
  const r = run(cmd, args);
  if (r.status === 0 && works.test(r.out) && r.out.includes(String(pid))) return 'ok';
  if (denied(r.out)) return 'denied';
  return `unexpected: status ${r.status}: ${r.out.slice(0, 200)}`;
}

function signal(pid: number): string {
  try {
    process.kill(pid, 0);
    return 'ok';
  } catch (e) {
    return (e as NodeJS.ErrnoException).code ?? String(e);
  }
}

function environment(pid: number, own: boolean): string {
  const withEnv = run('/bin/ps', ['eww', '-o', 'command=', '-p', String(pid)]).out.trim();
  const argv = run('/bin/ps', ['ww', '-o', 'command=', '-p', String(pid)]).out.trim();
  if (!argv) return 'no such process';
  if (own) return withEnv.includes(`KEYFLAP_PROBE_MARKER=${marker}`) ? 'ok' : 'hidden';
  return withEnv === argv ? 'denied' : 'visible';
}

function lsof(pid: number): string {
  const r = run('/usr/sbin/lsof', ['-p', String(pid), '-Fn']);
  return r.out.split('\n').some((l) => l.startsWith('n')) ? 'ok' : 'denied';
}

const tfp = JSON.parse(
  run('/usr/bin/osascript', ['-l', 'JavaScript', '-e', JXA, 'self', ...targets.map(String)]).out,
) as Record<string, number>;
const kr = (k: string) => (tfp[k] === 0 ? 'ok' : `kr=${tfp[k]}`);

function view(pid: number, own: boolean, taskForPid: string) {
  return {
    vmmap: memoryTool('/usr/bin/vmmap', ['-summary', String(pid)], pid, /Process:/),
    sample: memoryTool(
      '/usr/bin/sample',
      [String(pid), '1', '-file', '/dev/null'],
      pid,
      /Sampling process/,
    ),
    lsof: lsof(pid),
    signal: signal(pid),
    environment: environment(pid, own),
    taskForPid,
  };
}

const ownPid = child.pid as number;
const out = {
  control: view(ownPid, true, kr('self')),
  targets: Object.fromEntries(targets.map((p) => [String(p), view(p, false, kr(String(p)))])),
};
child.kill();
process.stdout.write(`${JSON.stringify(out)}\n`);
