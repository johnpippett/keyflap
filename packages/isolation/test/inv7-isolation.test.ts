import { describe, expect, it } from 'vitest';
import {
  host,
  inspectProcesses,
  outcomes,
  pids,
  probe,
  ptrace,
  skipReason,
  whereOn,
} from './helpers.ts';
import { L } from './platform.ts';

function listeningPorts(): number[] {
  const c = host();
  const ports = new Set<number>();
  for (const f of ['/proc/net/tcp', '/proc/net/tcp6']) {
    const text = c.as('agentuser', ['cat', f]).stdout;
    for (const line of text.split('\n').slice(1)) {
      const cols = line.trim().split(/\s+/);
      if (cols[3] !== '0A') continue;
      const port = Number.parseInt((cols[1] ?? '').split(':')[1] ?? '', 16);
      if (Number.isInteger(port)) ports.add(port);
    }
  }
  return [...ports].sort((a, b) => a - b);
}

function darwinListeners(): { pid: number; user: string; addr: string }[] {
  const out = host().exec(['lsof', '-nP', '-iTCP', '-sTCP:LISTEN', '-FpLn'], {
    check: true,
  }).stdout;
  const rows: { pid: number; user: string; addr: string }[] = [];
  let pid = 0;
  let user = '';
  for (const line of out.split('\n')) {
    if (line.startsWith('p')) pid = Number(line.slice(1));
    else if (line.startsWith('L')) user = line.slice(1);
    else if (line.startsWith('n')) rows.push({ pid, user, addr: line.slice(1) });
  }
  return rows;
}

describe.skipIf(skipReason !== null || L.os !== 'darwin')(
  `invariant 7: service mode (${whereOn('darwin')})`,
  () => {
    it('the managed Chromium is driven over a pipe and no port speaks DevTools', () => {
      const h = host();
      const { chromium } = pids();
      const cmdline = h.exec(['ps', '-ww', '-o', 'command=', '-p', String(chromium)], {
        check: true,
      }).stdout;
      expect(cmdline).toContain('--remote-debugging-pipe');
      expect(cmdline).not.toContain('--remote-debugging-port');
      expect(h.exec(['ps', '-o', 'user=', '-p', String(chromium)]).stdout.trim()).toBe(
        L.users.core,
      );

      const tree = h
        .exec(['ps', '-axww', '-o', 'pid=,user=,command='], { check: true })
        .stdout.split('\n')
        .map((l) => l.trim().split(/\s+/))
        .filter(
          ([, user, cmd]) => user === L.users.core && cmd?.startsWith('/opt/keyflap/browsers/'),
        )
        .map(([pid]) => Number(pid));
      expect(tree).toContain(chromium);
      expect(tree.length).toBeGreaterThan(1);
      const listeners = darwinListeners();
      expect(listeners.filter((l) => tree.includes(l.pid))).toEqual([]);

      const ours = listeners.filter((l) => Object.values(L.users).includes(l.user));
      const ports = [...new Set(ours.map((l) => Number(l.addr.split(':').pop())))].sort(
        (a, b) => a - b,
      );
      expect(ports).toEqual([8765, 8766]);
      const res = probe(ports.map((port) => ({ kind: 'devtools' as const, port })));
      for (const r of res) expect.soft(r.ok, `port ${JSON.stringify(r.attempt)}`).toBe(false);
    });

    it("the user uid can't borrow the browser's pipe, memory or process", () => {
      const { chromium } = pids();
      const r = outcomes({
        profile: { kind: 'list', path: L.browserProfile },
        home: { kind: 'list', path: '/Library/Keyflap/data/core' },
      });
      expect(r).toEqual({ profile: 'EACCES', home: 'EACCES' });
      const { control, targets } = inspectProcesses([chromium]);
      expect(control.lsof).toBe('ok');
      expect(control.taskForPid).toBe('ok');
      expect(targets[String(chromium)]).toEqual({
        vmmap: 'denied',
        sample: 'denied',
        lsof: 'denied',
        signal: 'EPERM',
        environment: 'denied',
        taskForPid: 'kr=5',
      });
    });

    it('the browser runs headless with its own sandbox, so there is no display to reach', () => {
      const { chromium } = pids();
      const cmdline = host().exec(['ps', '-ww', '-o', 'command=', '-p', String(chromium)], {
        check: true,
      }).stdout;
      expect(cmdline).toContain('--headless');
      expect(cmdline).not.toContain('--no-sandbox');
      expect(cmdline).toContain('chromium-1248/chrome-mac-arm64/Google Chrome for Testing.app');
    });
  },
);

describe.skipIf(skipReason !== null || L.os !== 'linux')(
  `invariant 7: service mode (${whereOn('linux')})`,
  () => {
    it('the managed Chromium is driven over a pipe and no port speaks DevTools', () => {
      const c = host();
      const cmdline = c
        .as('agentuser', ['cat', `/proc/${pids().chromium}/cmdline`])
        .stdout.split('\0');
      expect(cmdline).toContain('--remote-debugging-pipe');
      expect(cmdline.some((a) => a.startsWith('--remote-debugging-port'))).toBe(false);
      expect(c.exec(['stat', '-c', '%U', `/proc/${pids().chromium}`]).stdout.trim()).toBe(
        'keyflap-core',
      );

      const ports = listeningPorts();
      expect(ports).toEqual(expect.arrayContaining([8765, 8766]));
      const res = probe(ports.map((port) => ({ kind: 'devtools' as const, port })));
      for (const r of res) expect.soft(r.ok, `port ${JSON.stringify(r.attempt)}`).toBe(false);
    });

    it("the user uid can't borrow the browser's pipe, memory or process", () => {
      const { chromium } = pids();
      const r = outcomes({
        fds: { kind: 'list', path: `/proc/${chromium}/fd` },
        fd3: { kind: 'open', path: `/proc/${chromium}/fd/3` },
        mem: { kind: 'open', path: `/proc/${chromium}/mem` },
        profile: { kind: 'list', path: '/var/lib/keyflap/core/.config' },
      });
      expect(r).toEqual({ fds: 'EACCES', fd3: 'EACCES', mem: 'EACCES', profile: 'EACCES' });
      const t = ptrace([chromium]);
      expect(t.control).toBe('ok');
      expect(t[String(chromium)]).toBe('EPERM');
    });

    it('the private X display is unreachable from the user uid', () => {
      const c = host();
      const { xvfb } = pids();
      const xcmd = c.exec(['cat', `/proc/${xvfb}/cmdline`]).stdout.split('\0');
      const display = xcmd.find((a) => /^:\d+$/.test(a)) as string;
      const n = display.slice(1);
      const r = outcomes({
        abstract: { kind: 'connect', path: `\0/tmp/.X11-unix/X${n}` },
        path: { kind: 'connect', path: `/tmp/.X11-unix/X${n}` },
        tcp: { kind: 'tcp', port: 6000 + Number(n) },
        xvfbFds: { kind: 'list', path: `/proc/${xvfb}/fd` },
      });
      expect(r.abstract).toBe('ECONNREFUSED');
      expect(r.tcp).toBe('ECONNREFUSED');
      expect(r.path).toBe('ENOENT');
      expect(r.xvfbFds).toBe('EACCES');
      const unix = c.exec(['cat', '/proc/net/unix']).stdout;
      expect(unix).toContain(`/tmp/.X11-unix/X${n}`);
      expect(unix).not.toContain(`@/tmp/.X11-unix/X${n}`);
      expect(xcmd).toEqual(expect.arrayContaining(['-nolisten', 'tcp', 'local', '-auth']));
      expect(c.exec(['test', '-e', `/tmp/.X11-unix/X${n}`]).status).not.toBe(0);
    });
  },
);
