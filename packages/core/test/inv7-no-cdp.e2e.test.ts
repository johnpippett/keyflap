import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, readlinkSync } from 'node:fs';
import { join } from 'node:path';
import { type Browser, chromium } from 'playwright';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { type McpHarness, startMcpHarness } from './mcp-harness.ts';

const EIGHT = [
  'auth_enroll_passkey',
  'auth_login',
  'auth_status',
  'browser_click',
  'browser_handoff',
  'browser_open',
  'browser_snapshot',
  'browser_type',
];

const ppidOf = (pid: number): number | null => {
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, 'utf8');
    const rest = stat.slice(stat.lastIndexOf(')') + 2).split(' ');
    return Number(rest[1]);
  } catch {
    return null;
  }
};

const rawCmdline = (pid: number): string => {
  try {
    return readFileSync(`/proc/${pid}/cmdline`, 'utf8');
  } catch {
    return '';
  }
};

const cmdline = (pid: number): string[] => {
  const args = rawCmdline(pid).split('\0').filter(Boolean);
  if (args.length === 1 && /\s/.test(args[0] as string)) {
    return (args[0] as string).split(/\s+/).filter(Boolean);
  }
  return args;
};

const allPids = (): number[] =>
  readdirSync('/proc')
    .filter((d) => /^\d+$/.test(d))
    .map(Number);

function tree(root: number): number[] {
  const children = new Map<number, number[]>();
  for (const pid of allPids()) {
    const pp = ppidOf(pid);
    if (pp === null) continue;
    children.set(pp, [...(children.get(pp) ?? []), pid]);
  }
  const out: number[] = [];
  const stack = [root];
  while (stack.length > 0) {
    const p = stack.pop() as number;
    out.push(p);
    stack.push(...(children.get(p) ?? []));
  }
  return out;
}

const browserPids = (): number[] =>
  tree(process.pid).filter((pid) => {
    const args = cmdline(pid);
    return (
      !args.some((a) => a.startsWith('--type=')) &&
      args.some((a) => a === '--remote-debugging-pipe' || a.startsWith('--remote-debugging-port'))
    );
  });

function fdTargets(pid: number): Map<number, string> {
  const out = new Map<number, string>();
  let fds: string[] = [];
  try {
    fds = readdirSync(`/proc/${pid}/fd`);
  } catch {
    return out;
  }
  for (const fd of fds) {
    try {
      out.set(Number(fd), readlinkSync(`/proc/${pid}/fd/${fd}`));
    } catch {}
  }
  return out;
}

function listeningTcpInodes(): Map<string, string> {
  const out = new Map<string, string>();
  for (const f of ['/proc/net/tcp', '/proc/net/tcp6']) {
    if (!existsSync(f)) continue;
    for (const line of readFileSync(f, 'utf8').split('\n').slice(1)) {
      const cols = line.trim().split(/\s+/);
      if (cols.length < 10 || cols[3] !== '0A') continue;
      out.set(cols[9] as string, cols[1] as string);
    }
  }
  return out;
}

function listeningSocketsOf(pids: number[]): string[] {
  const listening = listeningTcpInodes();
  const found = new Set<string>();
  for (const pid of pids) {
    for (const target of fdTargets(pid).values()) {
      const m = /^socket:\[(\d+)\]$/.exec(target);
      const addr = m ? listening.get(m[1] as string) : undefined;
      if (addr) found.add(addr);
    }
  }
  return [...found];
}

function unixSockets(): Map<string, { path: string; listening: boolean; state: string }> {
  const out = new Map<string, { path: string; listening: boolean; state: string }>();
  for (const line of readFileSync('/proc/net/unix', 'utf8').split('\n').slice(1)) {
    const cols = line.trim().split(/\s+/);
    if (cols.length < 7) continue;
    out.set(cols[6] as string, {
      path: cols[7] ?? '',
      listening: (Number.parseInt(cols[3] as string, 16) & 0x10000) !== 0,
      state: cols[5] as string,
    });
  }
  return out;
}

const userDataDir = (pid: number): string | undefined =>
  cmdline(pid)
    .find((a) => a.startsWith('--user-data-dir='))
    ?.slice('--user-data-dir='.length);

interface PsRow {
  ppid: number;
  raw: string;
  args: string[];
}

function psTable(): Map<number, PsRow> {
  const r = spawnSync('/bin/ps', ['-A', '-ww', '-o', 'pid=,ppid=,command='], {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  if (r.status !== 0) throw new Error(`ps failed: ${r.error ?? r.stderr}`);
  const out = new Map<number, PsRow>();
  for (const line of r.stdout.split('\n')) {
    const m = /^\s*(\d+)\s+(\d+)\s(.*)$/.exec(line);
    if (!m) continue;
    const raw = m[3] as string;
    out.set(Number(m[1]), { ppid: Number(m[2]), raw, args: raw.split(/\s+/).filter(Boolean) });
  }
  return out;
}

function psTree(root: number, rows: Map<number, PsRow>): number[] {
  const children = new Map<number, number[]>();
  for (const [pid, r] of rows) children.set(r.ppid, [...(children.get(r.ppid) ?? []), pid]);
  const out: number[] = [];
  const stack = [root];
  while (stack.length > 0) {
    const p = stack.pop() as number;
    out.push(p);
    stack.push(...(children.get(p) ?? []));
  }
  return out;
}

const psBrowserPids = (): number[] => {
  const rows = psTable();
  return psTree(process.pid, rows).filter((pid) => {
    const args = rows.get(pid)?.args ?? [];
    return (
      !args.some((a) => a.startsWith('--type=')) &&
      args.some((a) => a === '--remote-debugging-pipe' || a.startsWith('--remote-debugging-port'))
    );
  });
};

function lsofListening(pids: number[]): string[] {
  const r = spawnSync(
    '/usr/sbin/lsof',
    ['-nP', '-a', '-p', pids.join(','), '-iTCP', '-sTCP:LISTEN', '-Fn'],
    { encoding: 'utf8' },
  );
  if (r.error) throw r.error;
  if (r.status !== 0 && !(r.status === 1 && r.stdout.trim() === '')) {
    throw new Error(`lsof failed (${r.status}): ${r.stderr}`);
  }
  return r.stdout
    .split('\n')
    .filter((l) => l.startsWith('n'))
    .map((l) => l.slice(1));
}

const psUserDataDir = (pid: number): string | undefined =>
  psTable()
    .get(pid)
    ?.args.find((a) => a.startsWith('--user-data-dir='))
    ?.slice('--user-data-dir='.length);

describe('invariant 7: the agent has no raw CDP access, only the eight mediated tools', () => {
  let h: McpHarness;

  beforeAll(async () => {
    h = await startMcpHarness({ agentName: 'inv7-agent', daemon: { actionTimeoutMs: 1000 } });
    const ctx = await h.context();
    await ctx.route(/\/inv7$/, (route) =>
      route.fulfill({
        contentType: 'text/html',
        body: `<!doctype html><title>inv7</title><body>
          <button id="b" onclick="window.clicks=(window.clicks||0)+1">Press</button>
          <input id="i" aria-label="Field"></body>`,
      }),
    );
  });
  afterAll(async () => h?.close());

  describe('MCP surface', () => {
    it('tools/list is exactly the eight tools; only the tools capability is offered', async () => {
      const tools = await h.mcp.listTools();
      expect(tools.map((t) => t.name).sort()).toEqual(EIGHT);
      const caps = h.mcp.client.getServerCapabilities() ?? {};
      expect(Object.keys(caps).filter((k) => k !== 'tools')).toEqual([]);
    });

    it('no schema has a script, evaluate, CDP, selector-engine or similar field', async () => {
      const tools = await h.mcp.listTools();
      const keys = new Set<string>();
      const walk = (s: unknown) => {
        if (typeof s !== 'object' || s === null) return;
        const o = s as Record<string, unknown>;
        if (o.properties && typeof o.properties === 'object') {
          for (const [k, v] of Object.entries(o.properties as Record<string, unknown>)) {
            keys.add(k);
            walk(v);
          }
        }
        for (const k of ['anyOf', 'oneOf', 'allOf'])
          if (Array.isArray(o[k])) (o[k] as unknown[]).forEach(walk);
        if (o.items) walk(o.items);
      };
      for (const t of tools) walk(t.inputSchema);
      expect([...keys].sort()).toEqual(
        [
          'css',
          'exact',
          'label',
          'name',
          'placeholder',
          'role',
          'submit',
          'target',
          'text',
          'timeoutMs',
          'url',
        ].sort(),
      );
      for (const k of keys) {
        expect(k).not.toMatch(
          /script|eval|cdp|devtools|debug|selector|engine|xpath|expression|function|code|frame|session|ws|endpoint/i,
        );
      }
    });

    it('unknown tools (evaluate, CDP, ...) are refused and never reach the browser', async () => {
      const toolCalls = () => h.auditEvents().filter((e) => e.type === 'tool.call').length;
      const before = toolCalls();
      for (const name of [
        'browser_evaluate',
        'browser_run_code',
        'browser_cdp',
        'cdp_send',
        'Runtime.evaluate',
        'Target.attachToTarget',
        'browser_new_cdp_session',
        'BROWSER_OPEN',
        'browser_open ',
      ]) {
        await expect(
          h.mcp.client.callTool({ name, arguments: { expression: '1' } }),
          name,
        ).rejects.toThrow(/unknown tool/);
      }
      expect(toolCalls()).toBe(before);
    });

    it('browser_open refuses every non-http(s) scheme, and the page does not move', async () => {
      await h.mcp.ok('browser_open', { url: `${h.rp.url}inv7` });
      const before = h.page().url();
      for (const url of [
        'javascript:alert(1)',
        'JAVASCRIPT:alert(1)',
        ' javascript:alert(1)',
        'java\nscript:alert(1)',
        'data:text/html,<script>alert(1)</script>',
        'file:///etc/passwd',
        'chrome://version',
        'chrome://inspect',
        'chrome-untrusted://terminal/',
        'devtools://devtools/bundled/inspector.html',
        'about:blank',
        'about:srcdoc',
        'view-source:http://rp.localhost/',
        'chrome-extension://abcdefghijklmnop/x.html',
        'blob:http://rp.localhost/1234',
        'filesystem:http://rp.localhost/temporary/x',
        'ws://127.0.0.1:9222/devtools/browser',
        'wss://rp.localhost/',
        'ftp://example.com/',
        'intent://x#Intent;end',
        'jar:file:///x!/y',
        '//rp.localhost/',
        '/relative',
      ]) {
        const msg = await h.mcp.err('browser_open', { url });
        expect(msg, url).toMatch(/only http and https|not a valid absolute URL/);
      }
      expect(h.page().url()).toBe(before);
    });

    it('css locators naming a selector engine (or chaining with >>) are refused', async () => {
      await h.mcp.ok('browser_open', { url: `${h.rp.url}inv7` });
      for (const css of [
        'xpath=//button',
        'XPATH=//button',
        '  xpath=//button',
        'text=Press',
        'css=#b',
        'id=b',
        'internal:role=button',
        'internal:control=enter-frame',
        'internal:attr=[aria-label="Field"]',
        '_react=App',
        '_vue=App',
        'nth=0',
        'visible=true',
        '#b >> nth=0',
        '#b >> xpath=..',
        'button>>text=Press',
        '//button',
        '..',
        '"Press"',
        "'Press'",
        '`Press`',
      ]) {
        const msg = await h.mcp.err('browser_click', { target: { css } });
        expect(msg, css).toMatch(/plain CSS/);
        const typed = await h.mcp.err('browser_type', { target: { css }, text: 'x' });
        expect(typed, css).toMatch(/plain CSS/);
      }
      expect(
        await h.page().evaluate(() => (window as unknown as { clicks?: number }).clicks ?? 0),
      ).toBe(0);
      await h.mcp.ok('browser_click', { target: { css: 'button#b' } });
      expect(await h.page().evaluate(() => (window as unknown as { clicks?: number }).clicks)).toBe(
        1,
      );
    });
  });

  describe('the managed Chromium (Linux /proc)', () => {
    let ours: number;

    beforeAll(() => {
      if (process.platform !== 'linux') return;
      const pids = browserPids();
      expect(pids).toHaveLength(1);
      ours = pids[0] as number;
    });

    it.runIf(process.platform === 'linux')(
      'is driven over --remote-debugging-pipe, with no --remote-debugging-port',
      () => {
        expect(cmdline(ours)).toContain('--remote-debugging-pipe');
        const raw = rawCmdline(ours);
        expect(raw).toContain('--remote-debugging-pipe');
        expect(raw).not.toContain('--remote-debugging-port');
        expect(raw).not.toContain('--remote-debugging-address');
        for (const pid of tree(ours)) {
          expect(rawCmdline(pid), String(pid)).not.toContain('--remote-debugging-port');
          expect(rawCmdline(pid), String(pid)).not.toContain('--remote-debugging-address');
        }
      },
    );

    it.runIf(process.platform === 'linux')(
      'its CDP channel (fds 3 and 4) is an unnamed, connected socketpair only it holds',
      () => {
        const fds = fdTargets(ours);
        const unix = unixSockets();
        for (const fd of [3, 4]) {
          const m = /^socket:\[(\d+)\]$/.exec(fds.get(fd) ?? '');
          expect(m, `fd ${fd}: ${fds.get(fd)}`).not.toBeNull();
          const entry = unix.get((m as RegExpExecArray)[1] as string);
          expect(entry, `fd ${fd} is a unix socket`).toBeDefined();
          expect(entry?.path, `fd ${fd} has no filesystem name`).toBe('');
          expect(entry?.listening, `fd ${fd} is not listening`).toBe(false);
          expect(entry?.state, `fd ${fd} is connected`).toBe('03');
          const target = fds.get(fd) as string;
          const browserTree = new Set(tree(ours));
          for (const pid of allPids()) {
            if (browserTree.has(pid)) continue;
            const held = [...fdTargets(pid).values()].includes(target);
            expect(held, `pid ${pid} holds the browser's end of fd ${fd}`).toBe(false);
          }
        }
      },
    );

    it.runIf(process.platform === 'linux')('wrote no DevToolsActivePort file', () => {
      const dir = userDataDir(ours);
      expect(dir).toBeTruthy();
      expect(existsSync(dir as string)).toBe(true);
      expect(existsSync(join(dir as string, 'DevToolsActivePort'))).toBe(false);
    });

    it.runIf(process.platform === 'linux')(
      'no process of the browser tree has a listening TCP socket',
      async () => {
        await h.mcp.ok('browser_open', { url: `${h.rp.url}login` });
        await h.mcp.ok('browser_snapshot');
        const pids = tree(ours);
        expect(pids.length).toBeGreaterThan(1);
        expect(listeningSocketsOf(pids)).toEqual([]);
        const mcpPort = Number(new URL(h.mcpUrl).port).toString(16).toUpperCase().padStart(4, '0');
        expect(listeningSocketsOf([process.pid]).some((a) => a.endsWith(`:${mcpPort}`))).toBe(true);
      },
    );

    describe.runIf(process.platform === 'linux')(
      'control: a debuggable Chromium is detected',
      () => {
        let debuggable: Browser;
        let pid: number;

        beforeAll(async () => {
          const before = new Set(browserPids());
          debuggable = await chromium.launch({ args: ['--remote-debugging-port=0'] });
          const added = browserPids().filter((p) => !before.has(p));
          expect(added).toHaveLength(1);
          pid = added[0] as number;
        });
        afterAll(async () => debuggable?.close());

        it('the same checks flag its port, its listener and its DevToolsActivePort file', () => {
          expect(cmdline(pid).some((a) => a.startsWith('--remote-debugging-port'))).toBe(true);
          expect(rawCmdline(pid)).toContain('--remote-debugging-port');
          expect(listeningSocketsOf(tree(pid)).length).toBeGreaterThan(0);
          const dir = userDataDir(pid) as string;
          expect(existsSync(join(dir, 'DevToolsActivePort'))).toBe(true);
          expect(listeningSocketsOf(tree(ours))).toEqual([]);
        });
      },
    );
  });

  describe.runIf(process.platform === 'darwin')('the managed Chromium (macOS ps / lsof)', () => {
    let ours: number;

    beforeAll(() => {
      const pids = psBrowserPids();
      expect(pids).toHaveLength(1);
      ours = pids[0] as number;
    });

    it('is driven over --remote-debugging-pipe, with no --remote-debugging-port', () => {
      const rows = psTable();
      const raw = rows.get(ours)?.raw ?? '';
      expect(raw).toContain('--remote-debugging-pipe');
      for (const pid of psTree(ours, rows)) {
        const r = rows.get(pid)?.raw ?? '';
        expect(r, String(pid)).not.toContain('--remote-debugging-port');
        expect(r, String(pid)).not.toContain('--remote-debugging-address');
      }
    });

    it('wrote no DevToolsActivePort file', () => {
      const dir = psUserDataDir(ours);
      expect(dir).toBeTruthy();
      expect(existsSync(dir as string)).toBe(true);
      expect(existsSync(join(dir as string, 'DevToolsActivePort'))).toBe(false);
    });

    it('no process of the browser tree has a listening TCP socket', async () => {
      await h.mcp.ok('browser_open', { url: `${h.rp.url}login` });
      await h.mcp.ok('browser_snapshot');
      const pids = psTree(ours, psTable());
      expect(pids.length).toBeGreaterThan(1);
      expect(lsofListening(pids)).toEqual([]);
      const mcpPort = new URL(h.mcpUrl).port;
      expect(lsofListening([process.pid]).some((a) => a.endsWith(`:${mcpPort}`))).toBe(true);
    });

    describe('control: a debuggable Chromium is detected', () => {
      let debuggable: Browser;
      let pid: number;

      beforeAll(async () => {
        const before = new Set(psBrowserPids());
        debuggable = await chromium.launch({ args: ['--remote-debugging-port=0'] });
        const added = psBrowserPids().filter((p) => !before.has(p));
        expect(added).toHaveLength(1);
        pid = added[0] as number;
      });
      afterAll(async () => debuggable?.close());

      it('the same checks flag its port, its listener and its DevToolsActivePort file', () => {
        expect(psTable().get(pid)?.raw).toContain('--remote-debugging-port');
        expect(lsofListening(psTree(pid, psTable())).length).toBeGreaterThan(0);
        const dir = psUserDataDir(pid) as string;
        expect(existsSync(join(dir, 'DevToolsActivePort'))).toBe(true);
        expect(lsofListening(psTree(ours, psTable()))).toEqual([]);
      });
    });
  });
});
