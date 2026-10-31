import { type ChildProcess, spawn } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { MAIN, runCli, tmpDir } from './helpers.ts';

const PASSPHRASE = 'e2e-passphrase-0d5b';
const TOKEN_RE = /aab_agent_[A-Za-z0-9_-]{43}/;

function mcpInitialize(url: string, token: string): Promise<number> {
  return fetch(url, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: '2025-06-18',
        capabilities: {},
        clientInfo: { name: 'e2e', version: '1' },
      },
    }),
  }).then(async (r) => {
    await r.body?.cancel();
    return r.status;
  });
}

function descendants(root: number): number[] {
  const children = new Map<number, number[]>();
  for (const name of readdirSync('/proc')) {
    if (!/^\d+$/.test(name)) continue;
    try {
      const stat = readFileSync(`/proc/${name}/stat`, 'utf8');
      const ppid = Number(stat.slice(stat.lastIndexOf(')') + 2).split(' ')[1]);
      const list = children.get(ppid) ?? [];
      list.push(Number(name));
      children.set(ppid, list);
    } catch {}
  }
  const out: number[] = [];
  const walk = (p: number) => {
    for (const c of children.get(p) ?? []) {
      out.push(c);
      walk(c);
    }
  };
  walk(root);
  return out;
}

describe('keyflap daemon (e2e)', () => {
  let dir: string;
  let daemon: ChildProcess;
  let stderr = '';
  let mcpUrl: string;
  let socketPath: string;

  beforeAll(async () => {
    dir = tmpDir();
    daemon = spawn(
      process.execPath,
      [MAIN, 'daemon', '--unprotected', '--data-dir', dir, '--mcp-port', '0'],
      {
        env: { ...process.env, KEYFLAP_PASSPHRASE: PASSPHRASE },
        stdio: ['pipe', 'pipe', 'pipe'],
      },
    );
    daemon.stderr?.on('data', (c: Buffer) => {
      stderr += c.toString();
    });
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`daemon did not start:\n${stderr}`)), 45_000);
      const check = () => {
        if (/Ctrl-C to stop/.test(stderr)) {
          clearTimeout(timer);
          resolve();
        }
      };
      daemon.stderr?.on('data', check);
      daemon.once('exit', (code) => {
        clearTimeout(timer);
        reject(new Error(`daemon exited ${code}:\n${stderr}`));
      });
    });
    mcpUrl = (/MCP endpoint:\s+(\S+)/.exec(stderr) as RegExpExecArray)[1] as string;
    socketPath = (/intent socket:\s+(\S+)/.exec(stderr) as RegExpExecArray)[1] as string;
  });

  afterAll(async () => {
    if (daemon.exitCode === null && daemon.signalCode === null) {
      daemon.kill('SIGKILL');
      await new Promise((r) => daemon.once('exit', r));
    }
    rmSync(dir, { recursive: true, force: true });
  });

  it('prints the MCP URL and intent socket path, never the passphrase', () => {
    expect(mcpUrl).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/mcp$/);
    expect(socketPath).toBe(join(dir, 'run', 'intent.sock'));
    expect(existsSync(socketPath)).toBe(true);
    expect(stderr).not.toContain(PASSPHRASE);
  });

  it('same-user mode says it is unprotected and audits it', () => {
    expect(stderr).toMatch(/UNPROTECTED: this broker runs as your OS user/);
    const db = new DatabaseSync(join(dir, 'broker.sqlite'), { readOnly: true });
    try {
      const rows = db.prepare("SELECT 1 FROM audit WHERE event_type = 'daemon.unprotected'").all();
      expect(rows.length).toBe(1);
    } finally {
      db.close();
    }
  });

  it.runIf(existsSync('/proc/self/environ'))(
    'the passphrase is in no child process environment (signer, Chromium)',
    () => {
      const pids = descendants(daemon.pid as number);
      expect(pids.length).toBeGreaterThan(1);
      const leaking: number[] = [];
      for (const pid of pids) {
        try {
          if (readFileSync(`/proc/${pid}/environ`, 'utf8').includes(PASSPHRASE)) leaking.push(pid);
        } catch {}
      }
      expect(leaking).toEqual([]);
    },
  );

  it('agent add while running → MCP accepts the token; hook records the intent; revoke cuts both', async () => {
    const added = await runCli(['agent', 'add', 'claude-code', '--data-dir', dir]);
    expect(added.code).toBe(0);
    const token = (TOKEN_RE.exec(added.stdout) as RegExpExecArray)[0];
    const agentId = (/--agent ([0-9a-f-]{36})/.exec(added.stdout) as RegExpExecArray)[1] as string;

    expect(await mcpInitialize(mcpUrl, token)).toBe(200);

    const prompt = 'sign in to the test RP for me';
    const hook = await runCli(['hook', 'claude-code', '--agent', agentId, '--data-dir', dir], {
      input: JSON.stringify({ hook_event_name: 'UserPromptSubmit', prompt }),
    });
    expect(hook).toMatchObject({ code: 0, stdout: '', stderr: '' });

    const db = new DatabaseSync(join(dir, 'broker.sqlite'), { readOnly: true });
    try {
      expect(db.prepare('SELECT agent_id, text FROM intents').all()).toEqual([
        { agent_id: agentId, text: prompt },
      ]);
      const types = (
        db.prepare('SELECT event_type FROM audit ORDER BY seq').all() as { event_type: string }[]
      ).map((r) => r.event_type);
      expect(types).toEqual(expect.arrayContaining(['agent.added', 'intent.recorded']));
    } finally {
      db.close();
    }

    const revoked = await runCli(['agent', 'revoke', agentId, '--data-dir', dir]);
    expect(revoked.code).toBe(0);
    expect(await mcpInitialize(mcpUrl, token)).toBe(401);
    const after = await runCli(['hook', 'claude-code', '--agent', agentId, '--data-dir', dir], {
      input: JSON.stringify({ prompt: 'again' }),
    });
    expect(after.code).toBe(0);
    expect(after.stdout).toBe('');
    expect(after.stderr).toMatch(/404/);
  });

  it('a second daemon on the same data dir refuses to start', async () => {
    const r = await runCli(['daemon', '--unprotected', '--data-dir', dir, '--mcp-port', '0'], {
      env: { KEYFLAP_PASSPHRASE: PASSPHRASE },
    });
    expect(r.code).toBe(1);
    expect(r.stderr).toMatch(/^keyflap: /m);
  });

  it('without --unprotected it refuses to start, before asking for a passphrase', async () => {
    const r = await runCli(['daemon', '--data-dir', tmpDir()], {
      env: { KEYFLAP_PASSPHRASE: PASSPHRASE },
    });
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/Pass --unprotected/);
  });

  it('without KEYFLAP_PASSPHRASE and without a TTY it refuses to start', async () => {
    const r = await runCli(['daemon', '--unprotected', '--data-dir', tmpDir()], {
      env: { KEYFLAP_PASSPHRASE: undefined },
    });
    expect(r.code).toBe(1);
    expect(r.stderr).toMatch(/set KEYFLAP_PASSPHRASE or run keyflap in a terminal/);
  });

  it('SIGINT shuts down cleanly: exit 0, sockets removed', async () => {
    const exited = new Promise<number | null>((r) => daemon.once('exit', (code) => r(code)));
    daemon.kill('SIGINT');
    expect(await exited).toBe(0);
    expect(existsSync(socketPath)).toBe(false);
    expect(existsSync(join(dir, 'run', 'signer.sock'))).toBe(false);
  });
});
