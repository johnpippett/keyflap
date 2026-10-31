import { execFileSync } from 'node:child_process';
import {
  chmodSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { createServer } from 'node:net';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { connectAgent, type McpAgent } from '../../core/test/mcp-harness.ts';
import { type SimulatedPhone, startSimulatedPhone } from '../../core/test/phone-sim.ts';
import { startTestRp, type TestRp } from '../../test-rp/src/index.ts';
import { inspectClaude, parseJsonFile } from '../src/setup/claude-config.ts';
import { MAIN, runCli, tmpDir } from './helpers.ts';
import { PtySession } from './pty.ts';

const PASSPHRASE = 'setup-e2e-passphrase-7Qx';
const PASSWORD = 'setup-e2e-alice-pw-4Lm!';
const SEED = 'KRSXG5CTMVRXEZLUKN2XAZLSKNSWK3TU';
const TOKEN_RE = /aab_agent_[A-Za-z0-9_-]{43}/g;

function freePort(): Promise<number> {
  return new Promise((resolve) => {
    const s = createServer().listen(0, '127.0.0.1', () => {
      const p = (s.address() as { port: number }).port;
      s.close(() => resolve(p));
    });
  });
}

function filesUnder(dir: string): string[] {
  const out: string[] = [];
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) out.push(...filesUnder(p));
    else if (e.isFile()) out.push(p);
  }
  return out;
}

describe('keyflap setup --unprotected (e2e)', () => {
  const home = tmpDir();
  const project = join(home, 'proj');
  const bin = join(home, 'bin');
  const dataDir = join(home, '.keyflap');
  const fakeLog = join(home, 'fake-calls.log');
  let rp: TestRp;
  let phone: SimulatedPhone;
  let session: PtySession;
  let mcp: McpAgent | null = null;
  let env: Record<string, string>;
  let origin: string;
  let mcpPort: number;

  beforeAll(async () => {
    mkdirSync(project);
    mkdirSync(bin);
    const fake = (name: string, body: string) => {
      writeFileSync(join(bin, name), `#!/bin/sh\necho "${name} $*" >> '${fakeLog}'\n${body}\n`);
      chmodSync(join(bin, name), 0o755);
    };
    fake(
      'tailscale',
      `case "$1" in status) echo '{"BackendState":"NeedsLogin","Self":{}}';; *) exit 1;; esac`,
    );
    fake('systemctl', 'echo "0 unit files listed."; exit 1');
    rp = await startTestRp({
      host: 'rp.localhost',
      users: [{ username: 'alice', password: PASSWORD, totpSecret: SEED }],
    });
    phone = await startSimulatedPhone();
    const approverPort = await freePort();
    mcpPort = await freePort();
    origin = `http://approver.localhost:${approverPort}`;
    env = {
      HOME: home,
      PATH: `${bin}:${dirname(process.execPath)}`,
      TERM: 'dumb',
      PLAYWRIGHT_BROWSERS_PATH:
        process.env.PLAYWRIGHT_BROWSERS_PATH ??
        (process.platform === 'darwin'
          ? join(homedir(), 'Library', 'Caches', 'ms-playwright')
          : join(homedir(), '.cache', 'ms-playwright')),
    };
  });

  afterAll(async () => {
    await mcp?.close();
    if (
      session &&
      (await Promise.race([session.exited, Promise.resolve('running')])) === 'running'
    ) {
      session.send('\u0003');
      await Promise.race([session.exited, new Promise((r) => setTimeout(r, 15_000))]);
    }
    await phone?.close();
    await rp?.close();
    rmSync(home, { recursive: true, force: true });
  });

  it('walks a newcomer from nothing to a working, signed-in agent', {
    timeout: 240_000,
  }, async () => {
    session = new PtySession(
      [process.execPath, MAIN, 'setup', '--unprotected', '--mcp-port', String(mcpPort)],
      { env, cwd: project },
    );
    const s = session;
    await s.answer(/Choice \[1\]: /, '1');
    await s.expect(/Tailscale: not logged in/);
    await s.answer(/Approver origin \(https:\/\/host:port\): /, origin);
    await s.answer(/Listen address \[127\.0\.0\.1:8766\]: /, `127.0.0.1:${new URL(origin).port}`);
    await s.answer(/Pair a phone now\? \[Y\/n\]: /, 'y');
    await s.answer(/New key-store passphrase: /, PASSPHRASE);
    await s.answer(/Repeat passphrase: /, PASSPHRASE);
    const link = await s.expect(/(http:\/\/approver\.localhost:\d+\/pair#[A-Za-z0-9_-]+)/);
    await s.expect(/answers from this machine/);
    await phone.pair(link[1] as string);
    await s.expect(/Phone paired/, 30_000);
    await s.answer(/Set up an agent for Claude Code\? \[Y\/n\]: /, '');
    await s.answer(/Agent name \[claude-code\]: /, '');
    await s.expect(/Added agent "claude-code"/);
    await s.answer(/Write the Claude Code config for this agent\? \[Y\/n\]: /, 'y');
    await s.answer(/Choice \[1\]: /, '1');
    await s.answer(/Project directory \[[^\]]+\]: /, '');
    await s.expect(/\.mcp\.json: new file/);
    await s.answer(/Apply these changes\? \[y\/N\]: /, 'y');
    await s.expect(/wrote .*settings\.local\.json/);
    await s.answer(/Choice \[5\]: /, '1');
    await s.answer(/Site \(e\.g\. [^)]+\): /, 'rp.localhost');
    await s.answer(/Username \(blank: none\): /, 'alice');
    await s.answer(/one-time code \(TOTP\)\? \[y\/N\]: /, 'y');
    await s.answer(/Password \(not shown\): /, PASSWORD);
    await s.answer(/TOTP secret or otpauth:\/\/ URI \(not shown\): /, SEED);
    await s.expect(/Added a password \+ TOTP for rp\.localhost \(username alice\)/);
    await s.answer(/Choice \[5\]: /, '5');
    await s.answer(/--headed\)\?.*\[(?:y\/N|Y\/n)\]: /, 'n');
    await s.expect(
      /Start the broker with:\s+keyflap daemon --unprotected --mcp-port \d+ --approver phone/,
    );
    await s.answer(/Start it now, in this terminal\? \[Y\/n\]: /, 'y');
    await s.expect(/All checks passed/, 90_000);
    await s.expect(/The daemon keeps running in this terminal/);

    const doc = await runCli(['doctor', '--json', '--project', project], { env: { ...env } });
    const report = JSON.parse(doc.stdout) as {
      ok: boolean;
      checks: { id: string; status: string }[];
    };
    expect(report.checks.filter((c) => c.status === 'fail')).toEqual([]);
    expect(doc.code).toBe(0);
    expect(report.ok).toBe(true);

    const mcpJson = JSON.parse(readFileSync(join(project, '.mcp.json'), 'utf8'));
    const server = mcpJson.mcpServers.keyflap as { url: string; headersHelper: string };
    expect(server.url).toBe(`http://127.0.0.1:${mcpPort}/mcp`);
    const headers = JSON.parse(
      execFileSync('/bin/sh', ['-c', server.headersHelper], { env, encoding: 'utf8' }),
    ) as { Authorization: string };
    const token = headers.Authorization.replace(/^Bearer /, '');
    expect(token).toMatch(/^aab_agent_/);
    const settings = JSON.parse(
      readFileSync(join(project, '.claude', 'settings.local.json'), 'utf8'),
    );
    const hookCmd = settings.hooks.UserPromptSubmit[0].hooks[0].command as string;
    const agentId = /--agent (\S+)/.exec(hookCmd)?.[1] as string;
    const words = 'sign in to the test RP with my password';
    const hookOut = execFileSync('/bin/sh', ['-c', hookCmd], {
      env,
      input: JSON.stringify({ hook_event_name: 'UserPromptSubmit', prompt: words }),
      encoding: 'utf8',
    });
    expect(hookOut).toBe('');

    mcp = await connectAgent(server.url, { id: agentId, name: 'claude-code', token });
    await mcp.ok('browser_open', { url: `${rp.url}password/login` });
    const [login, card] = await Promise.all([
      mcp.ok<{ status: string }>('auth_login'),
      phone.approve(origin, 45_000),
    ]);
    expect(card).toContain(words);
    expect(login.status).toBe('success');
    const deadline = Date.now() + 15_000;
    let snap = '';
    while (Date.now() < deadline && !snap.includes('Signed in as alice')) {
      snap = (await mcp.ok<{ snapshot: string }>('browser_snapshot')).snapshot;
    }
    expect(snap).toContain('Signed in as alice');

    const transcript = s.output;
    if (process.env.SETUP_E2E_DUMP) writeFileSync(process.env.SETUP_E2E_DUMP, transcript);
    expect(transcript.match(TOKEN_RE)).toBeNull();
    const tokenFile = join(dataDir, 'agents', `${agentId}.token`);
    expect(statSync(tokenFile).mode & 0o777).toBe(0o600);
    const holders = [...filesUnder(project), ...filesUnder(dataDir)].filter((f) => {
      try {
        return readFileSync(f, 'latin1').includes(token);
      } catch {
        return false;
      }
    });
    expect(holders).toEqual([tokenFile]);
    for (const secret of [PASSWORD, SEED, PASSPHRASE]) expect(transcript).not.toContain(secret);
    expect(JSON.stringify(mcp.raw)).not.toContain(PASSWORD);
    const calls = readFileSync(fakeLog, 'utf8');
    expect(calls).toContain('tailscale status --json');
    expect(calls).not.toContain('tailscale serve');
    const db = new DatabaseSync(join(dataDir, 'broker.sqlite'), { readOnly: true });
    const events = (
      db.prepare('SELECT event_type FROM audit').all() as { event_type: string }[]
    ).map((r) => r.event_type);
    db.close();
    for (const e of [
      'setup.pairing',
      'approver.pairing_accepted',
      'approver.paired',
      'agent.added',
    ])
      expect(events).toContain(e);
    const verify = await runCli(['audit', 'verify'], { env: { ...env } });
    expect(verify.code).toBe(0);
  });

  describe("invariant 4: the host token stays out of the model's reach", () => {
    it('setup wrote the sandbox and permission deny rules for the data dir', () => {
      const files = {
        userSettings: undefined,
        projectSettings: undefined,
        localSettings: parseJsonFile(
          readFileSync(join(project, '.claude', 'settings.local.json'), 'utf8'),
        ),
        userState: undefined,
        projectMcp: parseJsonFile(readFileSync(join(project, '.mcp.json'), 'utf8')),
      };
      const insp = inspectClaude(files, { project, mcpPort, denyDir: dataDir, home });
      expect(insp).toMatchObject({
        denyRead: true,
        denyWrite: true,
        permissionDeny: true,
        sandboxEnabled: true,
        failIfUnavailable: true,
        allowUnsandboxedCommands: false,
        hookViaPnpm: false,
      });
      expect(statSync(join(dataDir, 'host-token')).isFile()).toBe(true);
    });
  });
});
