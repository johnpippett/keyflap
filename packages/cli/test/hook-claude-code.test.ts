import { chmodSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { createServer, type Server, type Socket } from 'node:net';
import { join } from 'node:path';
import type { DatabaseSync } from 'node:sqlite';
import { ApproverKey, ScriptedApprover } from '@aab/approver';
import {
  AgentRegistry,
  Broker,
  type IntentServer,
  loadOrCreateHostToken,
  openDb,
  startIntentServer,
} from '@aab/core';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { MAX_PROMPT, promptFromHookInput } from '../src/hook-claude-code.ts';
import { type CliResult, runCli, tmpDir } from './helpers.ts';

const fakeSigner = {
  createCredential: () => Promise.reject(new Error('unused')),
  sign: () => Promise.reject(new Error('unused')),
  releaseSecret: () => Promise.reject(new Error('unused')),
};

const SECRET_WORDS = 'zebra-umbrella-7781';

function hookInput(prompt: unknown, extra: Record<string, unknown> = {}): string {
  return JSON.stringify({
    session_id: 'abc123',
    transcript_path: '/tmp/t.jsonl',
    cwd: '/tmp',
    permission_mode: 'default',
    hook_event_name: 'UserPromptSubmit',
    prompt,
    ...extra,
  });
}

describe('keyflap hook claude-code (end to end)', () => {
  let dir: string;
  let db: DatabaseSync;
  let broker: Broker;
  let registry: AgentRegistry;
  let server: IntentServer;
  let token: string;
  let agentId: string;

  const intents = () =>
    db.prepare('SELECT agent_id, text FROM intents ORDER BY created_at, rowid').all() as {
      agent_id: string;
      text: string;
    }[];

  const hook = (input: string | Buffer, args: string[] = [], dataDir = dir) =>
    runCli(['hook', 'claude-code', '--agent', agentId, '--data-dir', dataDir, ...args], {
      input,
    });

  const expectSilentExit0 = (r: CliResult) => {
    expect(r.signal).toBeNull();
    expect(r.code).toBe(0);
    expect(r.stdout).toBe('');
    expect(r.stderr).not.toContain(token);
    expect(r.stderr).not.toContain(SECRET_WORDS);
  };

  beforeAll(async () => {
    dir = tmpDir();
    db = openDb(join(dir, 'broker.sqlite'));
    const key = ApproverKey.generate('t');
    broker = new Broker({ db, signer: fakeSigner, approver: new ScriptedApprover(key) });
    registry = new AgentRegistry(db);
    token = loadOrCreateHostToken(join(dir, 'host-token'));
    agentId = registry.add('claude-code').id;
    server = await startIntentServer({
      socketPath: join(dir, 'run', 'intent.sock'),
      hostToken: token,
      registry,
      broker,
    });
  });

  afterAll(async () => {
    await server.close();
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  afterEach(() => {
    db.exec('DELETE FROM intents');
  });

  it('records the prompt verbatim, silently', async () => {
    const prompt = `sign me in to "rp" ${SECRET_WORDS}\n  second line ünïcødé 🔑 \\ </script>`;
    const r = await hook(hookInput(prompt));
    expectSilentExit0(r);
    expect(r.stderr).toBe('');
    expect(intents()).toEqual([{ agent_id: agentId, text: prompt }]);
    const audit = broker.audit.all().filter((e) => e.event_type === 'intent.recorded');
    expect(audit.at(-1)?.payload_json).not.toContain(SECRET_WORDS);
  });

  it('forwards slash commands verbatim and accepts prompt_type user_input', async () => {
    expectSilentExit0(
      await hook(hookInput('/login-helper example.com', { prompt_type: 'slash_command' })),
    );
    expectSilentExit0(await hook(hookInput('typed', { prompt_type: 'user_input' })));
    expect(intents().map((i) => i.text)).toEqual(['/login-helper example.com', 'typed']);
  });

  it('accepts input without optional fields', async () => {
    expectSilentExit0(await hook(JSON.stringify({ prompt: 'just a prompt' })));
    expect(intents().map((i) => i.text)).toEqual(['just a prompt']);
  });

  it('skips turns that are not the user typing (no intent, no noise)', async () => {
    const cases = [
      hookInput(SECRET_WORDS, { hook_event_name: 'SessionStart' }),
      hookInput(SECRET_WORDS, { agent_id: 'sub-1', agent_type: 'Explore' }),
      hookInput(SECRET_WORDS, { prompt_type: 'task_notification' }),
      hookInput(`<task-notification>\n${SECRET_WORDS}\n</task-notification>`),
      hookInput('   \n '),
    ];
    for (const input of cases) {
      const r = await hook(input);
      expectSilentExit0(r);
      expect(r.stderr).toBe('');
    }
    expect(intents()).toEqual([]);
  });

  it('daemon down: exit 0, nothing on stdout, a short stderr line', async () => {
    const down = tmpDir();
    try {
      writeFileSync(join(down, 'host-token'), `${token}\n`, { mode: 0o600 });
      const r = await hook(hookInput(SECRET_WORDS), [], down);
      expectSilentExit0(r);
      expect(r.stderr).toMatch(/cannot reach intent socket: ENOENT/);
      expect(r.stderr.trim().split('\n')).toHaveLength(1);
    } finally {
      rmSync(down, { recursive: true, force: true });
    }
  });

  it('missing, wrong, malformed or over-permissive host token', async () => {
    const other = tmpDir();
    const sock = join(other, 'run');
    mkdirSync(sock, { mode: 0o700 });
    try {
      let r = await hook(hookInput(SECRET_WORDS), [], other);
      expectSilentExit0(r);
      expect(r.stderr).toMatch(/cannot read host token \(ENOENT\)/);

      const wrong = 'A'.repeat(43);
      writeFileSync(join(other, 'host-token'), `${wrong}\n`, { mode: 0o600 });
      symlinkSync(join(dir, 'run', 'intent.sock'), join(sock, 'intent.sock'));
      r = await hook(hookInput(SECRET_WORDS), [], other);
      expectSilentExit0(r);
      expect(r.stderr).not.toContain(wrong);
      expect(r.stderr).toMatch(/401 host token rejected/);

      writeFileSync(join(other, 'host-token'), 'not a token\n', { mode: 0o600 });
      r = await hook(hookInput(SECRET_WORDS), [], other);
      expectSilentExit0(r);
      expect(r.stderr).toMatch(/host token file is malformed/);

      writeFileSync(join(other, 'host-token'), `${token}\n`);
      chmodSync(join(other, 'host-token'), 0o644);
      r = await hook(hookInput(SECRET_WORDS), [], other);
      expectSilentExit0(r);
      expect(r.stderr).toMatch(/accessible to other users/);
    } finally {
      rmSync(other, { recursive: true, force: true });
    }
    expect(intents()).toEqual([]);
  });

  it('malformed stdin', async () => {
    const cases: (string | Buffer)[] = [
      '',
      `not json ${SECRET_WORDS}`,
      `{"prompt": "${SECRET_WORDS}"`,
      JSON.stringify([SECRET_WORDS]),
      JSON.stringify({ text: SECRET_WORDS }),
      hookInput(42),
      Buffer.from([0x7b, 0xff, 0xfe, 0x7d]),
    ];
    for (const input of cases) {
      const r = await hook(input);
      expectSilentExit0(r);
      expect(r.stderr).toMatch(/malformed hook input/);
    }
    expect(intents()).toEqual([]);
  });

  it('oversized input and over-long prompts are not recorded (never truncated)', async () => {
    let r = await hook(Buffer.alloc(2 * 1024 * 1024, 0x20));
    expectSilentExit0(r);
    expect(r.stderr).toMatch(/hook input too large/);
    r = await hook(hookInput(`${SECRET_WORDS} ${'x'.repeat(MAX_PROMPT)}`));
    expectSilentExit0(r);
    expect(r.stderr).toMatch(/longer than 8000/);
    expect(intents()).toEqual([]);
  });

  it('unknown and revoked agents', async () => {
    let r = await runCli(['hook', 'claude-code', '--agent', 'no-such-agent', '--data-dir', dir], {
      input: hookInput(SECRET_WORDS),
    });
    expectSilentExit0(r);
    expect(r.stderr).toMatch(/404 unknown or revoked agent/);

    const gone = registry.add('gone');
    registry.revoke(gone.id);
    r = await runCli(['hook', 'claude-code', '--agent', gone.id, '--data-dir', dir], {
      input: hookInput(SECRET_WORDS),
    });
    expectSilentExit0(r);
    expect(r.stderr).toMatch(/404/);
    expect(intents()).toEqual([]);
  });

  it('bad arguments still exit 0 with nothing on stdout', async () => {
    for (const args of [
      ['hook', 'claude-code'],
      ['hook', 'claude-code', '--agent'],
      ['hook', 'claude-code', '--agent', 'x', '--bogus'],
      ['hook', 'other-host', '--agent', 'x'],
      ['hook'],
    ]) {
      const r = await runCli(args, { input: hookInput(SECRET_WORDS) });
      expectSilentExit0(r);
      expect(r.stderr).toMatch(/^keyflap hook: /);
    }
  });

  it('a socket that never answers times out quickly', async () => {
    const hung = tmpDir();
    const sockets: Socket[] = [];
    let srv: Server | undefined;
    try {
      writeFileSync(join(hung, 'host-token'), `${token}\n`, { mode: 0o600 });
      mkdirSync(join(hung, 'run'), { mode: 0o700 });
      srv = createServer((s) => sockets.push(s));
      await new Promise<void>((res) =>
        (srv as Server).listen(join(hung, 'run', 'intent.sock'), res),
      );
      const started = Date.now();
      const r = await hook(hookInput(SECRET_WORDS), [], hung);
      expectSilentExit0(r);
      expect(r.stderr).toMatch(/timed out/);
      expect(Date.now() - started).toBeLessThan(8_000);
    } finally {
      for (const s of sockets) s.destroy();
      await new Promise<void>((res) => (srv ? srv.close(() => res()) : res()));
      rmSync(hung, { recursive: true, force: true });
    }
  });
});

describe('promptFromHookInput', () => {
  const parse = (prompt: string) =>
    promptFromHookInput(
      Buffer.from(JSON.stringify({ hook_event_name: 'UserPromptSubmit', prompt })),
    );
  const HOST_CONTEXT =
    '<system-reminder>\nThe user started this session without choosing a project folder.\n</system-reminder>';
  const WORDS = 'sign into my test site with my password';

  it('records only the words after the host context the Claude desktop app puts first', () => {
    expect(parse(`${HOST_CONTEXT}\n\n\n${WORDS}`)).toEqual({ prompt: WORDS });
    expect(parse(`${HOST_CONTEXT}\n${HOST_CONTEXT}\n${WORDS}`)).toEqual({ prompt: WORDS });
  });

  it('records nothing when the host context is all there is', () => {
    expect(parse(`${HOST_CONTEXT}\n\n`)).toHaveProperty('skip');
  });

  it('keeps host-context tags that are not at the start, and an unclosed one', () => {
    expect(parse(`${WORDS}\n${HOST_CONTEXT}`)).toEqual({ prompt: `${WORDS}\n${HOST_CONTEXT}` });
    const unclosed = `<system-reminder>\n${WORDS}`;
    expect(parse(unclosed)).toEqual({ prompt: unclosed });
  });

  it('never echoes input in its errors', () => {
    for (const raw of [`{"prompt": "${SECRET_WORDS}`, `[${JSON.stringify(SECRET_WORDS)}]`]) {
      try {
        promptFromHookInput(Buffer.from(raw));
        expect.unreachable();
      } catch (err) {
        expect((err as Error).message).not.toContain(SECRET_WORDS);
      }
    }
  });
});
