import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { promptFromCodexInput } from '../src/hook-codex.ts';
import { MAX_PROMPT } from '../src/hook-core.ts';
import { runCli } from './helpers.ts';
import { type IntentFixture, SECRET_WORDS, startIntentFixture } from './intent-fixture.ts';

function codexInput(prompt: unknown, extra: Record<string, unknown> = {}): string {
  return JSON.stringify({
    session_id: '0199a213-81c0-7800-8aa1-bbab2a035a53',
    turn_id: 'turn-1',
    transcript_path: '/tmp/rollout.jsonl',
    cwd: '/tmp/project',
    hook_event_name: 'UserPromptSubmit',
    model: 'gpt-5-codex',
    permission_mode: 'default',
    prompt,
    ...extra,
  });
}

describe('invariant 4: keyflap hook codex records only human prompts', () => {
  let f: IntentFixture;
  const hook = (input: string | Buffer) =>
    runCli(['hook', 'codex', '--agent', f.agentId, '--data-dir', f.dir], { input });

  beforeAll(async () => {
    f = await startIntentFixture('codex');
  });
  afterAll(async () => {
    await f.close();
  });
  afterEach(() => {
    f.db.exec('DELETE FROM intents');
  });

  it('records the prompt verbatim, silently (invariant 5: nothing added or trimmed)', async () => {
    const prompt = ` sign me in to "rp" ${SECRET_WORDS}\n  ünïcødé 🔑 \\ </script> `;
    const r = await hook(codexInput(prompt, { transcript_path: null }));
    f.expectSilentExit0(r);
    expect(r.stderr).toBe('');
    expect(f.intents()).toEqual([{ agent_id: f.agentId, text: prompt }]);
    const audit = f.broker.audit.all().filter((e) => e.event_type === 'intent.recorded');
    expect(audit.at(-1)?.payload_json).not.toContain(SECRET_WORDS);
  });

  it('records nothing for subagents, other events and empty prompts', async () => {
    const cases = [
      codexInput(SECRET_WORDS, { agent_id: '0199a213-0000-7000-8000-000000000001' }),
      codexInput(SECRET_WORDS, { agent_type: 'explorer' }),
      codexInput(SECRET_WORDS, { agent_id: 'a', agent_type: 'default' }),
      codexInput(SECRET_WORDS, { hook_event_name: 'SessionStart' }),
      codexInput(SECRET_WORDS, { hook_event_name: 'Stop' }),
      codexInput(SECRET_WORDS, { hook_event_name: undefined }),
      codexInput('   \n '),
    ];
    for (const input of cases) {
      const r = await hook(input);
      f.expectSilentExit0(r);
      expect(r.stderr).toBe('');
    }
    expect(f.intents()).toEqual([]);
  });

  it('over-long prompts and malformed input: not recorded, never truncated', async () => {
    let r = await hook(codexInput(`${SECRET_WORDS} ${'x'.repeat(MAX_PROMPT)}`));
    f.expectSilentExit0(r);
    expect(r.stderr).toMatch(/longer than 8000/);
    for (const input of [
      '',
      `not json ${SECRET_WORDS}`,
      `{"prompt": "${SECRET_WORDS}"`,
      JSON.stringify([SECRET_WORDS]),
      codexInput(undefined),
      codexInput(42),
      Buffer.from([0x7b, 0xff, 0xfe, 0x7d]),
    ]) {
      r = await hook(input);
      f.expectSilentExit0(r);
      expect(r.stderr).toMatch(/malformed hook input/);
    }
    r = await hook(Buffer.alloc(2 * 1024 * 1024, 0x20));
    f.expectSilentExit0(r);
    expect(r.stderr).toMatch(/hook input too large/);
    expect(f.intents()).toEqual([]);
  });

  it('daemon down, unknown agent, bad arguments: exit 0, nothing on stdout', async () => {
    let r = await runCli(['hook', 'codex', '--agent', f.agentId, '--data-dir', '/nonexistent'], {
      input: codexInput(SECRET_WORDS),
    });
    f.expectSilentExit0(r);
    expect(r.stderr).toMatch(/cannot read host token/);
    r = await runCli(['hook', 'codex', '--agent', 'no-such-agent', '--data-dir', f.dir], {
      input: codexInput(SECRET_WORDS),
    });
    f.expectSilentExit0(r);
    expect(r.stderr).toMatch(/404 unknown or revoked agent/);
    for (const args of [
      ['hook', 'codex'],
      ['hook', 'codex', '--agent'],
      ['hook', 'codex', '--agent', 'x', '--bogus'],
    ]) {
      r = await runCli(args, { input: codexInput(SECRET_WORDS) });
      f.expectSilentExit0(r);
      expect(r.stderr).toMatch(/^keyflap hook: /);
    }
    expect(f.intents()).toEqual([]);
  });
});

describe('promptFromCodexInput', () => {
  it('returns the prompt exactly, or a skip reason', () => {
    expect(promptFromCodexInput(Buffer.from(codexInput(' hi ')))).toEqual({ prompt: ' hi ' });
    expect(promptFromCodexInput(Buffer.from(codexInput('x', { agent_id: 'a' })))).toHaveProperty(
      'skip',
    );
  });

  it('never echoes input in its errors', () => {
    for (const raw of [`{"prompt": "${SECRET_WORDS}`, codexInput(SECRET_WORDS.repeat(1000))]) {
      try {
        promptFromCodexInput(Buffer.from(raw));
        expect.unreachable();
      } catch (err) {
        expect((err as Error).message).not.toContain(SECRET_WORDS);
      }
    }
  });
});
