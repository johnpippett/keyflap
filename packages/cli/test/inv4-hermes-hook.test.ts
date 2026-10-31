import { execFile, spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { MAX_PROMPT } from '../src/hook-core.ts';
import { GOAL_ALREADY_SEEN_KICK, parseOwner, promptFromHermesInput } from '../src/hook-hermes.ts';
import { MAIN, runCli } from './helpers.ts';
import { type IntentFixture, SECRET_WORDS, startIntentFixture } from './intent-fixture.ts';

const OWNER_ID = '1001';

function admission(
  text: unknown,
  o: {
    platform?: string;
    source?: Record<string, unknown>;
    message_id?: unknown;
    event?: string;
  } = {},
) {
  const platform = o.platform ?? 'telegram';
  return JSON.stringify({
    event: o.event ?? 'post_gateway_admission',
    platform,
    session_key: `agent:main:${platform}:dm:${OWNER_ID}`,
    message_id: 'message_id' in o ? o.message_id : '4242',
    text,
    source: {
      platform,
      chat_id: OWNER_ID,
      chat_name: null,
      chat_type: 'dm',
      user_id: OWNER_ID,
      user_name: 'owner',
      thread_id: null,
      chat_topic: null,
      ...o.source,
    },
  });
}

describe('invariant 4: keyflap hook hermes records only the owner’s direct messages', () => {
  let f: IntentFixture;
  const hook = (input: string | Buffer, extra: string[] = []) =>
    runCli(
      [
        'hook',
        'hermes',
        '--agent',
        f.agentId,
        '--owner',
        `telegram:${OWNER_ID}`,
        '--owner',
        'matrix:@sam:example.org',
        '--data-dir',
        f.dir,
        ...extra,
      ],
      { input },
    );

  beforeAll(async () => {
    f = await startIntentFixture('hermes');
  });
  afterAll(async () => {
    await f.close();
  });
  afterEach(() => {
    f.db.exec('DELETE FROM intents');
  });

  it('records an owner DM verbatim, silently (invariant 5: nothing added or trimmed)', async () => {
    const text = `  sign me in to "rp" ${SECRET_WORDS}\n  second line ünïcødé 🔑 \\ </script>  `;
    const r = await hook(admission(text));
    f.expectSilentExit0(r);
    expect(r.stderr).toBe('');
    expect(f.intents()).toEqual([{ agent_id: f.agentId, text }]);
    const audit = f.broker.audit.all().filter((e) => e.event_type === 'intent.recorded');
    expect(audit.at(-1)?.payload_json).not.toContain(SECRET_WORDS);
  });

  it('accepts numeric ids, user ids with colons, and a matching --profile', async () => {
    f.expectSilentExit0(
      await hook(admission('numeric', { message_id: 77, source: { user_id: 1001 } })),
    );
    f.expectSilentExit0(
      await hook(
        admission('matrix', {
          platform: 'matrix',
          source: { user_id: '@sam:example.org', chat_id: '!room:example.org' },
        }),
      ),
    );
    f.expectSilentExit0(
      await hook(admission('profile', { source: { profile: 'work' } }), ['--profile', 'work']),
    );
    expect(f.intents().map((i) => i.text)).toEqual(['numeric', 'matrix', 'profile']);
  });

  it('records nothing for anything that is not the owner typing in a DM', async () => {
    const W = SECRET_WORDS;
    const cases: [string, string][] = [
      ['webhook', admission(W, { platform: 'webhook' })],
      ['api_server', admission(W, { platform: 'api_server' })],
      ['msgraph_webhook', admission(W, { platform: 'msgraph_webhook' })],
      ['relay', admission(W, { platform: 'relay' })],
      ['local CLI', admission(W, { platform: 'local' })],
      ['email (forgeable sender)', admission(W, { platform: 'email' })],
      ['sms (forgeable sender)', admission(W, { platform: 'sms' })],
      ['cron', admission(W, { platform: 'cron' })],
      ['subagent', admission(W, { platform: 'subagent' })],
      ['group chat', admission(W, { source: { chat_type: 'group' } })],
      ['channel', admission(W, { source: { chat_type: 'channel' } })],
      ['thread with others', admission(W, { source: { chat_type: 'thread' } })],
      ['no chat type', admission(W, { source: { chat_type: undefined } })],
      ['bot sender', admission(W, { source: { is_bot: true } })],
      ['non-owner DM', admission(W, { source: { user_id: '999' } })],
      ['owner id on another platform', admission(W, { platform: 'discord' })],
      ['no sender', admission(W, { source: { user_id: null } })],
      ['source platform mismatch', admission(W, { source: { platform: 'webhook' } })],
      ['another Hermes profile', admission(W, { source: { profile: 'other' } })],
      ['synthetic turn: no message id', admission(W, { message_id: undefined })],
      ['synthetic turn: null message id', admission(W, { message_id: null })],
      ['synthetic turn: empty message id', admission(W, { message_id: '' })],
      ['internal / other hook event', admission(W, { event: 'pre_llm_call' })],
      ['no event', JSON.stringify({ ...JSON.parse(admission(W)), event: undefined })],
      ['Hermes goal kick-off text', admission(GOAL_ALREADY_SEEN_KICK)],
      ['empty text', admission('  \n ')],
    ];
    for (const [name, input] of cases) {
      const r = await hook(input);
      f.expectSilentExit0(r);
      expect(r.stderr, name).toBe('');
    }
    f.expectSilentExit0(await hook(admission(SECRET_WORDS), ['--profile', 'work']));
    expect(f.intents()).toEqual([]);
  });

  it('over-long text and malformed input: not recorded, never truncated', async () => {
    let r = await hook(admission(`${SECRET_WORDS} ${'x'.repeat(MAX_PROMPT)}`));
    f.expectSilentExit0(r);
    expect(r.stderr).toMatch(/longer than 8000/);
    for (const input of [
      '',
      `not json ${SECRET_WORDS}`,
      `{"text": "${SECRET_WORDS}"`,
      JSON.stringify([SECRET_WORDS]),
      JSON.stringify({ event: 'post_gateway_admission', text: SECRET_WORDS }),
      admission(42),
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

  it('bad arguments still exit 0 with nothing on stdout', async () => {
    for (const args of [
      ['hook', 'hermes', '--agent', f.agentId],
      ['hook', 'hermes', '--agent', f.agentId, '--owner', `webhook:${OWNER_ID}`],
      ['hook', 'hermes', '--agent', f.agentId, '--owner', 'telegram:'],
      ['hook', 'hermes', '--agent', f.agentId, '--owner', 'telegram:a b'],
      ['hook', 'hermes', '--owner', `telegram:${OWNER_ID}`],
      ['hook', 'codex', '--agent', 'x', '--owner', `telegram:${OWNER_ID}`],
    ]) {
      const r = await runCli([...args, '--data-dir', f.dir], { input: admission(SECRET_WORDS) });
      f.expectSilentExit0(r);
      expect(r.stderr).toMatch(/^keyflap hook: /);
    }
    expect(f.intents()).toEqual([]);
  });
});

describe('promptFromHermesInput', () => {
  const filter = { owners: [parseOwner(`telegram:${OWNER_ID}`)], profile: null };
  it('returns the text exactly, or a skip reason', () => {
    expect(promptFromHermesInput(Buffer.from(admission(' hi ')), filter)).toEqual({
      prompt: ' hi ',
    });
    expect(
      promptFromHermesInput(Buffer.from(admission('x', { platform: 'webhook' })), filter),
    ).toHaveProperty('skip');
    expect(promptFromHermesInput(Buffer.from(admission('x')), { ...filter, owners: [] })).toEqual({
      skip: 'not from an owner',
    });
  });

  it('never echoes input in its errors', () => {
    for (const raw of [`{"text": "${SECRET_WORDS}`, admission(SECRET_WORDS.repeat(1000))]) {
      try {
        promptFromHermesInput(Buffer.from(raw), filter);
        expect.unreachable();
      } catch (err) {
        expect((err as Error).message).not.toContain(SECRET_WORDS);
      }
    }
  });

  it('owner platforms are chat platforms with authenticated senders only', () => {
    for (const p of [
      'webhook',
      'api_server',
      'msgraph_webhook',
      'relay',
      'email',
      'sms',
      'local',
    ]) {
      expect(() => parseOwner(`${p}:1`)).toThrow();
    }
    expect(parseOwner('Telegram:42')).toEqual({ platform: 'telegram', userId: '42' });
  });
});

const python = spawnSync('python3', ['--version']).status === 0 ? 'python3' : null;
const PLUGIN_TESTS = join(import.meta.dirname, 'hermes-plugin');

describe.skipIf(python === null)('Hermes keyflap-intent plugin (Python unittest)', () => {
  it('passes its unit tests', () => {
    const r = spawnSync(python as string, ['-B', '-m', 'unittest', 'test_keyflap_intent'], {
      cwd: PLUGIN_TESTS,
      encoding: 'utf8',
      timeout: 60_000,
    });
    expect(r.stderr).toMatch(/\nOK\s*$/);
    expect(r.status).toBe(0);
  });
});

const HERMES_SRC = process.env.KEYFLAP_TEST_HERMES_SRC;
describe.skipIf(!HERMES_SRC || !existsSync(join(HERMES_SRC ?? '', 'gateway')))(
  'Hermes keyflap-intent plugin through the real Hermes loader (opt-in)',
  () => {
    let f: IntentFixture;
    let home = '';
    beforeAll(async () => {
      f = await startIntentFixture('hermes-loader');
    });
    afterAll(async () => {
      await f.close();
      if (home) rmSync(home, { recursive: true, force: true });
    });

    const run = async (env: Record<string, string>) => {
      if (home) rmSync(home, { recursive: true, force: true });
      home = mkdtempSync(join(tmpdir(), 'hermes-home-'));
      const config = {
        command: [process.execPath, MAIN],
        agent: f.agentId,
        owners: ['telegram:1001'],
        dataDir: f.dir,
      };
      const r = await promisify(execFile)(
        process.env.KEYFLAP_TEST_HERMES_PYTHON ?? 'python3',
        [
          '-I',
          '-B',
          join(PLUGIN_TESTS, 'hermes_loader_check.py'),
          HERMES_SRC as string,
          join(import.meta.dirname, '..', 'src', 'integrations', 'hermes', 'keyflap-intent'),
          JSON.stringify(config),
        ],
        {
          encoding: 'utf8',
          timeout: 120_000,
          env: {
            PATH: process.env.PATH ?? '',
            HOME: home,
            HERMES_HOME: home,
            HERMES_SITE_PACKAGES: process.env.KEYFLAP_TEST_HERMES_SITE ?? '',
            ...env,
          },
        },
      );
      return JSON.parse(r.stdout.trim().split('\n').at(-1) as string);
    };

    it('loads, fires post_gateway_admission, records the owner DM, never consumes it', async () => {
      const text = `sign me in to rp ${SECRET_WORDS} ü`;
      const out = await run({ CHECK_TEXT: text });
      expect(out).toEqual({ hooks: ['post_gateway_admission'], handled: false, reply: null });
      expect(f.intents()).toEqual([{ agent_id: f.agentId, text }]);
    });

    it('a group message, another sender and a webhook record nothing', async () => {
      f.db.exec('DELETE FROM intents');
      expect((await run({ CHECK_TEXT: 'group', CHECK_CHAT_TYPE: 'group' })).handled).toBe(false);
      expect((await run({ CHECK_TEXT: 'other', CHECK_USER_ID: '999' })).handled).toBe(false);
      expect((await run({ CHECK_TEXT: 'hook', CHECK_PLATFORM: 'webhook' })).handled).toBe(false);
      expect(f.intents()).toEqual([]);
    });
  },
);
