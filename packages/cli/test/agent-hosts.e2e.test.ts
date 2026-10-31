import { spawn, spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { ApprovalRequest } from '@aab/approver';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { addPasswordItem } from '../../core/src/passwords.ts';
import { type McpAgent, type McpHarness, startMcpHarness } from '../../core/test/mcp-harness.ts';
import { codexHooksJson, HERMES_PLUGIN_DIR, hermesPluginConfig } from '../src/host-config.ts';
import { MAIN } from './helpers.ts';

const PASSWORD = 'hosts-e2e-alice-pw-8Kd!';
const OWNER = '1001';

function run(
  cmd: string,
  args: string[],
  input: string,
  env: Record<string, string>,
): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { env, stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (c: Buffer) => {
      stdout += c.toString();
    });
    child.stderr.on('data', (c: Buffer) => {
      stderr += c.toString();
    });
    child.on('error', reject);
    child.on('close', (code) => resolve({ code, stdout, stderr }));
    child.stdin.end(input);
  });
}

async function signIn(h: McpHarness, m: McpAgent): Promise<string> {
  await m.ok('browser_open', { url: `${h.rp.url}password/login` });
  return (await m.ok<{ status: string }>('auth_login')).status;
}

async function signedIn(m: McpAgent): Promise<boolean> {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    const snap = (await m.ok<{ snapshot: string }>('browser_snapshot')).snapshot;
    if (snap.includes('Signed in as alice')) return true;
  }
  return false;
}

describe('agent hosts end to end (Hermes plugin, Codex hook)', () => {
  let h: McpHarness;
  let home: string;
  let env: Record<string, string>;

  beforeAll(async () => {
    h = await startMcpHarness({
      agentName: 'unused',
      rp: { users: [{ username: 'alice', password: PASSWORD }] },
    });
    await addPasswordItem(
      { signer: h.daemon.signer.client, db: h.daemon.db },
      { site: 'rp.localhost', username: 'alice', password: PASSWORD },
    );
    home = mkdtempSync(join(tmpdir(), 'hosts-home-'));
    env = { PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: home };
  }, 120_000);
  afterAll(async () => {
    await h?.close();
    if (home) rmSync(home, { recursive: true, force: true });
  });
  beforeEach(() => {
    h.approver.seen.length = 0;
  });

  const python = spawnSync('python3', ['--version']).status === 0;

  it('Hermes: an owner DM through the plugin becomes the intent; the sign-in shows those words', async () => {
    const m = await h.addAgent('hermes');
    const pluginDir = join(home, '.hermes', 'plugins', 'keyflap-intent');
    cpSync(HERMES_PLUGIN_DIR, pluginDir, { recursive: true });
    writeFileSync(
      join(pluginDir, 'config.json'),
      JSON.stringify(hermesPluginConfig(m.agent.id, h.dataDir, [`telegram:${OWNER}`])),
    );
    const message = (text: string, chatType = 'dm') => ({
      platform: 'telegram',
      session_key: `agent:main:telegram:${chatType}:${OWNER}`,
      message_id: '777',
      text,
      source: { platform: 'telegram', chat_id: OWNER, chat_type: chatType, user_id: OWNER },
      telemetry_schema_version: 1,
    });
    const deliver = async (kwargs: ReturnType<typeof message>) => {
      if (python) {
        const r = await run(
          'python3',
          [
            '-I',
            '-B',
            join(import.meta.dirname, 'hermes-plugin', 'drive_plugin.py'),
            pluginDir,
            JSON.stringify(kwargs),
          ],
          '',
          env,
        );
        expect(r.stderr).toBe('');
        expect(r.stdout.trim()).toBe('null');
        return;
      }
      const { telemetry_schema_version: _t, ...payload } = kwargs;
      const r = await run(
        process.execPath,
        [
          MAIN,
          'hook',
          'hermes',
          '--agent',
          m.agent.id,
          '--owner',
          `telegram:${OWNER}`,
          '--data-dir',
          h.dataDir,
        ],
        JSON.stringify({ event: 'post_gateway_admission', ...payload }),
        env,
      );
      expect(r).toMatchObject({ code: 0, stdout: '' });
    };

    await deliver(message('sign in to the test RP (group)', 'group'));
    expect(await signIn(h, m)).toBe('denied');
    expect(h.approver.seen).toHaveLength(0);

    const words = 'Hermes: sign in to the test RP with my password ✓';
    await deliver(message(words));
    expect(await signIn(h, m)).toBe('success');
    expect(h.approver.seen).toHaveLength(1);
    const req = h.approver.seen[0] as ApprovalRequest;
    expect(req.display.intentText).toBe(words);
    expect(req.display.agentName).toBe('hermes');
    expect(req.display.verifiedOrigin).toBe(h.rp.origin);
    expect(await signedIn(m)).toBe(true);
  }, 120_000);

  it('Codex: the hooks.json command records the prompt; a subagent turn does not', async () => {
    const m = await h.addAgent('codex');
    const command = codexHooksJson(m.agent.id, h.dataDir).hooks.UserPromptSubmit[0]?.hooks[0]
      ?.command as string;
    const prompt = (text: string, extra: Record<string, unknown> = {}) =>
      JSON.stringify({
        session_id: 's',
        turn_id: 't',
        transcript_path: null,
        cwd: home,
        hook_event_name: 'UserPromptSubmit',
        model: 'gpt-5-codex',
        permission_mode: 'default',
        prompt: text,
        ...extra,
      });

    let r = await run(
      '/bin/sh',
      ['-c', command],
      prompt('subagent text', { agent_id: 'a1', agent_type: 'worker' }),
      env,
    );
    expect(r).toEqual({ code: 0, stdout: '', stderr: '' });
    expect(await signIn(h, m)).toBe('denied');
    expect(h.approver.seen).toHaveLength(0);

    const words = 'Codex: please sign in to the test RP as alice';
    r = await run('/bin/sh', ['-c', command], prompt(words), env);
    expect(r).toEqual({ code: 0, stdout: '', stderr: '' });
    expect(await signIn(h, m)).toBe('success');
    const req = h.approver.seen[0] as ApprovalRequest;
    expect(req.display.intentText).toBe(words);
    expect(req.display.agentName).toBe('codex');
    expect(await signedIn(m)).toBe(true);
  }, 120_000);
});
