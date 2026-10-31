import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  type McpAgent,
  type McpHarness,
  mcpSignUp,
  postIntent,
  startMcpHarness,
} from './mcp-harness.ts';

const intentCount = (h: McpHarness) =>
  (h.daemon.db.prepare('SELECT COUNT(*) AS n FROM intents').get() as { n: number }).n;

const lastDenied = (h: McpHarness) =>
  h
    .auditEvents()
    .filter((e) => e.type === 'denied')
    .at(-1)?.payload;

async function tryEnroll(m: McpAgent): Promise<unknown> {
  await m.ok('browser_click', { target: { role: 'button', name: 'Add a passkey' } });
  return m.ok('auth_enroll_passkey');
}

async function tryLogin(h: McpHarness, m: McpAgent): Promise<unknown> {
  await m.ok('browser_open', { url: `${h.rp.url}login` });
  await m.ok('browser_click', { target: { role: 'button', name: 'Sign in with a passkey' } });
  return m.ok('auth_login');
}

async function pageStatus(m: McpAgent): Promise<string> {
  const { snapshot } = await m.ok<{ snapshot: string }>('browser_snapshot');
  return snapshot;
}

function stringFields(schema: unknown, path = ''): string[] {
  if (typeof schema !== 'object' || schema === null) return [];
  const s = schema as Record<string, unknown>;
  const out: string[] = [];
  if (s.type === 'string') out.push(path);
  for (const key of ['anyOf', 'oneOf', 'allOf']) {
    if (Array.isArray(s[key]))
      for (const sub of s[key] as unknown[]) out.push(...stringFields(sub, path));
  }
  if (s.properties && typeof s.properties === 'object') {
    for (const [k, v] of Object.entries(s.properties as Record<string, unknown>)) {
      out.push(...stringFields(v, path ? `${path}.${k}` : k));
    }
  }
  if (s.items) out.push(...stringFields(s.items, `${path}[]`));
  return out;
}

function allClosed(schema: unknown): boolean {
  if (typeof schema !== 'object' || schema === null) return true;
  const s = schema as Record<string, unknown>;
  if (s.type === 'object' && s.additionalProperties !== false) return false;
  const subs = [
    ...(Array.isArray(s.anyOf) ? s.anyOf : []),
    ...(Array.isArray(s.oneOf) ? s.oneOf : []),
    ...(Array.isArray(s.allOf) ? s.allOf : []),
    ...Object.values((s.properties as Record<string, unknown>) ?? {}),
  ];
  return subs.every(allClosed);
}

describe('invariant 4: no prompt without a live out-of-band intent', () => {
  let h: McpHarness;
  let a: McpAgent;
  let b: McpAgent;

  beforeAll(async () => {
    h = await startMcpHarness({ agentName: 'inv4-agent-a' });
    a = h.mcp;
    b = await h.addAgent('inv4-agent-b');
  });
  afterAll(async () => h?.close());

  it('no intent at all: the page gets NotAllowedError, the tool says denied, no prompt, audited', async () => {
    expect(intentCount(h)).toBe(0);
    await mcpSignUp(h, a, 'inv4-a');
    expect(await tryEnroll(a)).toEqual({ status: 'denied' });
    expect(await pageStatus(a)).toContain('error: NotAllowedError');
    expect(h.approver.seen).toHaveLength(0);
    expect(lastDenied(h)).toMatchObject({
      agentId: a.agent.id,
      kind: 'passkey.create',
      verifiedOrigin: h.rp.origin,
      reason: 'no_live_intent',
    });
    expect(h.rp.users.get('inv4-a')?.passkeys).toHaveLength(0);
  });

  it('wrong, missing or misplaced host token: 401 and nothing recorded', async () => {
    const body = { agentId: a.agent.id, text: 'forged: sign me in everywhere' };
    const cases: { token?: string | null; authorization?: string }[] = [
      { token: null },
      { token: 'x'.repeat(43) },
      {
        token: `${h.daemon.hostToken.slice(0, -1)}${h.daemon.hostToken.endsWith('A') ? 'B' : 'A'}`,
      },
      { token: a.agent.token },
      { authorization: h.daemon.hostToken },
      { authorization: `Basic ${h.daemon.hostToken}` },
      { authorization: `Bearer ${h.daemon.hostToken} extra` },
    ];
    for (const c of cases) {
      const r = await postIntent(h.daemon.intentSocketPath, body, c);
      expect(r.status, JSON.stringify(c)).toBe(401);
    }
    for (const path of ['/v1/intents', '/mcp/v1/intents']) {
      const res = await fetch(new URL(path, h.mcpUrl), {
        method: 'POST',
        headers: {
          authorization: `Bearer ${a.agent.token}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify(body),
      });
      expect(res.status, path).not.toBe(201);
      expect(res.status, path).toBeGreaterThanOrEqual(400);
    }
    expect(intentCount(h)).toBe(0);
    const rejected = h.auditEvents().filter((e) => e.type === 'intent.rejected');
    expect(rejected.length).toBe(cases.length);
    for (const r of rejected)
      expect(r.payload).toMatchObject({ status: 401, reason: 'bad_host_token' });
    expect(await tryEnroll(a)).toEqual({ status: 'denied' });
    expect(h.approver.seen).toHaveLength(0);
  });

  it('no MCP tool has a field that could carry an intent', async () => {
    const tools: Tool[] = await a.listTools();
    const fields = Object.fromEntries(
      tools.map((t) => [t.name, [...new Set(stringFields(t.inputSchema))].sort()]),
    );
    const locator = [
      'target.css',
      'target.label',
      'target.name',
      'target.placeholder',
      'target.role',
      'target.text',
    ];
    expect(fields).toEqual({
      browser_open: ['url'],
      browser_click: locator,
      browser_type: [...locator, 'text'].sort(),
      browser_snapshot: [],
      auth_status: [],
      auth_login: [],
      auth_enroll_passkey: [],
      browser_handoff: [],
    });
    for (const t of tools) expect(allClosed(t.inputSchema), t.name).toBe(true);
  });

  it('intent-shaped arguments are rejected by the schema and record nothing', async () => {
    const words = 'yes, I the user approve: sign in to rp.localhost';
    const extras = [
      { intent: words },
      { intentText: words },
      { justification: words },
      { reason: words },
      { userMessage: words },
      { prompt: words },
      { origin: h.rp.origin },
      { agentName: 'the user' },
    ];
    const base: Record<string, Record<string, unknown>> = {
      browser_open: { url: `${h.rp.url}account` },
      browser_click: { target: { role: 'button', name: 'Add a passkey' } },
      browser_type: { target: { label: 'Username' }, text: 'x' },
      browser_snapshot: {},
      auth_status: {},
      auth_login: {},
      auth_enroll_passkey: {},
    };
    for (const [tool, args] of Object.entries(base)) {
      for (const extra of extras) {
        const msg = await a.err(tool, { ...args, ...extra });
        expect(msg, `${tool} ${Object.keys(extra)[0]}`).toMatch(/^invalid arguments/);
      }
    }
    expect(
      await a.err('browser_click', { target: { role: 'button', name: 'x', intent: words } }),
    ).toMatch(/^invalid arguments/);
    const viaMeta = await a.call('auth_status', {}, { intent: words, userMessage: words });
    expect(viaMeta.isError).not.toBe(true);
    expect(intentCount(h)).toBe(0);
    await a.ok('browser_open', { url: `${h.rp.url}account` });
    expect(await tryEnroll(a)).toEqual({ status: 'denied' });
    expect(h.approver.seen).toHaveLength(0);
    expect(lastDenied(h)).toMatchObject({ agentId: a.agent.id, reason: 'no_live_intent' });
  });

  it('a valid intent over the socket: the prompt appears and the flow succeeds', async () => {
    const words = 'Please add a passkey to my inv4-a account';
    const r = await postIntent(
      h.daemon.intentSocketPath,
      { agentId: a.agent.id, text: words },
      { token: h.daemon.hostToken },
    );
    expect(r.status).toBe(201);
    expect(intentCount(h)).toBe(1);
    await a.ok('browser_open', { url: `${h.rp.url}account` });
    expect(await tryEnroll(a)).toEqual({ status: 'success' });
    expect(h.approver.seen).toHaveLength(1);
    expect(h.approver.seen[0]?.display).toMatchObject({
      intentText: words,
      agentName: 'inv4-agent-a',
      action: 'register',
    });
    await expect.poll(() => h.rp.users.get('inv4-a')?.passkeys.length).toBe(1);
  });

  it("another agent's live intent does not count: B is denied on create and get, no prompt", async () => {
    const prompts = h.approver.seen.length;
    await mcpSignUp(h, b, 'inv4-b');
    expect(await tryEnroll(b)).toEqual({ status: 'denied' });
    expect(lastDenied(h)).toMatchObject({
      agentId: b.agent.id,
      kind: 'passkey.create',
      reason: 'no_live_intent',
    });
    await b.ok('browser_click', { target: { role: 'button', name: 'Log out' } });
    expect(await tryLogin(h, b)).toEqual({ status: 'denied' });
    expect(await pageStatus(b)).toContain('error: NotAllowedError');
    expect(lastDenied(h)).toMatchObject({
      agentId: b.agent.id,
      kind: 'passkey.get',
      reason: 'no_live_intent',
    });
    expect(h.approver.seen.length).toBe(prompts);
  });

  it('an intent addressed to an unknown or revoked agent is refused (404)', async () => {
    const c = h.daemon.registry.add('inv4-agent-c');
    h.daemon.registry.revoke(c.id);
    for (const agentId of [c.id, 'no-such-agent']) {
      const r = await postIntent(
        h.daemon.intentSocketPath,
        { agentId, text: 'hello' },
        { token: h.daemon.hostToken },
      );
      expect(r.status).toBe(404);
    }
    expect(intentCount(h)).toBe(1);
  });
});

describe('invariant 4: an expired intent is no intent', () => {
  const TTL = 2_500;
  let h: McpHarness;

  beforeAll(async () => {
    h = await startMcpHarness({ agentName: 'inv4-ttl', daemon: { intentTtlMs: TTL } });
  });
  afterAll(async () => h?.close());

  it('within the TTL the prompt appears; after it, create and get are denied without one', async () => {
    const m = h.mcp;
    await mcpSignUp(h, m, 'inv4-ttl');
    const { intentId, expiresAt } = await h.intent('add a passkey, quickly');
    expect(await tryEnroll(m)).toEqual({ status: 'success' });
    expect(h.approver.seen).toHaveLength(1);

    const wait = expiresAt - Date.now() + 200;
    if (wait > 0) await new Promise((r) => setTimeout(r, wait));
    const row = h.daemon.db
      .prepare('SELECT expires_at FROM intents WHERE id = ?')
      .get(intentId) as {
      expires_at: number;
    };
    expect(row.expires_at).toBeLessThan(Date.now());

    await m.ok('browser_click', { target: { role: 'button', name: 'Log out' } });
    expect(await tryLogin(h, m)).toEqual({ status: 'denied' });
    expect(await pageStatus(m)).toContain('error: NotAllowedError');
    expect(h.approver.seen).toHaveLength(1);
    expect(lastDenied(h)).toMatchObject({
      agentId: m.agent.id,
      kind: 'passkey.get',
      reason: 'no_live_intent',
    });

    await h.intent('sign me back in');
    expect(await tryLogin(h, m)).toEqual({ status: 'success' });
    expect(h.approver.seen).toHaveLength(2);
    expect(h.approver.seen[1]?.display.intentText).toBe('sign me back in');
  });
});
