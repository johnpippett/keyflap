import type { AgentBrowserPort } from '@aab/mcp';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { NewAgent } from '../src/agents.ts';
import { type Harness, startHarness } from './harness.ts';

describe('multiple agents', () => {
  let h: Harness;
  let a: { agent: NewAgent; port: AgentBrowserPort };
  let b: { agent: NewAgent; port: AgentBrowserPort };
  const resolve = (agent: NewAgent) => {
    const r = h.daemon.resolveAgent(agent.token);
    if (!r) throw new Error('unresolved');
    return { agent, port: r.port };
  };

  beforeAll(async () => {
    h = await startHarness({ agentName: 'agent-a', intent: 'A: add a passkey on the test RP' });
    a = resolve(h.agent);
    b = resolve(h.daemon.registry.add('agent-b'));
  });
  afterAll(async () => h?.close());

  it('contexts are created lazily and are distinct', async () => {
    expect(h.daemon.sessions.peek(b.agent.id)).toBeUndefined();
    await b.port.authStatus();
    const sa = h.daemon.sessions.peek(a.agent.id);
    const sb = h.daemon.sessions.peek(b.agent.id);
    expect(sa && sb).toBeTruthy();
    expect(sa?.context).not.toBe(sb?.context);
  });

  it("agent A's sign-up session is invisible to agent B", async () => {
    await a.port.open(`${h.rp.url}signup`);
    const info = await a.port.type({ label: 'Username' }, 'sam', { submit: true });
    expect(info.url).toBe(`${h.rp.url}account`);
    const bInfo = await b.port.open(`${h.rp.url}account`);
    expect(bInfo.url).toBe(`${h.rp.url}login`);
    expect((await a.port.snapshot()).snapshot).toContain('Signed in as sam');
    expect((await b.port.snapshot()).snapshot).toContain('Signed out');
  });

  it("approval names agent A and shows A's words for A's ceremony", async () => {
    await a.port.open(`${h.rp.url}account`);
    await a.port.click({ role: 'button', name: 'Add a passkey' });
    expect(await a.port.authEnrollPasskey()).toEqual({ status: 'success' });
    const req = h.approver.seen.at(-1);
    expect(req?.display).toMatchObject({
      agentName: 'agent-a',
      intentText: 'A: add a passkey on the test RP',
      verifiedOrigin: h.rp.origin,
      action: 'register',
    });
  });

  it("with its own intent, B's approval names agent B and shows B's words", async () => {
    h.daemon.broker.intents.record(b.agent.id, 'B: sign in to the test RP');
    await b.port.open(`${h.rp.url}login`);
    await b.port.click({ role: 'button', name: 'Sign in with a passkey' });
    expect(await b.port.authLogin()).toEqual({ status: 'success' });
    expect(h.approver.seen.at(-1)?.display).toMatchObject({
      agentName: 'agent-b',
      intentText: 'B: sign in to the test RP',
      action: 'sign-in',
    });
    expect(await a.port.authLogin({ timeoutMs: 200 })).toEqual({ status: 'timeout' });
  });

  it('requests and audit entries carry the right agent id', () => {
    const rows = h.daemon.db
      .prepare('SELECT agent_id, kind, status FROM requests ORDER BY created_at, rowid')
      .all() as { agent_id: string; kind: string; status: string }[];
    expect(rows.map((r) => [r.agent_id, r.kind, r.status])).toEqual([
      [a.agent.id, 'passkey.create', 'completed'],
      [b.agent.id, 'passkey.get', 'completed'],
    ]);
    expect(h.daemon.broker.audit.verify()).toBeNull();
  });
});
