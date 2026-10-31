import { describe, expect, it } from 'vitest';
import { AgentPort } from '../src/agent-port.ts';
import { AuditLog } from '../src/audit.ts';
import type { Broker } from '../src/broker.ts';
import { openDb } from '../src/db.ts';
import type { AgentSessions } from '../src/sessions.ts';

const AGENT = { id: 'agent-1', name: 'agent one' };

function portWithAudit() {
  const db = openDb(':memory:');
  const audit = new AuditLog(db);
  const sessions = {
    get: async () => ({ markDirty() {}, secrets: () => [] as string[] }),
    peek: () => undefined,
  } as unknown as AgentSessions;
  const port = new AgentPort({
    agent: AGENT,
    sessions,
    broker: { audit } as unknown as Broker,
    isActive: () => true,
  });
  return { db, audit, port };
}

describe('invariant 10: a tool call that cannot be audited fails', () => {
  it('control: the call returns its result and is audited once, with identifiers only', async () => {
    const { audit, port } = portWithAudit();
    expect(await port.handoff()).toEqual({ status: 'unsupported', reason: 'not_available' });
    const rows = audit.all();
    expect(rows.map((r) => r.event_type)).toEqual(['tool.call']);
    expect(JSON.parse(rows[0]?.payload_json as string)).toEqual({
      agentId: AGENT.id,
      tool: 'browser_handoff',
      ok: true,
    });
  });

  it('when the audit append throws, the call rejects and the result is not returned', async () => {
    const { db, port } = portWithAudit();
    db.exec('DROP TABLE audit');
    await expect(port.handoff()).rejects.toThrow();
  });
});
