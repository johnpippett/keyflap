import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { type ApprovalRequest, ApproverKey, ScriptedApprover } from '@aab/approver';
import { spawnSigner } from '@aab/signer/client';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AgentRegistry } from '../src/agents.ts';
import { Broker } from '../src/broker.ts';
import { openDb } from '../src/db.ts';

describe('invariant 6 / section 11: one pending approval per agent', () => {
  let dir: string;
  let stop: () => Promise<void>;
  let broker: Broker;
  let reg: AgentRegistry;
  const seen: ApprovalRequest[] = [];
  const waiting: (() => void)[] = [];
  const answerAll = () => {
    for (const f of waiting.splice(0)) f();
  };

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), 'inv6-ap-'));
    const key = ApproverKey.generate();
    const signer = await spawnSigner({
      socketPath: join(dir, 's.sock'),
      storePath: join(dir, 'keys'),
      passphrase: 'pw',
      trustedApproverKeys: key.trustEntry(),
    });
    const db = openDb(join(dir, 'db.sqlite'));
    const approver = new ScriptedApprover(key, async (r) => {
      seen.push(r);
      await new Promise<void>((res) => waiting.push(res));
      return true;
    });
    broker = new Broker({ db, signer: signer.client, approver });
    reg = new AgentRegistry(db);
    stop = async () => {
      await signer.stop();
      db.close();
      rmSync(dir, { recursive: true, force: true });
    };
  });
  afterAll(async () => stop?.());

  const b = (n: number) => ({ $b: randomBytes(n).toString('base64url') });
  const create = (agent: { id: string; name: string }, host: string) =>
    broker.handleWebAuthn(
      {
        kind: 'create',
        frame: { url: `https://${host}/`, isMainFrame: true, securityOrigin: `https://${host}` },
        mediation: null,
        options: {
          challenge: b(32),
          rp: { id: host, name: 'E' },
          user: { id: b(16), name: 'u', displayName: 'u' },
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        },
      },
      agent,
    );
  const waitForCards = async (n: number) => {
    while (seen.length < n) await new Promise((r) => setTimeout(r, 10));
  };

  it('a second request while a card waits is denied without a card', async () => {
    const a = reg.add('agent-a');
    const other = reg.add('agent-b');
    broker.intents.record(a.id, 'set up passkeys');
    broker.intents.record(other.id, 'set up passkeys');

    const first = create(a, 'one.example.com');
    await waitForCards(1);
    const flood = await Promise.all([1, 2, 3, 4, 5].map((i) => create(a, `f${i}.example.com`)));
    expect(flood.every((r) => r.ok === false)).toBe(true);
    expect(seen).toHaveLength(1);
    const reasons = broker.audit
      .all()
      .filter((r) => r.event_type === 'denied')
      .map((r) => JSON.parse(r.payload_json).reason);
    expect(reasons).toEqual(Array(5).fill('approval_pending'));

    const theirs = create(other, 'two.example.com');
    await waitForCards(2);
    answerAll();
    expect((await first).ok).toBe(true);
    expect((await theirs).ok).toBe(true);

    const again = create(a, 'three.example.com');
    await waitForCards(3);
    answerAll();
    expect((await again).ok).toBe(true);
  });
});
