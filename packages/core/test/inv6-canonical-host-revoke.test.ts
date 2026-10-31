import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { type ApprovalRequest, ApproverKey, ScriptedApprover } from '@aab/approver';
import { spawnSigner } from '@aab/signer/client';
import { afterEach, describe, expect, it } from 'vitest';
import { AgentRegistry } from '../src/agents.ts';
import { Broker, type FillTarget } from '../src/broker.ts';
import { openDb } from '../src/db.ts';
import { addPasswordItem } from '../src/passwords.ts';

const cleanups: (() => Promise<void> | void)[] = [];
afterEach(async () => {
  while (cleanups.length) await cleanups.pop()?.();
});

async function setup() {
  const dir = mkdtempSync(join(tmpdir(), 'inv6-ch-'));
  const key = ApproverKey.generate();
  const signer = await spawnSigner({
    socketPath: join(dir, 's.sock'),
    storePath: join(dir, 'keys'),
    passphrase: 'pw',
    trustedApproverKeys: key.trustEntry(),
  });
  const db = openDb(join(dir, 'db.sqlite'));
  const seen: ApprovalRequest[] = [];
  const hooks: { deciding?: () => void } = {};
  const approver = new ScriptedApprover(key, (r) => {
    seen.push(r);
    hooks.deciding?.();
    return true;
  });
  const broker = new Broker({ db, signer: signer.client, approver });
  cleanups.push(async () => {
    await signer.stop();
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });
  return { dir, signer, db, broker, seen, hooks };
}

const denials = (broker: Broker) =>
  broker.audit
    .all()
    .filter((r) => r.event_type === 'denied')
    .map((r) => JSON.parse(r.payload_json).reason as string);

describe('invariant 6 / policy: a trailing-dot host is not a verified origin (review L2)', () => {
  it('a deny rule on example.com denies https://example.com. before any prompt', async () => {
    const { signer, db, broker, seen } = await setup();
    await addPasswordItem(
      { signer: signer.client, db },
      { site: 'example.com', username: 'u', password: 'pw-secret-123' },
    );
    const a = new AgentRegistry(db).add('agent');
    const A = { id: a.id, name: a.name };
    broker.policy.set('example.com', '*', { mode: 'deny' });
    broker.intents.record(A.id, 'sign in');
    let performed = 0;
    const target = (origin: string, host: string): FillTarget => ({
      origin: { origin, host },
      first: 'password',
      perform: async ({ release }) => {
        performed++;
        await release('password');
        return { outcome: 'success' };
      },
    });
    expect(await broker.fill(A, target('https://example.com', 'example.com'))).toBe('denied');
    expect(await broker.fill(A, target('https://example.com.', 'example.com.'))).toBe('denied');
    expect(await broker.fill(A, target('https://EXAMPLE.com', 'EXAMPLE.com'))).toBe('denied');
    expect(seen).toEqual([]);
    expect(performed).toBe(0);
    expect(denials(broker)).toEqual(['policy_deny', 'non_canonical_host', 'origin_mismatch']);
  });

  it('a page at https://login.example.com./ gets no passkey and no prompt', async () => {
    const { db, broker, seen } = await setup();
    const a = new AgentRegistry(db).add('agent');
    broker.intents.record(a.id, 'sign in');
    const res = await broker.handleWebAuthn(
      {
        kind: 'get',
        frame: {
          url: 'https://login.example.com./signin',
          isMainFrame: true,
          securityOrigin: 'https://login.example.com.',
        },
        mediation: null,
        options: { challenge: { $b: randomBytes(32).toString('base64url') } },
      },
      { id: a.id, name: a.name },
    );
    expect(res).toEqual({ ok: false, name: 'NotAllowedError' });
    expect(seen).toEqual([]);
    expect(denials(broker)).toEqual(['non_canonical_host']);
  });
});

describe('invariant 6: a revoke from another process stops the broker (review L3)', () => {
  it('a revoked agent gets no signature, even inside an allow-for grant', async () => {
    const { dir, db, broker, seen } = await setup();
    const a = new AgentRegistry(db).add('agent');
    const A = { id: a.id, name: a.name };
    const ORIGIN = 'https://login.example.com';
    const b = (n: number) => ({ $b: randomBytes(n).toString('base64url') });
    const frame = { url: `${ORIGIN}/signin`, isMainFrame: true, securityOrigin: ORIGIN };
    broker.intents.record(A.id, 'sign in to example');
    const c = await broker.handleWebAuthn(
      {
        kind: 'create',
        frame,
        mediation: null,
        options: {
          challenge: b(32),
          rp: { id: 'example.com', name: 'E' },
          user: { id: b(16), name: 'u', displayName: 'u' },
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        },
      },
      A,
    );
    expect(c.ok).toBe(true);
    broker.policy.set(ORIGIN, A.id, { mode: 'allow-for', allowForMs: 600_000 });
    const get = () =>
      broker.handleWebAuthn(
        { kind: 'get', frame, mediation: null, options: { challenge: b(32), rpId: 'example.com' } },
        A,
      );
    expect((await get()).ok).toBe(true);
    expect(broker.grants.size()).toBe(1);
    expect((await get()).ok).toBe(true);
    const prompts = seen.length;
    expect(prompts).toBe(2);

    const cli = openDb(join(dir, 'db.sqlite'));
    cleanups.push(() => cli.close());
    expect(new AgentRegistry(cli).revoke(A.id)).toBe(true);

    const after = await get();
    expect(after).toEqual({ ok: false, name: 'NotAllowedError' });
    expect(seen.length).toBe(prompts);
    expect(denials(broker).at(-1)).toBe('agent_revoked');
    expect(broker.grants.size()).toBe(0);
  });

  it('revoked while the user approves: nothing is signed', async () => {
    const { dir, db, broker, hooks } = await setup();
    const a = new AgentRegistry(db).add('agent');
    const A = { id: a.id, name: a.name };
    const ORIGIN = 'https://login.example.com';
    const b = (n: number) => ({ $b: randomBytes(n).toString('base64url') });
    const frame = { url: `${ORIGIN}/signin`, isMainFrame: true, securityOrigin: ORIGIN };
    broker.intents.record(A.id, 'sign in to example');
    const cli = openDb(join(dir, 'db.sqlite'));
    cleanups.push(() => cli.close());
    hooks.deciding = () => {
      new AgentRegistry(cli).revoke(A.id);
    };
    const res = await broker.handleWebAuthn(
      {
        kind: 'create',
        frame,
        mediation: null,
        options: {
          challenge: b(32),
          rp: { id: 'example.com', name: 'E' },
          user: { id: b(16), name: 'u', displayName: 'u' },
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        },
      },
      A,
    );
    expect(res.ok).toBe(false);
    expect(denials(broker).at(-1)).toBe('agent_revoked');
    expect(broker.credentials.passkeysForRp('example.com')).toHaveLength(0);
  });
});
