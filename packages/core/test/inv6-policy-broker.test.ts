import { randomBytes } from 'node:crypto';
import { rmSync } from 'node:fs';
import { join } from 'node:path';
import type { DatabaseSync } from 'node:sqlite';
import {
  type ApprovalDecision,
  type ApprovalRequest,
  type Approver,
  ApproverKey,
  ScriptedApprover,
} from '@aab/approver';
import { type SpawnedSigner, spawnSigner } from '@aab/signer/client';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { type AgentIdentity, Broker, type SignerPort } from '../src/broker.ts';
import { openDb } from '../src/db.ts';
import { ALL_AGENTS } from '../src/policy.ts';
import { registerAgents, tmpDir } from './harness.ts';

const A1: AgentIdentity = { id: 'agent-1', name: 'agent one' };
const A2: AgentIdentity = { id: 'agent-2', name: 'agent two' };
const ORIGIN = 'https://login.example.com';
const frame = (url = `${ORIGIN}/signin`) => ({
  url,
  isMainFrame: true,
  securityOrigin: new URL(url).origin,
});
const bytes = (n: number) => ({ $b: randomBytes(n).toString('base64url') });
const flagsOf = (res: Awaited<ReturnType<Broker['handleWebAuthn']>>) =>
  res.ok
    ? (Buffer.from(res.credential.response.authenticatorData as string, 'base64url')[32] ?? 0)
    : -1;

class TestApprover implements Approver {
  readonly seen: ApprovalRequest[] = [];
  tamper: ((req: ApprovalRequest) => ApprovalRequest) | null = null;
  private readonly inner: ScriptedApprover;
  private readonly key: ApproverKey;
  constructor(key: ApproverKey) {
    this.key = key;
    this.inner = new ScriptedApprover(key);
  }
  async request(req: ApprovalRequest): Promise<ApprovalDecision> {
    this.seen.push(req);
    if (this.tamper)
      return {
        approved: true,
        approval: this.key.approve(this.tamper(req), { userVerified: false }),
      };
    return this.inner.request(req);
  }
}

describe('invariant 6: policy at the broker (deny, allow-for grants, ask-strong)', () => {
  let dir: string;
  let db: DatabaseSync;
  let key: ApproverKey;
  let signer: SpawnedSigner;
  let broker: Broker;
  let approver: TestApprover;

  const startSigner = () =>
    spawnSigner({
      socketPath: join(dir, 'run', 's.sock'),
      storePath: join(dir, 'keys'),
      passphrase: 'pw',
      trustedApproverKeys: key.trustEntry(),
      highRiskDomains: ['bank.example.net'],
    });
  const port: SignerPort = {
    createCredential: (r) => signer.client.createCredential(r),
    sign: (r) => signer.client.sign(r),
    releaseSecret: (r) => signer.client.releaseSecret(r),
  };

  const get = (agent = A1, url = `${ORIGIN}/signin`) =>
    broker.handleWebAuthn(
      {
        kind: 'get',
        frame: frame(url),
        mediation: null,
        options: { challenge: bytes(32), rpId: 'example.com' },
      },
      agent,
    );
  const events = () =>
    broker.audit.all().map((r) => ({ type: r.event_type, p: JSON.parse(r.payload_json) }));
  const lastDenied = () =>
    events()
      .filter((e) => e.type === 'denied')
      .at(-1)?.p.reason;

  beforeAll(async () => {
    dir = tmpDir();
    key = ApproverKey.generate();
    approver = new TestApprover(key);
    signer = await startSigner();
    db = openDb(join(dir, 'db.sqlite'));
    registerAgents(db, A1, A2);
    broker = new Broker({ db, signer: port, approver, highRiskDomains: ['bank.example.net'] });
    broker.intents.record(A1.id, 'sign in to example');
    const created = await broker.handleWebAuthn(
      {
        kind: 'create',
        frame: frame(),
        mediation: null,
        options: {
          challenge: bytes(32),
          rp: { id: 'example.com', name: 'Example' },
          user: { id: bytes(16), name: 'u', displayName: 'u' },
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        },
      },
      A1,
    );
    expect(created.ok).toBe(true);
  });
  afterAll(async () => {
    await signer.stop();
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });
  beforeEach(() => {
    db.exec('DELETE FROM policies');
    broker.grants.dropAgent(A1.id);
    broker.grants.dropAgent(A2.id);
    approver.tamper = null;
    broker.intents.record(A1.id, 'sign in to example');
    broker.intents.record(A2.id, 'sign in to example');
  });

  it('deny: refused before any prompt or credential lookup, and audited', async () => {
    broker.policy.set('example.com', ALL_AGENTS, { mode: 'deny' });
    const before = approver.seen.length;
    expect(await get()).toEqual({ ok: false, name: 'NotAllowedError' });
    expect(approver.seen.length).toBe(before);
    const ev = events();
    expect(ev.at(-2)).toMatchObject({
      type: 'policy',
      p: {
        agentId: A1.id,
        verifiedOrigin: ORIGIN,
        mode: 'deny',
        rules: [{ pattern: 'example.com', agentId: '*' }],
      },
    });
    expect(ev.at(-1)).toMatchObject({ type: 'denied', p: { reason: 'policy_deny' } });
  });

  it('allow-for: one prompt that shows the window, then sign-ins from the grant, each audited', async () => {
    broker.policy.set(ORIGIN, A1.id, { mode: 'allow-for', allowForMs: 10 * 60_000 });
    const before = approver.seen.length;
    const first = await get();
    expect(first.ok).toBe(true);
    expect(approver.seen.length).toBe(before + 1);
    const req = approver.seen.at(-1) as ApprovalRequest;
    expect(req.display.allowForMs).toBe(10 * 60_000);
    expect(req.binding.grant).toEqual({ agentId: A1.id, durationMs: 10 * 60_000 });
    expect(req.policy.tier).toBe('ask');
    expect(broker.grants.size()).toBe(1);
    const created = events().find((e) => e.type === 'grant.created');
    expect(created?.p).toMatchObject({ agentId: A1.id, verifiedOrigin: ORIGIN });

    for (let i = 0; i < 2; i++) {
      const again = await get();
      expect(again.ok).toBe(true);
      expect(flagsOf(again) & 0x04).toBe(0);
    }
    expect(approver.seen.length).toBe(before + 1);
    const used = events().filter((e) => e.type === 'grant.used');
    expect(used).toHaveLength(2);
    expect(used[0]?.p).toMatchObject({
      grantId: created?.p.grantId,
      agentId: A1.id,
      verifiedOrigin: ORIGIN,
    });
    expect(events().filter((e) => e.type === 'passkey.signed').length).toBeGreaterThanOrEqual(3);
  });

  it('allow-for at the 24 hour cap: the approver signs it, the signer records it, later sign-ins need no prompt', async () => {
    const cap = 24 * 60 * 60_000;
    const count = (type: string) => events().filter((e) => e.type === type).length;
    broker.policy.set(ORIGIN, A1.id, { mode: 'allow-for', allowForMs: cap });
    const before = approver.seen.length;
    const createdBefore = count('grant.created');
    const usedBefore = count('grant.used');
    expect((await get()).ok).toBe(true);
    const req = approver.seen.at(-1) as ApprovalRequest;
    expect(req.display.allowForMs).toBe(cap);
    expect(req.binding.grant).toEqual({ agentId: A1.id, durationMs: cap });
    expect(count('grant.created')).toBe(createdBefore + 1);
    expect((await get()).ok).toBe(true);
    expect(approver.seen.length).toBe(before + 1);
    expect(count('grant.used')).toBe(usedBefore + 1);
    expect(() =>
      broker.policy.set(ORIGIN, A1.id, { mode: 'allow-for', allowForMs: cap + 1 }),
    ).toThrow(/between 1s and 24h/);
  });

  it('inside the window a login still needs a live intent (invariant 4), and is denied unprompted without one', async () => {
    broker.policy.set(ORIGIN, A1.id, { mode: 'allow-for', allowForMs: 10 * 60_000 });
    expect((await get()).ok).toBe(true);
    db.exec('DELETE FROM intents');
    const before = approver.seen.length;
    const usedBefore = events().filter((e) => e.type === 'grant.used').length;
    expect(await get()).toEqual({ ok: false, name: 'NotAllowedError' });
    expect(lastDenied()).toBe('no_live_intent');
    expect(approver.seen.length).toBe(before);
    expect(events().filter((e) => e.type === 'grant.used').length).toBe(usedBefore);
  });

  it('the grant is per agent, per exact origin, and only while the policy still says allow-for', async () => {
    broker.policy.set('example.com', ALL_AGENTS, { mode: 'allow-for', allowForMs: 10 * 60_000 });
    expect((await get()).ok).toBe(true);
    const n = approver.seen.length;
    expect((await get()).ok).toBe(true);
    expect(approver.seen.length).toBe(n);
    expect((await get(A2)).ok).toBe(true);
    expect(approver.seen.length).toBe(n + 1);
    expect(approver.seen.at(-1)?.binding.grant?.agentId).toBe(A2.id);
    expect((await get(A1, 'https://www.example.com/signin')).ok).toBe(true);
    expect(approver.seen.length).toBe(n + 2);
    broker.policy.set(ORIGIN, ALL_AGENTS, { mode: 'ask' });
    expect((await get()).ok).toBe(true);
    expect(approver.seen.length).toBe(n + 3);
    expect(approver.seen.at(-1)?.binding.grant).toBeUndefined();
    expect(approver.seen.at(-1)?.display.allowForMs).toBeUndefined();
  });

  it('shortening the window applies to grants already made', async () => {
    broker.policy.set(ORIGIN, A1.id, { mode: 'allow-for', allowForMs: 10 * 60_000 });
    expect((await get()).ok).toBe(true);
    const n = approver.seen.length;
    broker.policy.set(ORIGIN, A1.id, { mode: 'allow-for', allowForMs: 1000 });
    await new Promise((r) => setTimeout(r, 1100));
    expect((await get()).ok).toBe(true);
    expect(approver.seen.length).toBe(n + 1);
  });

  it('ask-strong by policy: the approver must verify the user; an Ed25519 approval is refused', async () => {
    broker.policy.set('example.com', ALL_AGENTS, { mode: 'ask-strong' });
    broker.policy.set(ORIGIN, A1.id, { mode: 'allow-for', allowForMs: 60_000 });
    expect(await get()).toEqual({ ok: false, name: 'NotAllowedError' });
    const req = approver.seen.at(-1) as ApprovalRequest;
    expect(req.policy.tier).toBe('ask-strong');
    expect(req.binding.grant).toBeUndefined();
    expect(req.display.allowForMs).toBeUndefined();
    expect(lastDenied()).toBe('user_verification_required');
  });

  it('a high-risk origin never gets a grant, whatever the policy says', async () => {
    broker.policy.set('bank.example.net', ALL_AGENTS, { mode: 'allow-for', allowForMs: 60_000 });
    broker.credentials.insertPasskey({
      id: 'bank-cred',
      rpId: 'bank.example.net',
      registrableDomain: 'example.net',
      userHandle: 'dQ',
      username: null,
      publicKey: 'AA',
      now: Date.now(),
    });
    const res = await broker.handleWebAuthn(
      {
        kind: 'get',
        frame: frame('https://bank.example.net/login'),
        mediation: null,
        options: { challenge: bytes(32) },
      },
      A1,
    );
    expect(res.ok).toBe(false);
    const req = approver.seen.at(-1) as ApprovalRequest;
    expect(req.display.verifiedOrigin).toBe('https://bank.example.net');
    expect(req.policy.tier).toBe('ask-strong');
    expect(req.binding.grant).toBeUndefined();
    expect(req.display.allowForMs).toBeUndefined();
  });

  it('an approval whose grant differs from the one asked for is refused', async () => {
    broker.policy.set(ORIGIN, A2.id, { mode: 'allow-for', allowForMs: 60_000 });
    approver.tamper = (r) => ({
      ...r,
      binding: { ...r.binding, grant: { agentId: A1.id, durationMs: 60_000 } },
    });
    expect((await get(A2)).ok).toBe(false);
    expect(lastDenied()).toBe('unexpected_grant');
    broker.policy.set(ORIGIN, A2.id, { mode: 'ask' });
    approver.tamper = (r) => ({
      ...r,
      display: { ...r.display, allowForMs: 60_000 },
      binding: { ...r.binding, grant: { agentId: A2.id, durationMs: 60_000 } },
    });
    expect((await get(A2)).ok).toBe(false);
    expect(lastDenied()).toBe('unexpected_grant');
  });

  it('after a signer restart the grant is refused, forgotten, and the next login asks', async () => {
    broker.policy.set(ORIGIN, A1.id, { mode: 'allow-for', allowForMs: 10 * 60_000 });
    expect((await get()).ok).toBe(true);
    await signer.stop();
    signer = await startSigner();
    const n = approver.seen.length;
    expect(await get()).toEqual({ ok: false, name: 'NotAllowedError' });
    expect(approver.seen.length).toBe(n);
    expect(lastDenied()).toBe('grant_refused');
    expect(
      events()
        .filter((e) => e.type === 'grant.dropped')
        .at(-1)?.p.reason,
    ).toBe('unknown_grant');
    const r = await get();
    expect(lastDenied()).toBe('grant_refused');
    expect(r.ok).toBe(true);
    expect(approver.seen.length).toBe(n + 1);
  });

  it('registration always asks, even under allow-for', async () => {
    broker.policy.set('example.com', ALL_AGENTS, { mode: 'allow-for', allowForMs: 60_000 });
    const res = await broker.handleWebAuthn(
      {
        kind: 'create',
        frame: frame(),
        mediation: null,
        options: {
          challenge: bytes(32),
          rp: { id: 'example.com', name: 'Example' },
          user: { id: bytes(16), name: 'v', displayName: 'v' },
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        },
      },
      A1,
    );
    expect(res.ok).toBe(true);
    const req = approver.seen.at(-1) as ApprovalRequest;
    expect(req.binding.kind).toBe('webauthn.create');
    expect(req.binding.grant).toBeUndefined();
    expect(broker.audit.verify()).toBeNull();
  });
});
