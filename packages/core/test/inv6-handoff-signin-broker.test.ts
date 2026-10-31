import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign } from 'node:crypto';
import { rmSync } from 'node:fs';
import { join } from 'node:path';
import type { DatabaseSync } from 'node:sqlite';
import {
  type ApprovalDecision,
  type ApprovalRequest,
  type Approver,
  ApproverKey,
  buildStatement,
  requestProblem,
} from '@aab/approver';
import {
  type ApprovalStatement,
  approvalChallenge,
  fillScope,
  type WebAuthnApproval,
} from '@aab/signer/approval';
import { type SpawnedSigner, spawnSigner } from '@aab/signer/client';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  type AgentIdentity,
  Broker,
  type FillTarget,
  HANDOFF_SIGNIN_GRANT_MS,
  type HandoffSignInOffer,
  type SignerPort,
} from '../src/broker.ts';
import { openDb } from '../src/db.ts';
import { addPasswordItem } from '../src/passwords.ts';
import { ALL_AGENTS } from '../src/policy.ts';
import { registerAgents, tmpDir } from './harness.ts';

const A1: AgentIdentity = { id: 'agent-1', name: 'agent one' };
const A2: AgentIdentity = { id: 'agent-2', name: 'agent two' };
const ORIGIN = 'https://login.example.com';
const AT = { origin: ORIGIN, host: 'login.example.com' };
const PW = 'alice-handoff-signin-pw-1!';
const APPROVER_ORIGIN = 'https://approver.example.net';

function softPhone() {
  const credentialId = randomBytes(32).toString('base64url');
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' });
  let counter = 0;
  return {
    key: {
      credentialId,
      x: jwk.x as string,
      y: jwk.y as string,
      rpId: 'approver.example.net',
      origin: APPROVER_ORIGIN,
    },
    approve(statement: ApprovalStatement): WebAuthnApproval {
      const cd = Buffer.from(
        JSON.stringify({
          type: 'webauthn.get',
          challenge: approvalChallenge(statement),
          origin: APPROVER_ORIGIN,
          crossOrigin: false,
        }),
      );
      const n = Buffer.alloc(4);
      n.writeUInt32BE(++counter);
      const ad = Buffer.concat([
        createHash('sha256').update('approver.example.net').digest(),
        Buffer.of(0x05),
        n,
      ]);
      const sig = sign('sha256', Buffer.concat([ad, createHash('sha256').update(cd).digest()]), {
        key: privateKey,
        dsaEncoding: 'der',
      });
      return {
        statement,
        approverKeyId: credentialId,
        webauthn: {
          authenticatorData: ad.toString('base64url'),
          clientDataJSON: cd.toString('base64url'),
          signature: sig.toString('base64url'),
        },
      };
    },
  };
}

type Mode = 'approve' | 'deny' | 'ed25519' | 'no-device' | 'longer-grant';

class PhoneLikeApprover implements Approver {
  readonly seen: ApprovalRequest[] = [];
  mode: Mode = 'approve';
  readonly phone = softPhone();
  private readonly ed = ApproverKey.generate();
  async request(req: ApprovalRequest): Promise<ApprovalDecision> {
    this.seen.push(req);
    const problem = requestProblem(req);
    if (problem) return { approved: false, reason: problem };
    if (this.mode === 'deny') return { approved: false, reason: 'user_denied' };
    if (this.mode === 'ed25519') {
      return { approved: true, approval: this.ed.approve(req, { userVerified: false }) };
    }
    let s = buildStatement(req, { userVerified: true });
    if (this.mode === 'longer-grant' && s.grant) {
      s = { ...s, grant: { ...s.grant, until: s.grant.until + 60_000 } };
    }
    const approval = this.phone.approve(s);
    return this.mode === 'no-device'
      ? { approved: true, approval }
      : { approved: true, approval, deviceId: 'dev-1' };
  }
}

const target = (origin = AT): FillTarget & { released: number } => {
  const t = {
    origin,
    first: 'password' as const,
    released: 0,
    async perform(ctx: Parameters<FillTarget['perform']>[0]) {
      await ctx.release('password');
      t.released++;
      return { outcome: 'success' as const };
    },
  };
  return t;
};

describe('P3b at the broker: one approval for a human check and the sign-in after it', () => {
  let dir: string;
  let db: DatabaseSync;
  let signer: SpawnedSigner;
  let broker: Broker;
  let approver: PhoneLikeApprover;
  let itemId: string;

  const port: SignerPort = {
    createCredential: (r) => signer.client.createCredential(r),
    sign: (r) => signer.client.sign(r),
    releaseSecret: (r) => signer.client.releaseSecret(r),
    acceptHandoffGrant: (a) => signer.client.acceptHandoffGrant(a),
    dropGrant: (g) => signer.client.dropGrant(g),
  };
  const events = () =>
    broker.audit.all().map((r) => ({ type: r.event_type, p: JSON.parse(r.payload_json) }));
  const offerFor = (agent = A1, at = AT): HandoffSignInOffer => {
    const r = broker.handoffSignInOffer(agent, at);
    if (!r.ok) throw new Error(r.reason);
    return r.offer;
  };
  const combinedApproval = async (agent = A1) => {
    const id = randomUUID();
    const r = await broker.approveHandoffSignIn(agent, offerFor(agent), { id });
    if (!r.ok) throw new Error(r.reason);
    expect(r.deviceId).toBe('dev-1');
    return { id, grantId: r.grantId };
  };
  const signerUse = (grantId: string, requestId = randomUUID()) =>
    signer.client.releaseSecret({
      itemId: (broker.credentials.passwordsForDomain('example.com')[0] as { signer_ref: string })
        .signer_ref,
      field: 'password',
      approval: {
        statement: {
          v: 1,
          requestId,
          kind: 'fill',
          verifiedOrigin: ORIGIN,
          rpId: 'example.com',
          credentialId: itemId,
          intentHash: 'aW50ZW50',
          clientDataHash: createHash('sha256')
            .update(fillScope(['password']))
            .digest('base64url'),
          userVerified: false,
          issuedAt: Date.now(),
          expiresAt: Date.now() + 60_000,
        },
        grantId,
        agentId: A1.id,
      },
    });

  beforeAll(async () => {
    dir = tmpDir();
    approver = new PhoneLikeApprover();
    signer = await spawnSigner({
      socketPath: join(dir, 'run', 's.sock'),
      storePath: join(dir, 'keys'),
      passphrase: 'pw',
      trustedApproverKeys: {},
      highRiskDomains: ['bank.example.net'],
    });
    await signer.client.addApprover({ key: approver.phone.key });
    db = openDb(join(dir, 'db.sqlite'));
    registerAgents(db, A1, A2);
    broker = new Broker({ db, signer: port, approver, highRiskDomains: ['bank.example.net'] });
    itemId = (
      await addPasswordItem(
        { signer: signer.client, db },
        { site: 'example.com', username: 'alice', password: PW },
      )
    ).id;
    await addPasswordItem(
      { signer: signer.client, db },
      { site: 'bank.example.net', username: 'alice', password: PW },
    );
  });
  afterAll(async () => {
    await signer.stop();
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });
  beforeEach(() => {
    db.exec('DELETE FROM policies');
    approver.mode = 'approve';
    broker.grants.dropAgent(A1.id);
    broker.grants.dropAgent(A2.id);
    broker.intents.record(A1.id, 'sign me in to example');
    broker.intents.record(A2.id, 'sign me in to example');
  });

  it('eligibility is computed from trusted state only (policy, high-risk, credential, intent)', () => {
    expect(offerFor()).toMatchObject({
      kind: 'fill',
      verifiedOrigin: ORIGIN,
      rpId: 'example.com',
      fields: ['password'],
      credentialType: 'password',
    });
    expect(
      broker.handoffSignInOffer(A1, {
        origin: 'https://bank.example.net',
        host: 'bank.example.net',
      }),
    ).toEqual({ ok: false, reason: 'high_risk' });
    broker.policy.set('example.com', ALL_AGENTS, { mode: 'ask-strong' });
    expect(broker.handoffSignInOffer(A1, AT)).toEqual({ ok: false, reason: 'policy_ask_strong' });
    broker.policy.set('example.com', ALL_AGENTS, { mode: 'deny' });
    expect(broker.handoffSignInOffer(A1, AT)).toEqual({ ok: false, reason: 'policy_deny' });
    broker.policy.set('example.com', ALL_AGENTS, { mode: 'allow-for', allowForMs: 60_000 });
    expect(broker.handoffSignInOffer(A1, AT).ok).toBe(true);
    db.exec('DELETE FROM policies');
    expect(
      broker.handoffSignInOffer(A1, {
        origin: 'https://other.example.org',
        host: 'other.example.org',
      }),
    ).toEqual({ ok: false, reason: 'no_credential' });
    expect(
      broker.handoffSignInOffer(A1, { origin: `${ORIGIN}/x`, host: 'login.example.com' }),
    ).toEqual({
      ok: false,
      reason: 'not_eligible',
    });
  });

  it('invariant 4: no live intent, no combined card (and the approver is never asked)', async () => {
    db.exec(`DELETE FROM intents WHERE agent_id = '${A1.id}'`);
    expect(broker.handoffSignInOffer(A1, AT)).toEqual({ ok: false, reason: 'no_live_intent' });
    broker.intents.record(A1.id, 'sign me in to example');
    const offer = offerFor();
    db.exec(`DELETE FROM intents WHERE agent_id = '${A1.id}'`);
    const asked = approver.seen.length;
    expect(await broker.approveHandoffSignIn(A1, offer, { id: randomUUID() })).toEqual({
      ok: false,
      reason: 'no_live_intent',
    });
    expect(approver.seen.length).toBe(asked);
    expect(events().at(-1)).toMatchObject({
      type: 'denied',
      p: { agentId: A1.id, kind: 'handoff.sign-in', reason: 'no_live_intent' },
    });
  });

  it('invariant 5: the card holds only the user-facing fields plus broker-authored text', async () => {
    const { id } = await combinedApproval();
    const req = approver.seen.at(-1) as ApprovalRequest;
    expect(req.display).toEqual({
      intentText: 'sign me in to example',
      intentAt: expect.any(Number),
      verifiedOrigin: ORIGIN,
      agentName: A1.name,
      credentialType: 'password',
      action: 'sign-in',
      handoffSignIn: { withinMs: HANDOFF_SIGNIN_GRANT_MS },
    });
    expect(req.policy).toEqual({ tier: 'ask' });
    expect(req.binding).toMatchObject({
      kind: 'fill',
      rpId: 'example.com',
      grant: { agentId: A1.id, durationMs: HANDOFF_SIGNIN_GRANT_MS, uses: 1 },
      handoff: { id },
    });
    expect(HANDOFF_SIGNIN_GRANT_MS).toBeLessThanOrEqual(7 * 60_000);
  });

  it('invariant 6: the grant is used only after Done, once; then the next sign-in asks again', async () => {
    const { id, grantId } = await combinedApproval();
    const asked = approver.seen.length;
    approver.mode = 'deny';
    expect(await broker.fill(A1, target())).toBe('denied');
    expect(approver.seen.length).toBe(asked + 1);
    broker.handoffEnded(id, 'done');
    const t = target();
    expect(await broker.fill(A1, t)).toBe('success');
    expect(t.released).toBe(1);
    expect(approver.seen.length).toBe(asked + 1);
    const used = events().filter((e) => e.type === 'grant.used');
    expect(used.at(-1)?.p).toMatchObject({
      grantId,
      agentId: A1.id,
      verifiedOrigin: ORIGIN,
      singleUse: true,
      handoffId: id,
    });
    expect(await broker.fill(A1, target())).toBe('denied');
    expect(approver.seen.length).toBe(asked + 2);
    await expect(signerUse(grantId)).rejects.toThrow('grant_used');
  });

  it('bound to the agent and the exact origin; never used under a tightened policy or without an intent', async () => {
    const { id, grantId } = await combinedApproval();
    broker.handoffEnded(id, 'done');
    approver.mode = 'deny';
    const asked = approver.seen.length;
    expect(await broker.fill(A2, target())).toBe('denied');
    expect(
      await broker.fill(A1, target({ origin: 'https://www.example.com', host: 'www.example.com' })),
    ).toBe('denied');
    broker.policy.set('example.com', ALL_AGENTS, { mode: 'ask-strong' });
    expect(await broker.fill(A1, target())).toBe('denied');
    expect(approver.seen.length).toBe(asked + 3);
    db.exec('DELETE FROM policies');
    db.exec(`DELETE FROM intents WHERE agent_id = '${A1.id}'`);
    expect(await broker.fill(A1, target())).toBe('denied');
    expect(events().at(-1)?.p.reason).toBe('no_live_intent');
    broker.intents.record(A1.id, 'sign me in to example');
    approver.mode = 'approve';
    expect(await broker.fill(A1, target())).toBe('success');
    expect(approver.seen.length).toBe(asked + 3);
    expect(
      events()
        .filter((e) => e.type === 'grant.used')
        .at(-1)?.p.grantId,
    ).toBe(grantId);
  });

  it('a handoff that ends without Done drops the grant in the core and at the signer', async () => {
    for (const outcome of ['cancelled', 'expired', 'left_site', 'page_closed', 'revoked']) {
      const { id, grantId } = await combinedApproval();
      broker.handoffEnded(id, outcome);
      expect(
        events()
          .filter((e) => e.type === 'grant.dropped')
          .at(-1)?.p,
      ).toEqual({
        grantId,
        handoffId: id,
        reason: `handoff_${outcome}`,
      });
      await expect
        .poll(() =>
          signerUse(grantId).then(
            () => 'used',
            (e) => e.message,
          ),
        )
        .toBe('unknown_grant');
      broker.handoffEnded(id, 'done');
      approver.mode = 'deny';
      expect(await broker.fill(A1, target())).toBe('denied');
      approver.mode = 'approve';
    }
  });

  it('only a phone approval from a named device counts; a widened grant is refused', async () => {
    for (const [mode, reason] of [
      ['ed25519', 'user_verification_required'],
      ['no-device', 'no_device'],
      ['longer-grant', 'unexpected_grant'],
      ['deny', 'approval_user_denied'],
    ] as const) {
      approver.mode = mode;
      const before = events().filter((e) => e.type === 'grant.created').length;
      expect(await broker.approveHandoffSignIn(A1, offerFor(), { id: randomUUID() })).toEqual({
        ok: false,
        reason,
      });
      expect(events().filter((e) => e.type === 'grant.created').length).toBe(before);
    }
    approver.mode = 'approve';
    const ctl = new AbortController();
    ctl.abort();
    expect(
      await broker.approveHandoffSignIn(A1, offerFor(), { id: randomUUID(), signal: ctl.signal }),
    ).toEqual({ ok: false, reason: 'handoff_ended' });
  });

  it('a sign-in already done for this request keeps a later check a plain handoff', async () => {
    approver.mode = 'approve';
    expect(await broker.fill(A1, target())).toBe('success');
    expect(broker.handoffSignInOffer(A1, AT)).toEqual({
      ok: false,
      reason: 'signed_in_for_intent',
    });
    broker.intents.record(A1.id, 'sign me in to example again');
    expect(broker.handoffSignInOffer(A1, AT).ok).toBe(true);
  });

  it('a passkey sign-in: one approval, then one signature without a prompt', async () => {
    const origin = 'https://passkey.example.org';
    const frame = { url: `${origin}/signin`, isMainFrame: true, securityOrigin: origin };
    const b = (n: number) => ({ $b: randomBytes(n).toString('base64url') });
    broker.intents.record(A1.id, 'register and sign in');
    const created = await broker.handleWebAuthn(
      {
        kind: 'create',
        frame,
        mediation: null,
        options: {
          challenge: b(32),
          rp: { id: 'passkey.example.org', name: 'P' },
          user: { id: b(16), name: 'u', displayName: 'u' },
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        },
      },
      A1,
    );
    expect(created.ok).toBe(true);
    broker.intents.record(A1.id, 'sign in with the passkey');
    const at = { origin, host: 'passkey.example.org' };
    const r = broker.handoffSignInOffer(A1, at);
    expect(r.ok && r.offer.kind).toBe('webauthn.get');
    const id = randomUUID();
    const ok = await broker.approveHandoffSignIn(A1, (r as { offer: HandoffSignInOffer }).offer, {
      id,
    });
    expect(ok.ok).toBe(true);
    broker.handoffEnded(id, 'done');
    const asked = approver.seen.length;
    const get = () =>
      broker.handleWebAuthn(
        { kind: 'get', frame, mediation: null, options: { challenge: b(32) } },
        A1,
      );
    expect((await get()).ok).toBe(true);
    expect(approver.seen.length).toBe(asked);
    approver.mode = 'deny';
    expect((await get()).ok).toBe(false);
    expect(approver.seen.length).toBe(asked + 1);
  });

  it('invariant 10: request, approval, grant.created / armed / used / dropped are in the chain', async () => {
    const types = new Set(events().map((e) => e.type));
    for (const t of [
      'request',
      'approval',
      'grant.created',
      'grant.armed',
      'grant.used',
      'grant.dropped',
    ]) {
      expect(types.has(t)).toBe(true);
    }
    for (const e of events().filter((x) => x.type.startsWith('grant.'))) {
      expect(JSON.stringify(e.p)).not.toContain(PW);
    }
    expect(broker.audit.verify()).toBeNull();
  });
});
