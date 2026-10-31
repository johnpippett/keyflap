import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { beforeEach, describe, expect, it } from 'vitest';
import {
  type ApprovalStatement,
  type FillField,
  fillScope,
  type GrantedApproval,
  HANDOFF_GRANT_MAX_MS,
  handoffSignInClientDataHash,
  type SignedApproval,
  sha256B64url,
} from '../src/approval.ts';
import { KeyStore } from '../src/keystore.ts';
import { SignerHandler } from '../src/server.ts';
import { authData, clientData, statement, testApprover, testPhone, tmpDir } from './helpers.ts';

type Res = { ok: true; result: Record<string, unknown> } | { ok: false; error: string };

const DOMAIN = 'example.com';
const ORIGIN = 'https://login.example.com';
const RISKY = 'example-bank.net';
const AGENT = 'agent-1';
const PASSWORD = 'correct horse battery staple';
const SEED = 'JBSWY3DPEHPK3PXP';
const HANDOFF = randomUUID();

describe('invariant 6 (P3b): the single-use grant of a combined human check + sign-in approval', () => {
  let handler: SignerHandler;
  let store: KeyStore;
  let storePath: string;
  let now: number;
  let phone: ReturnType<typeof testPhone>;
  let itemId: string;
  let riskyItemId: string;
  let credentialId: string;
  let logs: { event: string; fields: Record<string, unknown> }[];

  const open = (trusted: Record<string, string> = {}) => {
    store = KeyStore.open(storePath, 'pw');
    handler = new SignerHandler({
      store,
      trustedApproverKeys: trusted,
      highRiskDomains: [RISKY],
      now: () => now,
      log: (event, fields) => logs.push({ event, fields }),
    });
  };
  const call = (req: unknown) => handler.handle(req as never) as Res;

  const combinedFill = (
    over: Partial<ApprovalStatement> = {},
    o: { item?: string; origin?: string; rpId?: string; fields?: FillField[] } = {},
  ): ApprovalStatement => ({
    ...statement({ clientDataJSON: '' }),
    kind: 'fill',
    verifiedOrigin: o.origin ?? ORIGIN,
    rpId: o.rpId ?? DOMAIN,
    credentialId: o.item ?? itemId,
    clientDataHash: sha256B64url(fillScope(o.fields ?? ['password', 'totp'])),
    userVerified: true,
    issuedAt: now,
    expiresAt: now + 60_000,
    grant: { agentId: AGENT, until: now + HANDOFF_GRANT_MAX_MS, uses: 1 },
    handoff: { id: HANDOFF },
    ...over,
  });

  const accept = (approval: SignedApproval) => call({ op: 'accept_handoff_grant', approval });

  const fillUse = (
    grantId: string,
    o: { requestId?: string; agentId?: string; origin?: string; item?: string } = {},
  ): GrantedApproval => ({
    statement: {
      ...statement({ clientDataJSON: '' }),
      requestId: o.requestId ?? randomUUID(),
      kind: 'fill',
      verifiedOrigin: o.origin ?? ORIGIN,
      rpId: DOMAIN,
      credentialId: o.item ?? itemId,
      clientDataHash: sha256B64url(fillScope(['password', 'totp'])),
      userVerified: false,
      issuedAt: now,
      expiresAt: now + 60_000,
    },
    grantId,
    agentId: o.agentId ?? AGENT,
  });
  const release = (field: FillField, approval: SignerAuthorizationLike, item = itemId) =>
    call({ op: 'release_secret', itemId: item, field, approval });

  const grantFill = (over: Partial<ApprovalStatement> = {}): string => {
    const s = combinedFill(over);
    const r = accept(phone.approve(s));
    if (!r.ok) throw new Error(r.error);
    expect(r.result).toEqual({ grantId: s.requestId, until: s.grant?.until });
    return s.requestId;
  };

  beforeEach(() => {
    now = Date.now();
    logs = [];
    storePath = join(tmpDir(), 'keys');
    phone = testPhone();
    open();
    expect(call({ op: 'add_approver', key: phone.key }).ok).toBe(true);
    const item = call({
      op: 'store_item',
      domain: DOMAIN,
      password: PASSWORD,
      totp: { secret: SEED },
    });
    if (!item.ok) throw new Error(item.error);
    itemId = item.result.itemId as string;
    const risky = call({ op: 'store_item', domain: RISKY, password: PASSWORD });
    if (!risky.ok) throw new Error(risky.error);
    riskyItemId = risky.result.itemId as string;
    credentialId = store.createP256(DOMAIN, 'dXNlcg').credentialId;
  });

  it('records the grant without releasing anything; one fill uses it (both fields), then it is spent', () => {
    const grantId = grantFill();
    expect(logs.some((l) => l.event === 'grant_recorded' && l.fields.handoffId === HANDOFF)).toBe(
      true,
    );
    expect(logs.some((l) => l.event === 'released')).toBe(false);
    const first = fillUse(grantId);
    expect(release('password', first)).toEqual({ ok: true, result: { value: PASSWORD } });
    expect(release('totp', first).ok).toBe(true);
    expect(release('password', first)).toEqual({ ok: false, error: 'approval_replayed' });
    expect(release('password', fillUse(grantId))).toEqual({ ok: false, error: 'grant_used' });
    expect(release('totp', fillUse(grantId))).toEqual({ ok: false, error: 'grant_used' });
  });

  it('a passkey sign-in: the statement binds the handoff, one signature, then spent', () => {
    const s = combinedFill(
      {
        kind: 'webauthn.get',
        credentialId,
        clientDataHash: handoffSignInClientDataHash(HANDOFF),
      },
      {},
    );
    const r = accept(phone.approve(s));
    expect(r.ok).toBe(true);
    const sign = (requestId: string) => {
      const cd = clientData('webauthn.get', ORIGIN);
      return call({
        op: 'sign',
        credentialId,
        authenticatorData: authData(DOMAIN, 0x01),
        clientDataJSON: cd,
        approval: {
          statement: statement({
            requestId,
            kind: 'webauthn.get',
            verifiedOrigin: ORIGIN,
            rpId: DOMAIN,
            credentialId,
            clientDataJSON: cd,
            issuedAt: now,
            expiresAt: now + 60_000,
          }),
          grantId: s.requestId,
          agentId: AGENT,
        },
      });
    };
    expect(sign(randomUUID()).ok).toBe(true);
    expect(sign(randomUUID())).toEqual({ ok: false, error: 'grant_used' });
    const loose = combinedFill(
      { kind: 'webauthn.get', credentialId, clientDataHash: sha256B64url('x') },
      {},
    );
    expect(accept(phone.approve(loose))).toEqual({
      ok: false,
      error: 'client_data_hash_mismatch',
    });
  });

  it('is bound to the agent, the exact origin and the credential (a mismatch does not spend it)', () => {
    const grantId = grantFill();
    const other = call({ op: 'store_item', domain: DOMAIN, password: 'another-password' });
    if (!other.ok) throw new Error(other.error);
    const otherItem = other.result.itemId as string;
    expect(release('password', fillUse(grantId, { agentId: 'agent-2' }))).toEqual({
      ok: false,
      error: 'grant_agent_mismatch',
    });
    expect(release('password', fillUse(grantId, { origin: 'https://www.example.com' }))).toEqual({
      ok: false,
      error: 'grant_origin_mismatch',
    });
    expect(release('password', fillUse(grantId, { item: otherItem }), otherItem)).toEqual({
      ok: false,
      error: 'grant_credential_mismatch',
    });
    expect(release('password', fillUse(grantId)).ok).toBe(true);
  });

  it('expires on its own (at most 7 minutes), so a lost drop cannot keep it alive', () => {
    const grantId = grantFill();
    now += HANDOFF_GRANT_MAX_MS + 1;
    expect(release('password', fillUse(grantId))).toEqual({ ok: false, error: 'grant_expired' });
    now = Date.now();
    const tooLong = combinedFill({
      grant: { agentId: AGENT, until: now + HANDOFF_GRANT_MAX_MS + 1, uses: 1 },
    });
    expect(accept(phone.approve(tooLong))).toEqual({ ok: false, error: 'grant_not_allowed' });
  });

  it('refused after drop_grant (the handoff was cancelled, expired, left the site...)', () => {
    const grantId = grantFill();
    expect(call({ op: 'drop_grant', grantId })).toEqual({ ok: true, result: { dropped: true } });
    expect(release('password', fillUse(grantId))).toEqual({ ok: false, error: 'unknown_grant' });
    expect(call({ op: 'drop_grant', grantId })).toEqual({ ok: true, result: { dropped: false } });
  });

  it('refused for a high-risk site or a strong (ask-strong) statement, even when requested', () => {
    const risky = combinedFill(
      { strong: true },
      { item: riskyItemId, origin: `https://${RISKY}`, rpId: RISKY, fields: ['password'] },
    );
    expect(accept(phone.approve(risky))).toEqual({ ok: false, error: 'grant_not_allowed' });
    const riskyNotStrong = combinedFill(
      {},
      { item: riskyItemId, origin: `https://${RISKY}`, rpId: RISKY, fields: ['password'] },
    );
    expect(accept(phone.approve(riskyNotStrong))).toEqual({
      ok: false,
      error: 'grant_not_allowed',
    });
    expect(accept(phone.approve(combinedFill({ strong: true })))).toEqual({
      ok: false,
      error: 'grant_not_allowed',
    });
    expect(logs.filter((l) => l.event === 'grant_recorded')).toHaveLength(0);
  });

  it('the combined statement is never an operation by itself', () => {
    const s = combinedFill();
    expect(release('password', phone.approve(s))).toEqual({
      ok: false,
      error: 'handoff_approval_not_an_operation',
    });
    const cd = clientData('webauthn.get', ORIGIN);
    const sign = call({
      op: 'sign',
      credentialId,
      authenticatorData: authData(DOMAIN, 0x05),
      clientDataJSON: cd,
      approval: phone.approve(
        combinedFill({
          kind: 'webauthn.get',
          credentialId,
          clientDataHash: sha256B64url(Buffer.from(cd, 'base64url')),
        }),
      ),
    });
    expect(sign).toEqual({ ok: false, error: 'handoff_approval_not_an_operation' });
    const grantId = grantFill();
    const u = fillUse(grantId);
    u.statement = { ...u.statement, handoff: { id: HANDOFF } };
    expect(release('password', u)).toEqual({ ok: false, error: 'bad_statement' });
  });

  it('needs a phone (UV) approval, a well-formed statement, and is accepted once', () => {
    const noHandoff = combinedFill();
    delete noHandoff.handoff;
    expect(accept(phone.approve(noHandoff))).toEqual({ ok: false, error: 'bad_statement' });
    const noUses = combinedFill({ grant: { agentId: AGENT, until: now + 60_000 } });
    expect(accept(phone.approve(noUses))).toEqual({ ok: false, error: 'bad_statement' });
    const twoUses = combinedFill({
      grant: { agentId: AGENT, until: now + 60_000, uses: 2 as 1 },
    });
    expect(accept(phone.approve(twoUses))).toEqual({ ok: false, error: 'bad_statement' });
    const badId = combinedFill({ handoff: { id: 'not an id!' } });
    expect(accept(phone.approve(badId))).toEqual({ ok: false, error: 'bad_statement' });
    const s = combinedFill();
    const a = phone.approve(s);
    expect(accept(a).ok).toBe(true);
    phone.setCounter(0);
    expect(accept(a)).toEqual({ ok: false, error: 'approval_replayed' });
    expect(accept(fillUse(s.requestId) as unknown as SignedApproval)).toEqual({
      ok: false,
      error: 'bad_approval',
    });
    const ed = testApprover();
    storePath = join(tmpDir(), 'keys2');
    open(ed.trusted);
    const item = call({
      op: 'store_item',
      domain: DOMAIN,
      password: PASSWORD,
      totp: { secret: SEED },
    });
    if (!item.ok) throw new Error(item.error);
    itemId = item.result.itemId as string;
    expect(accept(ed.sign(combinedFill({ userVerified: false })))).toEqual({
      ok: false,
      error: 'user_verification_required',
    });
  });

  it('refuses a grant for another agent than the one that uses it, and an unknown credential', () => {
    const grantId = grantFill({ grant: { agentId: 'agent-9', until: now + 60_000, uses: 1 } });
    expect(release('password', fillUse(grantId))).toEqual({
      ok: false,
      error: 'grant_agent_mismatch',
    });
    expect(accept(phone.approve(combinedFill({}, { item: 'no-such-item' })))).toEqual({
      ok: false,
      error: 'unknown_item',
    });
    expect(
      accept(
        phone.approve(
          combinedFill({
            kind: 'webauthn.get',
            credentialId: 'no-such-credential',
            clientDataHash: handoffSignInClientDataHash(HANDOFF),
          }),
        ),
      ),
    ).toEqual({ ok: false, error: 'unknown_credential' });
  });
});

type SignerAuthorizationLike = SignedApproval | GrantedApproval;
