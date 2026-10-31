import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { beforeEach, describe, expect, it } from 'vitest';
import {
  type ApprovalStatement,
  type FillField,
  fillScope,
  type GrantedApproval,
  type SignedApproval,
  sha256B64url,
} from '../src/approval.ts';
import { KeyStore } from '../src/keystore.ts';
import { SignerHandler } from '../src/server.ts';
import { authData, clientData, statement, testApprover, testPhone, tmpDir } from './helpers.ts';

type Res = { ok: true; result: Record<string, unknown> } | { ok: false; error: string };

const RP = 'example.com';
const ORIGIN = 'https://login.example.com';
const AGENT = 'agent-1';
const WINDOW = 30 * 60_000;
const GRANT_CAP_MS = 24 * 60 * 60_000;

describe('invariant 6: allow-for grants are authorized by the signed approval and checked by the signer', () => {
  const approver = testApprover();
  let storePath: string;
  let handler: SignerHandler;
  let now: number;
  let credentialId: string;
  let logs: { event: string; fields: Record<string, unknown> }[];

  const open = () => {
    handler = new SignerHandler({
      store: KeyStore.open(storePath, 'pw'),
      trustedApproverKeys: approver.trusted,
      highRiskDomains: ['bank.example.net'],
      now: () => now,
      log: (event, fields) => logs.push({ event, fields }),
    });
  };
  const call = (req: unknown) => handler.handle(req as never) as Res;

  const createCred = (rpId = RP, origin = ORIGIN): string => {
    const cd = clientData('webauthn.create', origin);
    const s = statement({
      kind: 'webauthn.create',
      rpId,
      verifiedOrigin: origin,
      clientDataJSON: cd,
      issuedAt: now,
      expiresAt: now + 60_000,
    });
    const r = call({
      op: 'create_credential',
      rpId,
      userHandle: 'dXNlcg',
      clientDataJSON: cd,
      approval: approver.sign(s),
    });
    if (!r.ok) throw new Error(r.error);
    return r.result.credentialId as string;
  };

  const getStatement = (over: Partial<ApprovalStatement> = {}, origin = ORIGIN) =>
    statement({
      kind: 'webauthn.get',
      verifiedOrigin: origin,
      rpId: RP,
      credentialId,
      clientDataJSON: clientData('webauthn.get', origin),
      issuedAt: now,
      expiresAt: now + 60_000,
      ...over,
    });

  const sign = (approval: SignedApproval | GrantedApproval, origin = ORIGIN, cred = credentialId) =>
    call({
      op: 'sign',
      credentialId: cred,
      authenticatorData: authData(RP, 0x01),
      clientDataJSON: clientData('webauthn.get', origin),
      approval,
    });

  const grantSignIn = (window = WINDOW): string => {
    const s = getStatement({ grant: { agentId: AGENT, until: now + window } });
    const r = sign(approver.sign(s));
    if (!r.ok) throw new Error(r.error);
    return s.requestId;
  };

  const use = (
    grantId: string,
    over: Partial<ApprovalStatement> = {},
    o: { agentId?: string; origin?: string } = {},
  ): GrantedApproval => ({
    statement: getStatement({ requestId: randomUUID(), ...over }, o.origin ?? ORIGIN),
    grantId,
    agentId: o.agentId ?? AGENT,
  });

  beforeEach(() => {
    now = Date.now();
    logs = [];
    storePath = join(tmpDir(), 'keys');
    open();
    credentialId = createCred();
  });

  it('later sign-ins inside the window need no approver signature, and the grant is logged', () => {
    const grantId = grantSignIn();
    expect(logs.some((l) => l.event === 'grant_recorded' && l.fields.grantId === grantId)).toBe(
      true,
    );
    expect(sign(use(grantId)).ok).toBe(true);
    now += WINDOW - 1000;
    expect(sign(use(grantId)).ok).toBe(true);
  });

  it('accepts a window of exactly 24 hours, and the grant works until that window ends', () => {
    const grantId = grantSignIn(GRANT_CAP_MS);
    expect(logs.some((l) => l.event === 'grant_recorded' && l.fields.grantId === grantId)).toBe(
      true,
    );
    now += GRANT_CAP_MS - 1000;
    expect(sign(use(grantId)).ok).toBe(true);
    now += 2000;
    expect(sign(use(grantId))).toEqual({ ok: false, error: 'grant_expired' });
  });

  it('refuses a window of 24 hours and one millisecond, recording no grant', () => {
    const tooLong = getStatement({ grant: { agentId: AGENT, until: now + GRANT_CAP_MS + 1 } });
    expect(sign(approver.sign(tooLong))).toEqual({ ok: false, error: 'grant_not_allowed' });
    expect(logs.filter((l) => l.event === 'grant_recorded')).toHaveLength(0);
  });

  it('refuses a use for another agent, origin, rpId, credential or kind', () => {
    const grantId = grantSignIn();
    const other = createCred();
    const cases: [GrantedApproval, string, string?, string?][] = [
      [use(grantId, {}, { agentId: 'agent-2' }), 'grant_agent_mismatch'],
      [
        use(grantId, {}, { origin: 'https://www.example.com' }),
        'grant_origin_mismatch',
        'https://www.example.com',
      ],
      [use(grantId, { rpId: 'login.example.com' }), 'grant_rp_mismatch'],
      [use(grantId, { credentialId: other }), 'grant_credential_mismatch', ORIGIN, other],
      [use(grantId, { kind: 'webauthn.create', credentialId: null }), 'grant_kind_mismatch'],
    ];
    for (const [a, error, origin, cred] of cases) {
      expect(sign(a, origin ?? ORIGIN, cred ?? credentialId)).toEqual({ ok: false, error });
    }
    const cd = clientData('webauthn.create', ORIGIN);
    const create = use(grantId, {
      kind: 'webauthn.create',
      credentialId: null,
      clientDataHash: sha256B64url(Buffer.from(cd, 'base64url')),
    });
    expect(
      call({
        op: 'create_credential',
        rpId: RP,
        userHandle: 'dXNlcg',
        clientDataJSON: cd,
        approval: create,
      }),
    ).toEqual({ ok: false, error: 'grant_kind_mismatch' });
  });

  it('ends with the window, and does not survive a signer restart', () => {
    const grantId = grantSignIn(60_000);
    now += 60_001;
    expect(sign(use(grantId))).toEqual({ ok: false, error: 'grant_expired' });
    now = Date.now();
    const g2 = grantSignIn();
    expect(sign(use(g2)).ok).toBe(true);
    open();
    expect(sign(use(g2))).toEqual({ ok: false, error: 'unknown_grant' });
    expect(sign(use('no-such-grant'))).toEqual({ ok: false, error: 'unknown_grant' });
  });

  it('each use is single-use per requestId, and the granting requestId stays spent', () => {
    const grantId = grantSignIn();
    const a = use(grantId);
    expect(sign(a).ok).toBe(true);
    expect(sign(a)).toEqual({ ok: false, error: 'approval_replayed' });
    expect(sign(use(grantId, { requestId: grantId }))).toEqual({
      ok: false,
      error: 'approval_replayed',
    });
  });

  it('refuses uses that claim UV, strong, a grant of their own, a signature, or a long or stale lifetime', () => {
    const grantId = grantSignIn();
    expect(sign(use(grantId, { userVerified: true }))).toEqual({
      ok: false,
      error: 'uv_requires_phone_approver',
    });
    expect(sign(use(grantId, { strong: true }))).toEqual({ ok: false, error: 'bad_statement' });
    expect(sign(use(grantId, { grant: { agentId: AGENT, until: now + 1000 } }))).toEqual({
      ok: false,
      error: 'bad_statement',
    });
    expect(sign(use(grantId, { keepSignedIn: { site: RP } }))).toEqual({
      ok: false,
      error: 'bad_statement',
    });
    const withSig = { ...use(grantId), signature: 'AAAA' } as unknown as GrantedApproval;
    expect(sign(withSig)).toEqual({ ok: false, error: 'bad_statement' });
    expect(sign(use(grantId, { expiresAt: now + 10 * 60_000 }))).toEqual({
      ok: false,
      error: 'lifetime_too_long',
    });
    expect(sign(use(grantId, { issuedAt: now - 120_000, expiresAt: now - 60_000 }))).toEqual({
      ok: false,
      error: 'expired',
    });
    expect(sign(use(grantId, { issuedAt: now + 31_000, expiresAt: now + 90_000 }))).toEqual({
      ok: false,
      error: 'not_yet_valid',
    });
    expect(sign(use(grantId, { clientDataHash: 'AAAA' }))).toEqual({
      ok: false,
      error: 'client_data_hash_mismatch',
    });
  });

  it('refuses the whole operation when a grant is not allowed: registration, too long, malformed', () => {
    const cd = clientData('webauthn.create', ORIGIN);
    const createWithGrant = statement({
      kind: 'webauthn.create',
      rpId: RP,
      verifiedOrigin: ORIGIN,
      clientDataJSON: cd,
      issuedAt: now,
      expiresAt: now + 60_000,
      grant: { agentId: AGENT, until: now + WINDOW },
    });
    expect(
      call({
        op: 'create_credential',
        rpId: RP,
        userHandle: 'dXNlcg',
        clientDataJSON: cd,
        approval: approver.sign(createWithGrant),
      }),
    ).toEqual({ ok: false, error: 'grant_not_allowed' });
    const tooLong = getStatement({ grant: { agentId: AGENT, until: now + GRANT_CAP_MS + 1 } });
    expect(sign(approver.sign(tooLong))).toEqual({ ok: false, error: 'grant_not_allowed' });
    const backwards = getStatement({ grant: { agentId: AGENT, until: now } });
    expect(sign(approver.sign(backwards))).toEqual({ ok: false, error: 'grant_not_allowed' });
    const extra = getStatement({
      grant: { agentId: AGENT, until: now + WINDOW, scope: 'all' } as never,
    });
    expect(sign(approver.sign(extra))).toEqual({ ok: false, error: 'bad_statement' });
    expect(logs.filter((l) => l.event === 'grant_recorded')).toHaveLength(0);
    expect(logs.filter((l) => l.event === 'signed')).toHaveLength(0);
  });

  it('a strong statement (policy ask-strong) needs a phone approval; Ed25519 is refused', () => {
    expect(sign(approver.sign(getStatement({ strong: true })))).toEqual({
      ok: false,
      error: 'user_verification_required',
    });
  });

  describe('fill grants', () => {
    let itemId: string;
    const fillStatement = (fields: FillField[], over: Partial<ApprovalStatement> = {}) =>
      ({
        ...statement({ clientDataJSON: '' }),
        kind: 'fill',
        verifiedOrigin: ORIGIN,
        rpId: RP,
        credentialId: itemId,
        clientDataHash: sha256B64url(fillScope(fields)),
        issuedAt: now,
        expiresAt: now + 60_000,
        ...over,
      }) as ApprovalStatement;
    const release = (field: FillField, approval: SignedApproval | GrantedApproval) =>
      call({ op: 'release_secret', itemId, field, approval });
    const fillUse = (grantId: string, fields: FillField[]): GrantedApproval => ({
      statement: fillStatement(fields, { requestId: randomUUID(), userVerified: false }),
      grantId,
      agentId: AGENT,
    });

    beforeEach(() => {
      const r = call({
        op: 'store_item',
        domain: RP,
        password: 'hunter2-long',
        totp: { secret: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP' },
      });
      if (!r.ok) throw new Error(r.error);
      itemId = r.result.itemId as string;
    });

    it('a later fill may release a subset of the granted fields, each once per use', () => {
      const s = fillStatement(['password', 'totp'], {
        grant: { agentId: AGENT, until: now + WINDOW },
      });
      expect(release('password', approver.sign(s)).ok).toBe(true);
      const both = fillUse(s.requestId, ['password', 'totp']);
      expect(release('password', both)).toEqual({ ok: true, result: { value: 'hunter2-long' } });
      expect(release('totp', both).ok).toBe(true);
      expect(release('password', both)).toEqual({ ok: false, error: 'approval_replayed' });
      expect(release('totp', fillUse(s.requestId, ['totp'])).ok).toBe(true);
      expect(sign(use(s.requestId))).toEqual({ ok: false, error: 'grant_kind_mismatch' });
    });

    it('refuses a use that asks for more than the grant covered', () => {
      const s = fillStatement(['password'], { grant: { agentId: AGENT, until: now + WINDOW } });
      expect(release('password', approver.sign(s)).ok).toBe(true);
      expect(release('password', fillUse(s.requestId, ['password', 'totp']))).toEqual({
        ok: false,
        error: 'grant_scope_mismatch',
      });
    });
  });
});

describe('invariant 6: no grant for high-risk or strong, and strong means a short phone approval', () => {
  let handler: SignerHandler;
  let phone: ReturnType<typeof testPhone>;
  let now: number;
  const call = (req: unknown) => handler.handle(req as never) as Res;

  beforeEach(() => {
    now = Date.now();
    phone = testPhone();
    handler = new SignerHandler({
      store: KeyStore.open(join(tmpDir(), 'keys'), 'pw'),
      trustedApproverKeys: {},
      highRiskDomains: ['bank.example.net'],
      now: () => now,
    });
    expect(call({ op: 'add_approver', key: phone.key }).ok).toBe(true);
  });

  const create = (rpId: string, origin: string): string => {
    const cd = clientData('webauthn.create', origin);
    const s = statement({
      kind: 'webauthn.create',
      rpId,
      verifiedOrigin: origin,
      clientDataJSON: cd,
      userVerified: true,
      issuedAt: now,
      expiresAt: now + 60_000,
    });
    const r = call({
      op: 'create_credential',
      rpId,
      userHandle: 'dXNlcg',
      clientDataJSON: cd,
      approval: phone.approve(s),
    });
    if (!r.ok) throw new Error(r.error);
    return r.result.credentialId as string;
  };

  const signWith = (
    rpId: string,
    origin: string,
    cred: string,
    over: Partial<ApprovalStatement>,
  ): Res => {
    const cd = clientData('webauthn.get', origin);
    const s = statement({
      kind: 'webauthn.get',
      rpId,
      verifiedOrigin: origin,
      credentialId: cred,
      clientDataJSON: cd,
      userVerified: true,
      issuedAt: now,
      expiresAt: now + 60_000,
      ...over,
    });
    return call({
      op: 'sign',
      credentialId: cred,
      authenticatorData: authData(rpId, 0x05),
      clientDataJSON: cd,
      approval: phone.approve(s),
    });
  };

  it('a phone approval with a grant for a configured or built-in high-risk origin is refused outright', () => {
    for (const [rpId, origin] of [
      ['bank.example.net', 'https://bank.example.net'],
      ['paypal.com', 'https://www.paypal.com'],
    ] as const) {
      const cred = create(rpId, origin);
      expect(
        signWith(rpId, origin, cred, { grant: { agentId: AGENT, until: now + WINDOW } }),
      ).toEqual({ ok: false, error: 'grant_not_allowed' });
      expect(signWith(rpId, origin, cred, {}).ok).toBe(true);
    }
  });

  it('a strong statement: phone approval ≤ 60 s signs, a longer one is refused, and it never grants', () => {
    const cred = create(RP, ORIGIN);
    expect(signWith(RP, ORIGIN, cred, { strong: true }).ok).toBe(true);
    expect(signWith(RP, ORIGIN, cred, { strong: true, expiresAt: now + 90_000 })).toEqual({
      ok: false,
      error: 'lifetime_too_long',
    });
    expect(
      signWith(RP, ORIGIN, cred, { strong: true, grant: { agentId: AGENT, until: now + WINDOW } }),
    ).toEqual({ ok: false, error: 'grant_not_allowed' });
    expect(signWith(RP, ORIGIN, cred, { grant: { agentId: AGENT, until: now + WINDOW } }).ok).toBe(
      true,
    );
  });
});
