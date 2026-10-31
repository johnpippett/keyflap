import { createHash, createPublicKey, generateKeyPairSync, verify } from 'node:crypto';
import { join } from 'node:path';
import { beforeEach, describe, expect, it } from 'vitest';
import {
  type ApprovalStatement,
  approverDescriptor,
  fillScope,
  type SignedApproval,
  sha256B64url,
} from '../src/approval.ts';
import { KeyStore } from '../src/keystore.ts';
import { BUILTIN_HIGH_RISK, isHighRisk, normalizeRiskDomain } from '../src/risk.ts';
import { SignerHandler } from '../src/server.ts';
import { authData, clientData, statement, testApprover, testPhone, tmpDir } from './helpers.ts';

type Res = { ok: true; result: Record<string, unknown> } | { ok: false; error: string };

describe('invariant 6: user verification on the approver device', () => {
  const terminal = testApprover('terminal');
  let storePath: string;
  let handler: SignerHandler;
  let phone: ReturnType<typeof testPhone>;

  const open = (highRiskDomains: string[] = ['bank.example.com']) => {
    handler = new SignerHandler({
      store: KeyStore.open(storePath, 'pw'),
      trustedApproverKeys: terminal.trusted,
      highRiskDomains,
    });
  };
  const call = (req: unknown) => handler.handle(req as never) as Res;
  const pair = (p = phone, approval?: SignedApproval) =>
    call({ op: 'add_approver', key: p.key, ...(approval ? { approval } : {}) });

  const create = (
    rpId: string,
    origin: string,
    approve: (s: ApprovalStatement) => SignedApproval,
    over: Partial<ApprovalStatement> = {},
  ) => {
    const cd = clientData('webauthn.create', origin);
    const s = statement({
      kind: 'webauthn.create',
      rpId,
      verifiedOrigin: origin,
      clientDataJSON: cd,
      ...over,
    });
    return call({
      op: 'create_credential',
      rpId,
      userHandle: 'dXNlcg',
      clientDataJSON: cd,
      approval: approve(s),
    });
  };

  beforeEach(() => {
    storePath = join(tmpDir(), 'keys');
    phone = testPhone();
    open();
  });

  describe('phone approvals (WebAuthn assertion verified by the signer)', () => {
    let credentialId: string;
    let publicKey: { x: string; y: string };

    beforeEach(() => {
      expect(pair().ok).toBe(true);
      const res = create('example.com', 'https://example.com', (s) =>
        phone.approve({ ...s, userVerified: true }),
      );
      if (!res.ok) throw new Error(res.error);
      ({ credentialId, publicKey } = res.result as typeof res.result & {
        credentialId: string;
        publicKey: { x: string; y: string };
      });
    });

    const signReq = (
      approve: (s: ApprovalStatement) => SignedApproval,
      flags = 0x05,
      over: Partial<ApprovalStatement> = {},
    ) => {
      const cd = clientData('webauthn.get', 'https://example.com');
      const ad = authData('example.com', flags);
      const s = statement({
        kind: 'webauthn.get',
        credentialId,
        clientDataJSON: cd,
        userVerified: true,
        ...over,
      });
      return {
        ad,
        cd,
        res: call({
          op: 'sign',
          credentialId,
          authenticatorData: ad,
          clientDataJSON: cd,
          approval: approve(s),
        }),
      };
    };

    it('signs with UV set, and the site signature verifies', () => {
      const { ad, cd, res } = signReq((s) => phone.approve(s));
      expect(res.ok).toBe(true);
      const sig = Buffer.from(
        (res as unknown as { result: { signature: string } }).result.signature,
        'base64url',
      );
      const key = createPublicKey({
        key: { kty: 'EC', crv: 'P-256', ...publicKey },
        format: 'jwk',
      });
      const h = createHash('sha256').update(Buffer.from(cd, 'base64url')).digest();
      expect(verify('sha256', Buffer.concat([Buffer.from(ad, 'base64url'), h]), key, sig)).toBe(
        true,
      );
    });

    const other = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey;
    const bad: [string, (s: ApprovalStatement) => SignedApproval, string][] = [
      [
        'a challenge for another statement',
        (s) => phone.approve(s, { challenge: 'b3RoZXI' }),
        'assertion_challenge_mismatch',
      ],
      [
        'a statement changed after the phone signed',
        (s) => ({ ...phone.approve(s), statement: { ...s, rpId: 'evil.com' } }),
        'assertion_challenge_mismatch',
      ],
      [
        'another origin in clientData',
        (s) => phone.approve(s, { origin: 'https://evil.example' }),
        'assertion_origin_mismatch',
      ],
      [
        'webauthn.create clientData',
        (s) => phone.approve(s, { type: 'webauthn.create' }),
        'assertion_type_mismatch',
      ],
      [
        'crossOrigin: true',
        (s) => phone.approve(s, { clientData: { crossOrigin: true } }),
        'assertion_cross_origin',
      ],
      [
        'a topOrigin',
        (s) => phone.approve(s, { clientData: { topOrigin: 'https://evil.example' } }),
        'assertion_cross_origin',
      ],
      [
        'another rpId hash',
        (s) => phone.approve(s, { rpId: 'evil.example' }),
        'assertion_rp_id_mismatch',
      ],
      ['no UV flag', (s) => phone.approve(s, { flags: 0x01 }), 'user_not_verified'],
      ['no UP flag', (s) => phone.approve(s, { flags: 0x04 }), 'missing_user_presence'],
      ['the AT flag', (s) => phone.approve(s, { flags: 0x45 }), 'unexpected_flags'],
      ['a signature by another key', (s) => phone.approve(s, { signWith: other }), 'bad_signature'],
      [
        'userVerified: false in the statement',
        (s) => phone.approve({ ...s, userVerified: false }),
        'user_not_verified',
      ],
      ['an unpaired phone', (s) => testPhone().approve(s), 'untrusted_approver'],
    ];
    for (const [name, approve, reason] of bad) {
      it(`refuses ${name}`, () => {
        expect(signReq(approve).res).toEqual({ ok: false, error: reason });
      });
    }

    it('refuses a replayed phone approval', () => {
      const cd = clientData('webauthn.get', 'https://example.com');
      const ad = authData('example.com', 0x05);
      const s = statement({
        kind: 'webauthn.get',
        credentialId,
        clientDataJSON: cd,
        userVerified: true,
      });
      const approval = phone.approve(s);
      const req = { op: 'sign', credentialId, authenticatorData: ad, clientDataJSON: cd, approval };
      expect(call(req).ok).toBe(true);
      expect(call(req)).toEqual({ ok: false, error: 'approval_replayed' });
    });

    it('requires a counter that moves forward, across restarts', () => {
      phone.setCounter(5);
      expect(signReq((s) => phone.approve(s)).res.ok).toBe(true);
      open();
      expect(signReq((s) => phone.approve(s)).res).toEqual({
        ok: false,
        error: 'sign_count_regressed',
      });
      phone.setCounter(6);
      expect(signReq((s) => phone.approve(s)).res.ok).toBe(true);
    });

    it('ignores Ed25519 approver keys once a phone is paired', () => {
      expect(signReq((s) => terminal.sign(s), 0x01, { userVerified: false }).res).toEqual({
        ok: false,
        error: 'untrusted_approver',
      });
    });
  });

  it('an Ed25519 approval can never claim user verification', () => {
    const res = create('example.com', 'https://example.com', (s) =>
      terminal.sign({ ...s, userVerified: true }),
    );
    expect(res).toEqual({ ok: false, error: 'uv_requires_phone_approver' });
    expect(create('example.com', 'https://example.com', (s) => terminal.sign(s)).ok).toBe(true);
  });

  describe('high-risk origins', () => {
    const cases: [string, string, string][] = [
      ['built-in payment site', 'paypal.com', 'https://www.paypal.com'],
      ['built-in government suffix', 'login.gov', 'https://secure.login.gov'],
      ['built-in identity provider', 'google.com', 'https://accounts.google.com'],
      ['configured domain', 'bank.example.com', 'https://bank.example.com'],
      ['high-risk origin host under a plain rpId', 'example.com', 'https://bank.example.com'],
    ];
    for (const [name, rpId, origin] of cases) {
      it(`${name}: Ed25519 refused, phone with UV accepted, long lifetime refused`, () => {
        expect(create(rpId, origin, (s) => terminal.sign(s))).toEqual({
          ok: false,
          error: 'user_verification_required',
        });
        expect(pair().ok).toBe(true);
        const t = Date.now();
        expect(
          create(rpId, origin, (s) => phone.approve(s), {
            userVerified: true,
            issuedAt: t,
            expiresAt: t + 61_000,
          }),
        ).toEqual({ ok: false, error: 'lifetime_too_long' });
        expect(create(rpId, origin, (s) => phone.approve(s), { userVerified: true }).ok).toBe(true);
      });
    }

    it('a plain origin still accepts the terminal approver before pairing', () => {
      expect(create('example.com', 'https://www.example.com', (s) => terminal.sign(s)).ok).toBe(
        true,
      );
    });

    it('password / TOTP release for a high-risk domain needs the phone too', () => {
      const stored = call({ op: 'store_item', domain: 'paypal.com', password: 'hunter2hunter2' });
      if (!stored.ok) throw new Error(stored.error);
      const itemId = stored.result.itemId as string;
      const fillStatement = (): ApprovalStatement => ({
        ...statement({ clientDataJSON: '' }),
        kind: 'fill',
        verifiedOrigin: 'https://www.paypal.com',
        rpId: 'paypal.com',
        credentialId: itemId,
        clientDataHash: sha256B64url(fillScope(['password'])),
      });
      const release = (approval: SignedApproval) =>
        call({ op: 'release_secret', itemId, field: 'password', approval });
      expect(release(terminal.sign(fillStatement()))).toEqual({
        ok: false,
        error: 'user_verification_required',
      });
      expect(pair().ok).toBe(true);
      const res = release(phone.approve({ ...fillStatement(), userVerified: true }));
      expect(res).toEqual({ ok: true, result: { value: 'hunter2hunter2' } });
    });

    it('the built-in list matches subdomains only on label boundaries, and fails closed', () => {
      expect(BUILTIN_HIGH_RISK.length).toBeGreaterThan(50);
      expect(isHighRisk('www.chase.com')).toBe(true);
      expect(isHighRisk('notchase.com')).toBe(false);
      expect(isHighRisk('example.gov')).toBe(true);
      expect(isHighRisk('gov.example.com')).toBe(false);
      expect(isHighRisk('')).toBe(true);
      expect(isHighRisk('www.amazon.co.uk')).toBe(true);
      expect(isHighRisk('online.santander.co.uk')).toBe(true);
      expect(isHighRisk('www.anz.com.au')).toBe(true);
      expect(isHighRisk('mijn.ing.nl')).toBe(true);
      expect(new Set(BUILTIN_HIGH_RISK).size).toBe(BUILTIN_HIGH_RISK.length);
      for (const d of BUILTIN_HIGH_RISK) expect(normalizeRiskDomain(d), d).toBe(d);
    });

    it('refuses a malformed extra domain at startup', () => {
      expect(() => open(['not a domain'])).toThrow();
    });
  });

  describe('pairing (add_approver)', () => {
    it('trusts the first phone, then requires an approver.add approval from it', () => {
      expect(pair()).toEqual({ ok: true, result: { added: true } });
      const second = testPhone({ rpId: phone.key.rpId, origin: phone.key.origin });
      expect(pair(second)).toEqual({ ok: false, error: 'missing_approval' });

      const addStatement = (over: Partial<ApprovalStatement> = {}): ApprovalStatement => ({
        ...statement({ clientDataJSON: '' }),
        kind: 'approver.add',
        verifiedOrigin: second.key.origin,
        rpId: second.key.rpId,
        credentialId: second.key.credentialId,
        clientDataHash: sha256B64url(approverDescriptor(second.key)),
        userVerified: true,
        ...over,
      });
      expect(pair(second, second.approve(addStatement()))).toEqual({
        ok: false,
        error: 'untrusted_approver',
      });
      expect(pair(second, terminal.sign({ ...addStatement(), userVerified: false }))).toEqual({
        ok: false,
        error: 'untrusted_approver',
      });
      const wrongKey = testPhone({ rpId: phone.key.rpId, origin: phone.key.origin });
      expect(
        pair(
          second,
          phone.approve(
            addStatement({ clientDataHash: sha256B64url(approverDescriptor(wrongKey.key)) }),
          ),
        ),
      ).toEqual({ ok: false, error: 'client_data_hash_mismatch' });
      expect(pair(second, phone.approve(addStatement({ kind: 'fill' })))).toEqual({
        ok: false,
        error: 'approval_kind_mismatch',
      });
      expect(pair(second, phone.approve(addStatement()))).toEqual({
        ok: true,
        result: { added: true },
      });
      const listed = call({ op: 'list_approvers' });
      expect(
        (
          listed as unknown as { result: { approvers: { credentialId: string }[] } }
        ).result.approvers.map((a) => a.credentialId),
      ).toEqual([phone.key.credentialId, second.key.credentialId]);
    });

    it('refuses bad keys and origins', () => {
      const p = testPhone({ rpId: 'approver.example.net', origin: 'http://approver.example.net' });
      expect(pair(p)).toEqual({ ok: false, error: 'bad_origin' });
      const q = testPhone({ rpId: 'other.example', origin: 'https://approver.example.net' });
      expect(pair(q)).toEqual({ ok: false, error: 'bad_origin' });
      expect(call({ op: 'add_approver', key: { ...phone.key, x: phone.key.y } }).ok).toBe(false);
      expect(
        pair(testPhone({ rpId: 'approver.localhost', origin: 'http://approver.localhost:1234' }))
          .ok,
      ).toBe(true);
    });

    it('the core cannot remove the last phone and re-pair its own key as "first use"', () => {
      expect(pair().ok).toBe(true);
      const rogue = testPhone({ rpId: phone.key.rpId, origin: phone.key.origin });
      expect(call({ op: 'remove_approver', credentialId: phone.key.credentialId })).toEqual({
        ok: false,
        error: 'last_approver_needs_admin',
      });
      expect(pair(rogue)).toEqual({ ok: false, error: 'missing_approval' });
      const second = testPhone({ rpId: phone.key.rpId, origin: phone.key.origin });
      const add: ApprovalStatement = {
        ...statement({ clientDataJSON: '' }),
        kind: 'approver.add',
        verifiedOrigin: second.key.origin,
        rpId: second.key.rpId,
        credentialId: second.key.credentialId,
        clientDataHash: sha256B64url(approverDescriptor(second.key)),
        userVerified: true,
      };
      expect(pair(second, phone.approve(add)).ok).toBe(true);
      expect(call({ op: 'remove_approver', credentialId: phone.key.credentialId })).toEqual({
        ok: true,
        result: { removed: true },
      });
      expect(call({ op: 'remove_approver', credentialId: second.key.credentialId })).toEqual({
        ok: false,
        error: 'last_approver_needs_admin',
      });
      expect(create('example.com', 'https://example.com', (s) => terminal.sign(s))).toEqual({
        ok: false,
        error: 'untrusted_approver',
      });
    });

    it('only the offline admin signer removes the last phone, which reopens first use', () => {
      expect(pair().ok).toBe(true);
      handler = new SignerHandler({
        store: KeyStore.open(storePath, 'pw'),
        trustedApproverKeys: terminal.trusted,
        approverAdmin: true,
      });
      expect(call({ op: 'remove_approver', credentialId: phone.key.credentialId })).toEqual({
        ok: true,
        result: { removed: true },
      });
      open();
      expect(create('example.com', 'https://example.com', (s) => terminal.sign(s)).ok).toBe(true);
      expect(pair(testPhone()).ok).toBe(true);
    });

    it('the latch survives a store where every approver was deleted some other way', () => {
      expect(pair().ok).toBe(true);
      const store = KeyStore.open(storePath, 'pw');
      store.removeApprover(phone.key.credentialId);
      open();
      expect(pair(testPhone())).toEqual({ ok: false, error: 'missing_approval' });
      expect(create('example.com', 'https://example.com', (s) => terminal.sign(s))).toEqual({
        ok: false,
        error: 'untrusted_approver',
      });
    });
  });

  it('an approval issued before the signer started is refused (no replay across restarts)', () => {
    expect(pair().ok).toBe(true);
    const stored = call({ op: 'store_item', domain: 'example.com', password: 'hunter2hunter2' });
    if (!stored.ok) throw new Error(stored.error);
    const itemId = stored.result.itemId as string;
    const approval = phone.approve({
      ...statement({ clientDataJSON: '' }),
      kind: 'fill',
      verifiedOrigin: 'https://example.com',
      rpId: 'example.com',
      credentialId: itemId,
      clientDataHash: sha256B64url(fillScope(['password'])),
      userVerified: true,
      issuedAt: Date.now() - 1_000,
    });
    const release = () => call({ op: 'release_secret', itemId, field: 'password', approval });
    expect(release()).toEqual({ ok: false, error: 'issued_before_signer_start' });
  });
});
