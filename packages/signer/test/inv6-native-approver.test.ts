import { generateKeyPairSync } from 'node:crypto';
import { join } from 'node:path';
import { beforeEach, describe, expect, it } from 'vitest';
import {
  type ApprovalStatement,
  approvalSigningBytes,
  approverDescriptor,
  fillScope,
  type SignedApproval,
  sha256B64url,
} from '../src/approval.ts';
import { KeyStore } from '../src/keystore.ts';
import { SignerHandler } from '../src/server.ts';
import {
  authData,
  clientData,
  statement,
  testApprover,
  testNativePhone,
  testPhone,
  tmpDir,
} from './helpers.ts';

type Res = { ok: true; result: Record<string, unknown> } | { ok: false; error: string };

describe('invariant 6: native iOS approver (Secure Enclave key)', () => {
  const terminal = testApprover('terminal');
  let storePath: string;
  let handler: SignerHandler;
  let app: ReturnType<typeof testNativePhone>;

  const open = (opts: { approverAdmin?: boolean } = {}) => {
    handler = new SignerHandler({
      store: KeyStore.open(storePath, 'pw'),
      trustedApproverKeys: terminal.trusted,
      highRiskDomains: ['bank.example.com'],
      ...opts,
    });
  };
  const call = (req: unknown) => handler.handle(req as never) as Res;
  const pairNative = (
    a = app,
    o: { approval?: SignedApproval; proof?: string; key?: unknown } = {},
  ) =>
    call({
      op: 'add_native_approver',
      key: o.key ?? a.key,
      proof: o.proof ?? a.proof(),
      ...(o.approval ? { approval: o.approval } : {}),
    });

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
      userVerified: true,
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

  const addNative = (
    n: ReturnType<typeof testNativePhone>,
    over: Partial<ApprovalStatement> = {},
  ) =>
    ({
      ...statement({ clientDataJSON: '' }),
      kind: 'approver.add',
      verifiedOrigin: n.key.origin,
      rpId: new URL(n.key.origin).hostname,
      credentialId: n.keyId,
      clientDataHash: sha256B64url(n.descriptor),
      userVerified: true,
      ...over,
    }) satisfies ApprovalStatement;

  beforeEach(() => {
    storePath = join(tmpDir(), 'keys');
    app = testNativePhone();
    open();
  });

  describe('pairing (add_native_approver)', () => {
    it('trusts the first app key on first use and lists it', () => {
      expect(pairNative()).toEqual({ ok: true, result: { added: true, keyId: app.keyId } });
      const listed = call({ op: 'list_approvers' }) as unknown as {
        result: { approvers: unknown[]; native: { keyId: string; userVerification: string }[] };
      };
      expect(listed.result.approvers).toEqual([]);
      expect(listed.result.native.map((k) => [k.keyId, k.userVerification])).toEqual([
        [app.keyId, 'biometry'],
      ]);
      expect(pairNative()).toEqual({ ok: false, error: 'approver_exists' });
    });

    it('refuses a key the app does not hold, or that does not need biometry', () => {
      const other = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey;
      expect(pairNative(app, { proof: app.proof(other) })).toEqual({
        ok: false,
        error: 'bad_proof',
      });
      expect(pairNative(app, { proof: '' })).toEqual({ ok: false, error: 'bad_proof' });
      for (const uv of ['none', 'passcode', undefined]) {
        expect(pairNative(app, { key: { ...app.key, userVerification: uv } })).toEqual({
          ok: false,
          error: 'user_verification_required',
        });
      }
      expect(pairNative(app, { key: { ...app.key, x: app.key.y } }).ok).toBe(false);
      expect(pairNative(app, { key: { ...app.key, x: 'AAAA' } })).toEqual({
        ok: false,
        error: 'bad_public_key',
      });
      for (const origin of ['http://approver.example.net', 'https://a.example/path', 'nope']) {
        const n = testNativePhone({ origin });
        expect(pairNative(n)).toEqual({ ok: false, error: 'bad_origin' });
      }
      const elsewhere = testNativePhone({ origin: 'https://other.example.net' });
      expect(
        pairNative(elsewhere, {
          key: { ...elsewhere.key, origin: 'https://approver.example.net' },
        }),
      ).toEqual({ ok: false, error: 'bad_proof' });
      expect(call({ op: 'list_approvers' })).toEqual({
        ok: true,
        result: { approvers: [], native: [] },
      });
    });

    it('a second app key needs an approver.add approval from an existing phone', () => {
      expect(pairNative().ok).toBe(true);
      const second = testNativePhone();
      expect(pairNative(second)).toEqual({ ok: false, error: 'missing_approval' });
      expect(pairNative(second, { approval: second.approve(addNative(second)) })).toEqual({
        ok: false,
        error: 'untrusted_approver',
      });
      expect(
        pairNative(second, {
          approval: terminal.sign({ ...addNative(second), userVerified: false }),
        }),
      ).toEqual({ ok: false, error: 'untrusted_approver' });
      const third = testNativePhone();
      expect(
        pairNative(second, {
          approval: app.approve(
            addNative(second, { clientDataHash: sha256B64url(third.descriptor) }),
          ),
        }),
      ).toEqual({ ok: false, error: 'client_data_hash_mismatch' });
      expect(
        pairNative(second, {
          approval: app.approve(addNative(second, { credentialId: third.keyId })),
        }),
      ).toEqual({ ok: false, error: 'approval_credential_mismatch' });
      expect(
        pairNative(second, { approval: app.approve(addNative(second, { kind: 'fill' })) }),
      ).toEqual({ ok: false, error: 'approval_kind_mismatch' });
      expect(pairNative(second, { approval: app.approve(addNative(second)) })).toEqual({
        ok: true,
        result: { added: true, keyId: second.keyId },
      });
    });

    it('phone passkeys and app keys vouch for each other', () => {
      const phone = testPhone();
      expect(call({ op: 'add_approver', key: phone.key }).ok).toBe(true);
      expect(pairNative(app)).toEqual({ ok: false, error: 'missing_approval' });
      expect(pairNative(app, { approval: phone.approve(addNative(app)) }).ok).toBe(true);
      const phone2 = testPhone({ rpId: phone.key.rpId, origin: phone.key.origin });
      const add: ApprovalStatement = {
        ...statement({ clientDataJSON: '' }),
        kind: 'approver.add',
        verifiedOrigin: phone2.key.origin,
        rpId: phone2.key.rpId,
        credentialId: phone2.key.credentialId,
        clientDataHash: sha256B64url(approverDescriptor(phone2.key)),
        userVerified: true,
      };
      expect(call({ op: 'add_approver', key: phone2.key, approval: app.approve(add) })).toEqual({
        ok: true,
        result: { added: true },
      });
    });

    it('the core cannot remove the last app key and re-pair its own as "first use"', () => {
      expect(pairNative().ok).toBe(true);
      expect(call({ op: 'remove_approver', credentialId: app.keyId })).toEqual({
        ok: false,
        error: 'last_approver_needs_admin',
      });
      expect(pairNative(testNativePhone())).toEqual({ ok: false, error: 'missing_approval' });
      expect(
        create('example.com', 'https://example.com', (s) => terminal.sign(s), {
          userVerified: false,
        }),
      ).toEqual({ ok: false, error: 'untrusted_approver' });
    });

    it('only the offline admin signer removes the last app key, which reopens first use', () => {
      expect(pairNative().ok).toBe(true);
      open({ approverAdmin: true });
      expect(call({ op: 'remove_approver', credentialId: app.keyId })).toEqual({
        ok: true,
        result: { removed: true },
      });
      open();
      expect(
        create('example.com', 'https://example.com', (s) => terminal.sign(s), {
          userVerified: false,
        }).ok,
      ).toBe(true);
      expect(pairNative(testNativePhone()).ok).toBe(true);
    });
  });

  describe('approvals', () => {
    beforeEach(() => {
      expect(pairNative().ok).toBe(true);
    });

    it('a native approval creates and signs; it counts as user-verified', () => {
      const res = create('example.com', 'https://example.com', (s) => app.approve(s));
      expect(res.ok).toBe(true);
      const { credentialId } = (res as unknown as { result: { credentialId: string } }).result;
      const cd = clientData('webauthn.get', 'https://example.com');
      const ad = authData('example.com', 0x05);
      const s = statement({ credentialId, clientDataJSON: cd, userVerified: true });
      expect(
        call({
          op: 'sign',
          credentialId,
          authenticatorData: ad,
          clientDataJSON: cd,
          approval: app.approve(s),
        }).ok,
      ).toBe(true);
    });

    const other = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey;
    const bad: [string, (s: ApprovalStatement) => SignedApproval, string][] = [
      [
        'a statement changed after the app signed',
        (s) => ({ ...app.approve(s), statement: { ...s, rpId: 'evil.com' } }),
        'bad_signature',
      ],
      ['a signature by another key', (s) => app.approve(s, { signWith: other }), 'bad_signature'],
      [
        'a raw r||s signature (DER is the format)',
        (s) => app.approve(s, { encoding: 'ieee-p1363' }),
        'bad_signature',
      ],
      [
        'a signature over the Ed25519 statement bytes (no native domain prefix)',
        (s) => app.approve(s, { bytes: approvalSigningBytes(s) }),
        'bad_signature',
      ],
      [
        'userVerified: false in the statement',
        (s) => app.approve({ ...s, userVerified: false }),
        'user_not_verified',
      ],
      ['an unpaired app key', (s) => testNativePhone().approve(s), 'untrusted_approver'],
      [
        'both a native signature and a WebAuthn assertion',
        (s) =>
          ({
            ...app.approve(s),
            webauthn: { authenticatorData: '', clientDataJSON: '', signature: '' },
          }) as unknown as SignedApproval,
        'bad_approval',
      ],
      [
        'a malformed signature field',
        (s) => ({ ...app.approve(s), native: { signature: 7 } }) as unknown as SignedApproval,
        'bad_assertion',
      ],
    ];
    for (const [name, approve, reason] of bad) {
      it(`refuses ${name}`, () => {
        expect(create('example.com', 'https://example.com', approve)).toEqual({
          ok: false,
          error: reason,
        });
      });
    }

    it('refuses a replayed native approval', () => {
      const cd = clientData('webauthn.create', 'https://example.com');
      const approval = app.approve(
        statement({
          kind: 'webauthn.create',
          clientDataJSON: cd,
          userVerified: true,
        }),
      );
      const req = {
        op: 'create_credential',
        rpId: 'example.com',
        userHandle: 'dXNlcg',
        clientDataJSON: cd,
        approval,
      };
      expect(call(req).ok).toBe(true);
      expect(call(req)).toEqual({ ok: false, error: 'approval_replayed' });
    });

    it('refuses an approval issued before the signer started (no replay across restarts)', () => {
      const t = Date.now() - 1_000;
      expect(
        create('example.com', 'https://example.com', (s) => app.approve(s), {
          issuedAt: t,
          expiresAt: t + 60_000,
        }),
      ).toEqual({ ok: false, error: 'issued_before_signer_start' });
    });

    it('high-risk origins accept a native approval, but not with a long lifetime', () => {
      for (const [rpId, origin] of [
        ['paypal.com', 'https://www.paypal.com'],
        ['bank.example.com', 'https://bank.example.com'],
      ] as const) {
        const t = Date.now();
        expect(
          create(rpId, origin, (s) => app.approve(s), { issuedAt: t, expiresAt: t + 61_000 }),
        ).toEqual({ ok: false, error: 'lifetime_too_long' });
        expect(create(rpId, origin, (s) => app.approve(s)).ok).toBe(true);
      }
    });

    it('password release for a high-risk domain works with the app key', () => {
      const stored = call({ op: 'store_item', domain: 'paypal.com', password: 'hunter2hunter2' });
      if (!stored.ok) throw new Error(stored.error);
      const itemId = stored.result.itemId as string;
      const approval = app.approve({
        ...statement({ clientDataJSON: '' }),
        kind: 'fill',
        verifiedOrigin: 'https://www.paypal.com',
        rpId: 'paypal.com',
        credentialId: itemId,
        clientDataHash: sha256B64url(fillScope(['password'])),
        userVerified: true,
      });
      expect(call({ op: 'release_secret', itemId, field: 'password', approval })).toEqual({
        ok: true,
        result: { value: 'hunter2hunter2' },
      });
    });
  });
});
