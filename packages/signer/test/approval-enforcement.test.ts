import { createHash, createPublicKey, verify } from 'node:crypto';
import { join } from 'node:path';
import { beforeEach, describe, expect, it } from 'vitest';
import type { SignedApproval } from '../src/approval.ts';
import { KeyStore } from '../src/keystore.ts';
import { SignerHandler } from '../src/server.ts';
import { authData, clientData, statement, testApprover, tmpDir } from './helpers.ts';

const ORIGIN = 'https://example.com';
const RP = 'example.com';

describe('signer approval enforcement', () => {
  const approver = testApprover();
  let handler: SignerHandler;
  let credentialId: string;
  let publicKey: { x: string; y: string };

  const createApproval = (cd: string, over = {}) =>
    approver.sign(statement({ kind: 'webauthn.create', clientDataJSON: cd, ...over }));

  const signApproval = (cd: string, over = {}) =>
    approver.sign(statement({ kind: 'webauthn.get', credentialId, clientDataJSON: cd, ...over }));

  const sign = (cd: string, approval: SignedApproval | undefined, ad = authData(RP)) =>
    handler.handle({
      op: 'sign',
      credentialId,
      authenticatorData: ad,
      clientDataJSON: cd,
      approval: approval as SignedApproval,
    });

  beforeEach(() => {
    handler = new SignerHandler({
      store: KeyStore.open(join(tmpDir(), 'keys'), 'pw'),
      trustedApproverKeys: approver.trusted,
    });
    const cd = clientData('webauthn.create', ORIGIN);
    const res = handler.handle({
      op: 'create_credential',
      rpId: RP,
      userHandle: 'dXNlcg',
      clientDataJSON: cd,
      approval: createApproval(cd),
    });
    if (!res.ok) throw new Error(res.error);
    ({ credentialId, publicKey } = res.result as {
      credentialId: string;
      publicKey: { x: string; y: string };
    });
  });

  it('signs with a valid approval, and the signature verifies over authData || SHA-256(clientDataJSON)', () => {
    const cd = clientData('webauthn.get', ORIGIN);
    const ad = authData(RP);
    const res = sign(cd, signApproval(cd), ad);
    expect(res.ok).toBe(true);
    const sig = Buffer.from(
      (res as { result: { signature: string } }).result.signature,
      'base64url',
    );
    const key = createPublicKey({ key: { kty: 'EC', crv: 'P-256', ...publicKey }, format: 'jwk' });
    const hash = createHash('sha256').update(Buffer.from(cd, 'base64url')).digest();
    expect(verify('sha256', Buffer.concat([Buffer.from(ad, 'base64url'), hash]), key, sig)).toBe(
      true,
    );
  });

  const cases: [
    string,
    () => { cd: string; approval: SignedApproval | undefined; ad?: string },
    string,
  ][] = [
    [
      'no approval',
      () => ({ cd: clientData('webauthn.get', ORIGIN), approval: undefined }),
      'missing_approval',
    ],
    [
      'approval from an untrusted key',
      () => {
        const cd = clientData('webauthn.get', ORIGIN);
        const other = testApprover('test-approver');
        return { cd, approval: other.sign(statement({ credentialId, clientDataJSON: cd })) };
      },
      'bad_signature',
    ],
    [
      'unknown approver id',
      () => {
        const cd = clientData('webauthn.get', ORIGIN);
        return {
          cd,
          approval: testApprover('stranger').sign(statement({ credentialId, clientDataJSON: cd })),
        };
      },
      'untrusted_approver',
    ],
    [
      'statement tampered after signing',
      () => {
        const cd = clientData('webauthn.get', 'https://evil.example.com');
        const a = signApproval(clientData('webauthn.get', ORIGIN));
        return {
          cd,
          approval: {
            ...a,
            statement: { ...a.statement, verifiedOrigin: 'https://evil.example.com' },
          },
        };
      },
      'bad_signature',
    ],
    [
      'expired approval',
      () => {
        const cd = clientData('webauthn.get', ORIGIN);
        return {
          cd,
          approval: signApproval(cd, { issuedAt: Date.now() - 120_000, expiresAt: Date.now() - 1 }),
        };
      },
      'expired',
    ],
    [
      'approval issued more than the clock skew (30 s) in the future',
      () => {
        const cd = clientData('webauthn.get', ORIGIN);
        const t = Date.now() + 31_000;
        return { cd, approval: signApproval(cd, { issuedAt: t, expiresAt: t + 60_000 }) };
      },
      'not_yet_valid',
    ],
    [
      'approval lifetime longer than the signer allows',
      () => {
        const cd = clientData('webauthn.get', ORIGIN);
        return { cd, approval: signApproval(cd, { expiresAt: Date.now() + 3_600_000 }) };
      },
      'lifetime_too_long',
    ],
    [
      'create approval used for signing',
      () => {
        const cd = clientData('webauthn.get', ORIGIN);
        return {
          cd,
          approval: approver.sign(
            statement({ kind: 'webauthn.create', credentialId, clientDataJSON: cd }),
          ),
        };
      },
      'approval_kind_mismatch',
    ],
    [
      'approval for a different credential',
      () => {
        const cd = clientData('webauthn.get', ORIGIN);
        return { cd, approval: signApproval(cd, { credentialId: 'b3RoZXI' }) };
      },
      'approval_credential_mismatch',
    ],
    [
      'clientDataJSON differs from the one approved',
      () => ({
        cd: clientData('webauthn.get', ORIGIN, { challenge: 'b3RoZXItY2hhbGxlbmdlLXh4eA' }),
        approval: signApproval(clientData('webauthn.get', ORIGIN)),
      }),
      'client_data_hash_mismatch',
    ],
    [
      'clientDataJSON origin differs from the approved origin',
      () => {
        const cd = clientData('webauthn.get', 'https://evil.com');
        return { cd, approval: signApproval(cd) };
      },
      'client_data_origin_mismatch',
    ],
    [
      'crossOrigin clientData',
      () => {
        const cd = clientData('webauthn.get', ORIGIN, { crossOrigin: true });
        return { cd, approval: signApproval(cd) };
      },
      'cross_origin_not_allowed',
    ],
    [
      'approval missing an intent hash',
      () => {
        const cd = clientData('webauthn.get', ORIGIN);
        return { cd, approval: signApproval(cd, { intentHash: '' }) };
      },
      'approval_missing_intent',
    ],
    [
      'invariant 3: approved origin outside the credential rpId',
      () => {
        const cd = clientData('webauthn.get', 'https://example.com.evil.net');
        return {
          cd,
          approval: signApproval(cd, { verifiedOrigin: 'https://example.com.evil.net' }),
        };
      },
      'origin_not_within_rp_id',
    ],
    [
      'invariant 3: approval names a different rpId than the credential',
      () => {
        const cd = clientData('webauthn.get', 'https://evil.com');
        return {
          cd,
          approval: signApproval(cd, { rpId: 'evil.com', verifiedOrigin: 'https://evil.com' }),
        };
      },
      'approval_rp_mismatch',
    ],
    [
      'invariant 3: authenticatorData rpIdHash for another site',
      () => {
        const cd = clientData('webauthn.get', ORIGIN);
        return { cd, approval: signApproval(cd), ad: authData('evil.com') };
      },
      'rp_id_hash_mismatch',
    ],
    [
      'UV flag without a user-verified approval',
      () => {
        const cd = clientData('webauthn.get', ORIGIN);
        return { cd, approval: signApproval(cd), ad: authData(RP, 0x05) };
      },
      'uv_not_approved',
    ],
    [
      'no user-presence flag',
      () => {
        const cd = clientData('webauthn.get', ORIGIN);
        return { cd, approval: signApproval(cd), ad: authData(RP, 0x00) };
      },
      'missing_user_presence',
    ],
  ];

  it.each(cases)('refuses: %s', (_name, build, reason) => {
    const { cd, approval, ad } = build();
    expect(sign(cd, approval, ad)).toEqual({ ok: false, error: reason });
  });

  it('an approval is single-use', () => {
    const cd = clientData('webauthn.get', ORIGIN);
    const approval = signApproval(cd);
    expect(sign(cd, approval).ok).toBe(true);
    expect(sign(cd, approval)).toEqual({ ok: false, error: 'approval_replayed' });
  });

  it('refuses to create a credential without an approval, or for an rpId the origin does not cover', () => {
    const cd = clientData('webauthn.create', ORIGIN);
    expect(
      handler.handle({
        op: 'create_credential',
        rpId: RP,
        userHandle: 'dXNlcg',
        clientDataJSON: cd,
        approval: undefined as unknown as SignedApproval,
      }),
    ).toEqual({ ok: false, error: 'missing_approval' });
    const evil = clientData('webauthn.create', 'https://evil.com');
    expect(
      handler.handle({
        op: 'create_credential',
        rpId: RP,
        userHandle: 'dXNlcg',
        clientDataJSON: evil,
        approval: createApproval(evil, { verifiedOrigin: 'https://evil.com' }),
      }),
    ).toEqual({ ok: false, error: 'origin_not_within_rp_id' });
  });
});
