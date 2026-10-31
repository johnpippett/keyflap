import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeEach, describe, expect, it } from 'vitest';
import { type FillField, fillScope, type SignedApproval, sha256B64url } from '../src/approval.ts';
import { KeyStore } from '../src/keystore.ts';
import { SignerHandler } from '../src/server.ts';
import { base32Decode, base32Encode, hotp, normalizeTotp, totpCode } from '../src/totp.ts';
import { clientData, statement, testApprover, tmpDir } from './helpers.ts';

const DOMAIN = 'example.com';
const ORIGIN = 'https://login.example.com';
const PASSWORD = 'correct horse battery staple';
const SEED = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';

describe('signer password items and fill release', () => {
  const approver = testApprover();
  let handler: SignerHandler;
  let store: KeyStore;
  let storePath: string;
  let itemId: string;
  let now = Date.now();

  const fillApproval = (
    over: Partial<Parameters<typeof statement>[0]> & { fields?: FillField[] } = {},
  ): SignedApproval => {
    const { fields = ['password', 'totp'], ...rest } = over;
    return approver.sign({
      ...statement({ clientDataJSON: '' }),
      kind: 'fill',
      verifiedOrigin: ORIGIN,
      rpId: DOMAIN,
      credentialId: itemId,
      clientDataHash: sha256B64url(fillScope(fields)),
      issuedAt: now,
      expiresAt: now + 60_000,
      ...rest,
    });
  };

  const release = (field: FillField, approval: SignedApproval, id = itemId) =>
    handler.handle({ op: 'release_secret', itemId: id, field, approval });

  beforeEach(() => {
    now = Date.now();
    storePath = join(tmpDir(), 'keys');
    store = KeyStore.open(storePath, 'pw');
    handler = new SignerHandler({ store, trustedApproverKeys: approver.trusted, now: () => now });
    const res = handler.handle({
      op: 'store_item',
      domain: DOMAIN,
      password: PASSWORD,
      totp: { secret: SEED },
    });
    if (!res.ok) throw new Error(res.error);
    itemId = (res.result as { itemId: string }).itemId;
  });

  it('releases the password and the current TOTP code once each under one approval', () => {
    const a = fillApproval();
    expect(release('password', a)).toEqual({ ok: true, result: { value: PASSWORD } });
    const code = release('totp', a);
    const expected = totpCode({ secret: SEED, algorithm: 'SHA1', digits: 6, period: 30 }, now);
    expect(code).toEqual({ ok: true, result: { value: expected } });
    expect(release('password', a)).toEqual({ ok: false, error: 'approval_replayed' });
    expect(release('totp', a)).toEqual({ ok: false, error: 'approval_replayed' });
  });

  it('persists items encrypted; the password and seed are not in the file', () => {
    const raw = readFileSync(storePath, 'utf8');
    expect(raw).not.toContain(PASSWORD);
    expect(raw).not.toContain(SEED);
    const reopened = KeyStore.open(storePath, 'pw');
    expect(reopened.item(itemId)?.password).toBe(PASSWORD);
    expect(reopened.item(itemId)?.totp?.secret).toBe(SEED);
  });

  const denials: [string, () => SignedApproval, FillField, string][] = [
    ['no approval', () => undefined as unknown as SignedApproval, 'password', 'missing_approval'],
    [
      'untrusted approver',
      () => {
        const other = testApprover('test-approver');
        return other.sign(fillApproval().statement);
      },
      'password',
      'bad_signature',
    ],
    [
      'tampered statement',
      () => {
        const a = fillApproval();
        return { ...a, statement: { ...a.statement, verifiedOrigin: 'https://evil.com' } };
      },
      'password',
      'bad_signature',
    ],
    [
      'expired',
      () => fillApproval({ issuedAt: now - 120_000, expiresAt: now - 1 }),
      'password',
      'expired',
    ],
    [
      'passkey sign-in approval',
      () => fillApproval({ kind: 'webauthn.get' }),
      'password',
      'approval_kind_mismatch',
    ],
    [
      'other item',
      () => fillApproval({ credentialId: 'pw_other' }),
      'password',
      'approval_credential_mismatch',
    ],
    ['other domain', () => fillApproval({ rpId: 'evil.com' }), 'password', 'approval_rp_mismatch'],
    [
      'origin outside the domain',
      () => fillApproval({ verifiedOrigin: 'https://example.com.evil.com' }),
      'password',
      'origin_not_within_rp_id',
    ],
    [
      'origin that is not an origin',
      () => fillApproval({ verifiedOrigin: 'https://login.example.com/path' }),
      'password',
      'origin_not_within_rp_id',
    ],
    ['no intent', () => fillApproval({ intentHash: '' }), 'password', 'approval_missing_intent'],
    [
      'field outside the scope',
      () => fillApproval({ fields: ['totp'] }),
      'password',
      'field_not_approved',
    ],
    [
      'totp outside the scope',
      () => fillApproval({ fields: ['password'] }),
      'totp',
      'field_not_approved',
    ],
    [
      'scope hash that matches no scope',
      () => fillApproval({ clientDataHash: sha256B64url('aab-fill-v1\npassword,totp,extra') }),
      'password',
      'field_not_approved',
    ],
  ];
  for (const [name, make, field, error] of denials) {
    it(`refuses: ${name}`, () => {
      expect(release(field, make())).toEqual({ ok: false, error });
      expect(release(field, fillApproval())).toMatchObject({ ok: true });
    });
  }

  it('refuses unknown items and fields', () => {
    expect(release('password', fillApproval(), 'pw_nope')).toEqual({
      ok: false,
      error: 'unknown_item',
    });
    expect(release('pin' as FillField, fillApproval())).toEqual({ ok: false, error: 'bad_field' });
  });

  it('refuses totp for an item without a seed', () => {
    const res = handler.handle({ op: 'store_item', domain: DOMAIN, password: 'xxxx' });
    const id = (res as { result: { itemId: string } }).result.itemId;
    expect(release('totp', fillApproval({ credentialId: id }), id)).toEqual({
      ok: false,
      error: 'no_totp',
    });
  });

  it('a fill approval cannot be replayed as a passkey approval, nor the other way round', () => {
    const cd = clientData('webauthn.create', ORIGIN);
    const create = handler.handle({
      op: 'create_credential',
      rpId: DOMAIN,
      userHandle: 'dXNlcg',
      clientDataJSON: cd,
      approval: fillApproval(),
    });
    expect(create).toEqual({ ok: false, error: 'approval_kind_mismatch' });
    const requestId = randomUUID();
    const pk = approver.sign(
      statement({
        kind: 'webauthn.create',
        requestId,
        clientDataJSON: cd,
        verifiedOrigin: ORIGIN,
        rpId: DOMAIN,
      }),
    );
    expect(
      handler.handle({
        op: 'create_credential',
        rpId: DOMAIN,
        userHandle: 'dXNlcg',
        clientDataJSON: cd,
        approval: pk,
      }),
    ).toMatchObject({ ok: true });
    expect(release('password', fillApproval({ requestId }))).toEqual({
      ok: false,
      error: 'approval_replayed',
    });
  });

  it('validates stored items', () => {
    const bad: [Record<string, unknown>, string][] = [
      [{ domain: 'Example.com', password: 'xxxx' }, 'bad_domain'],
      [{ domain: 'com', password: 'xxxx' }, 'bad_domain'],
      [{ domain: 'example.com/x', password: 'xxxx' }, 'bad_domain'],
      [{ domain: DOMAIN, password: '' }, 'bad_password'],
      [{ domain: DOMAIN, password: 'abc' }, 'bad_password'],
      [{ domain: DOMAIN, password: 'a\u0000b' }, 'bad_password'],
      [{ domain: DOMAIN, password: 'x'.repeat(1025) }, 'bad_password'],
      [{ domain: DOMAIN, password: 'xxxx', totp: { secret: 'not base32!' } }, 'bad_totp'],
      [{ domain: DOMAIN, password: 'xxxx', totp: { secret: 'JBSWY3DP' } }, 'bad_totp'],
      [{ domain: DOMAIN, password: 'xxxx', totp: { secret: SEED, digits: 9 } }, 'bad_totp'],
      [{ domain: DOMAIN, password: 'xxxx', totp: { secret: SEED, algorithm: 'MD5' } }, 'bad_totp'],
    ];
    for (const [req, error] of bad) {
      expect(handler.handle({ op: 'store_item', ...req } as never), JSON.stringify(req)).toEqual({
        ok: false,
        error,
      });
    }
  });

  it('deletes items', () => {
    expect(handler.handle({ op: 'delete_item', itemId })).toEqual({
      ok: true,
      result: { deleted: true },
    });
    expect(release('password', fillApproval())).toEqual({ ok: false, error: 'unknown_item' });
    expect(handler.handle({ op: 'delete_item', itemId })).toEqual({
      ok: true,
      result: { deleted: false },
    });
  });

  it('never logs a password, seed or code', () => {
    const log: string[] = [];
    const h = new SignerHandler({
      store,
      trustedApproverKeys: approver.trusted,
      now: () => now,
      log: (e, f) => log.push(JSON.stringify([e, f])),
    });
    h.handle({ op: 'store_item', domain: DOMAIN, password: PASSWORD, totp: { secret: SEED } });
    const a = fillApproval();
    const code = (
      h.handle({ op: 'release_secret', itemId, field: 'totp', approval: a }) as {
        result: { value: string };
      }
    ).result.value;
    h.handle({ op: 'release_secret', itemId, field: 'password', approval: a });
    const all = log.join('\n');
    expect(log.length).toBeGreaterThanOrEqual(3);
    for (const s of [PASSWORD, SEED, code]) expect(all).not.toContain(s);
  });
});

describe('TOTP', () => {
  it('matches the RFC 6238 test vectors (SHA1, SHA256, SHA512; 8 digits)', () => {
    const seeds = {
      SHA1: Buffer.from('12345678901234567890'),
      SHA256: Buffer.from('12345678901234567890123456789012'),
      SHA512: Buffer.from('1234567890123456789012345678901234567890123456789012345678901234'),
    } as const;
    const vectors: [number, string, string, string][] = [
      [59, '94287082', '46119246', '90693936'],
      [1111111109, '07081804', '68084774', '25091201'],
      [2000000000, '69279037', '90698825', '38618901'],
    ];
    for (const [t, sha1, sha256, sha512] of vectors) {
      for (const [alg, want] of [
        ['SHA1', sha1],
        ['SHA256', sha256],
        ['SHA512', sha512],
      ] as const) {
        const secret = base32Encode(seeds[alg]);
        expect(totpCode({ secret, algorithm: alg, digits: 8, period: 30 }, t * 1000)).toBe(want);
      }
    }
  });

  it('matches RFC 4226 HOTP vectors', () => {
    const key = Buffer.from('12345678901234567890');
    const want = ['755224', '287082', '359152', '969429', '338314'];
    for (const [i, w] of want.entries()) expect(hotp(key, i, 6, 'SHA1')).toBe(w);
  });

  it('base32 round-trips and normalizes', () => {
    const bytes = Buffer.from('any carnal pleasure.');
    expect(base32Decode(base32Encode(bytes))).toEqual(bytes);
    expect(normalizeTotp({ secret: 'jbsw y3dp ehpk 3pxp' })).toEqual({
      secret: 'JBSWY3DPEHPK3PXP',
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
    });
    expect(normalizeTotp({ secret: 'JBSWY3DPEHPK3PXP', period: 10 })).toBeNull();
    expect(base32Decode('A1')).toBeNull();
  });
});
