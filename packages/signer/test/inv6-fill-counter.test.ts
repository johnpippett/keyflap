import { join } from 'node:path';
import { beforeEach, describe, expect, it } from 'vitest';
import {
  type ApprovalStatement,
  type FillField,
  fillScope,
  type SignedApproval,
  sha256B64url,
} from '../src/approval.ts';
import { KeyStore } from '../src/keystore.ts';
import { SignerHandler } from '../src/server.ts';
import { totpCode } from '../src/totp.ts';
import { statement, testPhone, tmpDir } from './helpers.ts';

type Res = { ok: true; result: Record<string, unknown> } | { ok: false; error: string };

const DOMAIN = 'example.com';
const ORIGIN = 'https://login.example.com';
const PASSWORD = 'correct horse battery staple';
const SEED = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';

describe('invariant 6: phone fill approval from an authenticator with a sign counter', () => {
  let storePath: string;
  let store: KeyStore;
  let handler: SignerHandler;
  let phone: ReturnType<typeof testPhone>;
  let itemId: string;
  let now = Date.now();

  const open = () => {
    store = KeyStore.open(storePath, 'pw');
    handler = new SignerHandler({ store, trustedApproverKeys: {}, now: () => now });
  };
  const call = (req: unknown) => handler.handle(req as never) as Res;
  const fillStatement = (fields: FillField[] = ['password', 'totp']): ApprovalStatement => ({
    ...statement({ clientDataJSON: '' }),
    kind: 'fill',
    verifiedOrigin: ORIGIN,
    rpId: DOMAIN,
    credentialId: itemId,
    clientDataHash: sha256B64url(fillScope(fields)),
    userVerified: true,
    issuedAt: now,
    expiresAt: now + 60_000,
  });
  const release = (field: FillField, approval: SignedApproval) =>
    call({ op: 'release_secret', itemId, field, approval });
  const counter = () => store.approver(phone.key.credentialId)?.signCount;
  const code = () => totpCode({ secret: SEED, algorithm: 'SHA1', digits: 6, period: 30 }, now);

  beforeEach(() => {
    now = Date.now();
    storePath = join(tmpDir(), 'keys');
    phone = testPhone();
    open();
    expect(call({ op: 'add_approver', key: phone.key }).ok).toBe(true);
    const res = call({
      op: 'store_item',
      domain: DOMAIN,
      password: PASSWORD,
      totp: { secret: SEED },
    });
    if (!res.ok) throw new Error(res.error);
    itemId = res.result.itemId as string;
    phone.setCounter(5);
  });

  it('releases the password then the TOTP code under one counting assertion, each once', () => {
    const a = phone.approve(fillStatement());
    expect(release('password', a)).toEqual({ ok: true, result: { value: PASSWORD } });
    expect(counter()).toBe(5);
    expect(release('totp', a)).toEqual({ ok: true, result: { value: code() } });
    expect(counter()).toBe(5);
    expect(release('password', a)).toEqual({ ok: false, error: 'approval_replayed' });
    expect(release('totp', a)).toEqual({ ok: false, error: 'approval_replayed' });
  });

  it('also in the other order (TOTP first)', () => {
    const a = phone.approve(fillStatement());
    expect(release('totp', a)).toEqual({ ok: true, result: { value: code() } });
    expect(release('password', a)).toEqual({ ok: true, result: { value: PASSWORD } });
  });

  it('a different fill (another requestId) still needs the counter to move forward', () => {
    expect(release('password', phone.approve(fillStatement())).ok).toBe(true);
    expect(release('password', phone.approve(fillStatement()))).toEqual({
      ok: false,
      error: 'sign_count_regressed',
    });
    phone.setCounter(6);
    expect(release('password', phone.approve(fillStatement())).ok).toBe(true);
    expect(counter()).toBe(6);
  });

  it('only the exact assertion that was accepted: a re-signed copy for the same fill is refused', () => {
    const s = fillStatement();
    expect(release('password', phone.approve(s)).ok).toBe(true);
    expect(release('totp', phone.approve(s))).toEqual({
      ok: false,
      error: 'sign_count_regressed',
    });
  });

  it('nothing carries over a signer restart', () => {
    const a = phone.approve(fillStatement());
    expect(release('password', a).ok).toBe(true);
    open();
    expect(release('totp', a)).toEqual({ ok: false, error: 'sign_count_regressed' });
  });

  it('expires with the approval', () => {
    const a = phone.approve(fillStatement());
    expect(release('password', a).ok).toBe(true);
    now += 60_001;
    expect(release('totp', a)).toEqual({ ok: false, error: 'sign_count_regressed' });
  });

  it('a later fill moving the counter does not let the earlier one lower it', () => {
    const first = phone.approve(fillStatement());
    expect(release('password', first).ok).toBe(true);
    phone.setCounter(6);
    expect(release('password', phone.approve(fillStatement())).ok).toBe(true);
    expect(release('totp', first)).toEqual({ ok: true, result: { value: code() } });
    expect(counter()).toBe(6);
    phone.setCounter(6);
    expect(release('password', phone.approve(fillStatement()))).toEqual({
      ok: false,
      error: 'sign_count_regressed',
    });
  });

  it('a statement changed after acceptance is not the accepted assertion', () => {
    const a = phone.approve(fillStatement());
    expect(release('password', a).ok).toBe(true);
    const asGet = { ...a, statement: { ...a.statement, kind: 'webauthn.get' as const } };
    expect(release('totp', asGet)).toEqual({ ok: false, error: 'assertion_challenge_mismatch' });
  });
});
