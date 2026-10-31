import { join } from 'node:path';
import type { CredentialSource, SourceItemInfo, SourceSecret } from '@aab/sources';
import { SourceError } from '@aab/sources';
import { beforeEach, describe, expect, it } from 'vitest';
import { type FillField, fillScope, type SignedApproval, sha256B64url } from '../src/approval.ts';
import { KeyStore } from '../src/keystore.ts';
import type { SignerRequest, SignerResponse } from '../src/protocol.ts';
import { SignerHandler } from '../src/server.ts';
import { totpCode } from '../src/totp.ts';
import { statement, testApprover, tmpDir } from './helpers.ts';

const REF = 'proton-pass:SHARE:-item1';
const DOMAIN = 'example.com';
const ORIGIN = 'https://login.example.com';
const PASSWORD = 'external Secr3t password';
const SEED = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';

class MemorySource implements CredentialSource {
  readonly kind = 'proton-pass';
  items: (SourceItemInfo & Record<string, unknown>)[] = [];
  secret: SourceSecret | SourceError = {
    hosts: ['login.example.com', 'example.org'],
    password: PASSWORD,
    totp: { secret: SEED },
  };
  fetches: { ref: string; reason: string }[] = [];
  gate: Promise<void> = Promise.resolve();

  async list(): Promise<SourceItemInfo[]> {
    if (this.secret instanceof SourceError) throw this.secret;
    return this.items;
  }

  async fetch(ref: string, reason: string): Promise<SourceSecret> {
    this.fetches.push({ ref, reason });
    await this.gate;
    if (this.secret instanceof SourceError) throw this.secret;
    return this.secret;
  }
}

describe('signer: external source items', () => {
  const approver = testApprover();
  let handler: SignerHandler;
  let source: MemorySource;
  let logs: { event: string; fields: Record<string, unknown> }[];
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
      credentialId: REF,
      clientDataHash: sha256B64url(fillScope(fields)),
      issuedAt: now,
      expiresAt: now + 60_000,
      ...rest,
    });
  };

  const call = (req: unknown) => handler.dispatch(req as SignerRequest);
  const release = (field: FillField, approval: SignedApproval, itemId = REF) =>
    call({ op: 'release_secret', itemId, field, approval });

  const makeHandler = (highRiskDomains: string[] = []) =>
    new SignerHandler({
      store: KeyStore.open(join(tmpDir(), 'keys'), 'pw'),
      trustedApproverKeys: approver.trusted,
      highRiskDomains,
      sources: [source],
      now: () => now,
      log: (event, fields) => logs.push({ event, fields }),
    });

  beforeEach(() => {
    now = Date.now();
    source = new MemorySource();
    logs = [];
    handler = makeHandler();
  });

  it('releases the password and the current TOTP code once each under one approval', async () => {
    const a = fillApproval();
    expect(await release('password', a)).toEqual({ ok: true, result: { value: PASSWORD } });
    const expected = totpCode({ secret: SEED, algorithm: 'SHA1', digits: 6, period: 30 }, now);
    expect(await release('totp', a)).toEqual({ ok: true, result: { value: expected } });
    expect(await release('password', a)).toEqual({ ok: false, error: 'approval_replayed' });
    expect(await release('totp', a)).toEqual({ ok: false, error: 'approval_replayed' });
    expect(source.fetches).toHaveLength(2);
    expect(source.fetches[0]).toEqual({
      ref: REF,
      reason: `Keyflap broker: approved sign-in on ${ORIGIN}`,
    });
  });

  it("refuses when the live item's URLs don't fall within the approved domain", async () => {
    source.secret = {
      hosts: ['other.test', 'example.com.evil.test'],
      password: PASSWORD,
      totp: null,
    };
    const a = fillApproval();
    expect(await release('password', a)).toEqual({ ok: false, error: 'item_not_for_domain' });
    source.secret = { hosts: ['example.com'], password: PASSWORD, totp: null };
    expect(await release('password', a)).toEqual({ ok: false, error: 'approval_replayed' });
  });

  it('accepts an item URL on the domain itself or any subdomain of it', async () => {
    source.secret = { hosts: ['example.com'], password: PASSWORD, totp: null };
    expect((await release('password', fillApproval())).ok).toBe(true);
    source.secret = { hosts: ['deep.sub.example.com'], password: PASSWORD, totp: null };
    expect((await release('password', fillApproval())).ok).toBe(true);
  });

  const denials: [string, () => SignedApproval, FillField, string][] = [
    ['no approval', () => undefined as unknown as SignedApproval, 'password', 'missing_approval'],
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
      'passkey sign-in approval',
      () => fillApproval({ kind: 'webauthn.get' }),
      'password',
      'approval_kind_mismatch',
    ],
    [
      'another item',
      () => fillApproval({ credentialId: 'proton-pass:SHARE:other' }),
      'password',
      'approval_credential_mismatch',
    ],
    [
      'origin outside the domain',
      () => fillApproval({ verifiedOrigin: 'https://example.com.evil.test' }),
      'password',
      'origin_not_within_rp_id',
    ],
    [
      'a bare TLD as the domain',
      () => fillApproval({ rpId: 'com' }),
      'password',
      'approval_rp_mismatch',
    ],
    ['no intent', () => fillApproval({ intentHash: '' }), 'password', 'approval_missing_intent'],
    [
      'field outside the scope',
      () => fillApproval({ fields: ['totp'] }),
      'password',
      'field_not_approved',
    ],
  ];
  for (const [name, approval, field, error] of denials) {
    it(`denies: ${name}`, async () => {
      expect(await release(field, approval())).toEqual({ ok: false, error });
      expect(source.fetches).toHaveLength(0);
    });
  }

  it('two concurrent requests with one approval read the item once', async () => {
    let open: () => void = () => {};
    source.gate = new Promise((r) => {
      open = r;
    });
    const a = fillApproval();
    const first = release('password', a);
    const second = release('password', a);
    open();
    expect(await first).toEqual({ ok: true, result: { value: PASSWORD } });
    expect(await second).toEqual({ ok: false, error: 'approval_replayed' });
    expect(source.fetches).toHaveLength(1);
  });

  it('passes on source failures as fixed reasons', async () => {
    source.secret = new SourceError('source_not_logged_in');
    expect(await release('password', fillApproval())).toEqual({
      ok: false,
      error: 'source_not_logged_in',
    });
    source.secret = { hosts: ['example.com'], password: 'abc', totp: null };
    expect(await release('password', fillApproval())).toEqual({ ok: false, error: 'bad_password' });
    expect(await release('totp', fillApproval())).toEqual({ ok: false, error: 'no_totp' });
  });

  it('a high-risk domain needs a phone approval with user verification', async () => {
    handler = makeHandler([DOMAIN]);
    expect(await release('password', fillApproval())).toEqual({
      ok: false,
      error: 'user_verification_required',
    });
  });

  it('a ref of an unconfigured source is just an unknown native item', async () => {
    const ref = 'bitwarden:x:y';
    expect(await release('password', fillApproval({ credentialId: ref }), ref)).toEqual({
      ok: false,
      error: 'unknown_item',
    });
  });

  it('lists metadata only, rebuilt field by field', async () => {
    source.items = [
      {
        ref: REF,
        hosts: ['login.example.com'],
        username: 'alice',
        hasTotp: true,
        password: PASSWORD,
      },
    ];
    const res = (await call({ op: 'list_source_items', source: 'proton-pass' })) as SignerResponse<{
      items: unknown[];
    }>;
    expect(res).toEqual({
      ok: true,
      result: {
        items: [{ ref: REF, hosts: ['login.example.com'], username: 'alice', hasTotp: true }],
      },
    });
    expect(await call({ op: 'list_source_items', source: 'nope' })).toEqual({
      ok: false,
      error: 'unknown_source',
    });
    source.secret = new SourceError('source_timeout');
    expect(await call({ op: 'list_source_items', source: 'proton-pass' })).toEqual({
      ok: false,
      error: 'source_timeout',
    });
  });

  it('never logs a secret', async () => {
    const a = fillApproval();
    await release('password', a);
    await release('totp', a);
    const text = JSON.stringify(logs);
    expect(text).not.toContain(PASSWORD);
    expect(text).not.toContain(SEED);
    expect(logs.filter((l) => l.event === 'released')).toEqual([
      {
        event: 'released',
        fields: expect.objectContaining({ itemId: REF, field: 'password', source: 'proton-pass' }),
      },
      { event: 'released', fields: expect.objectContaining({ itemId: REF, field: 'totp' }) },
    ]);
  });
});
