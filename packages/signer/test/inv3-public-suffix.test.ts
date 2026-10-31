import { join } from 'node:path';
import type { CredentialSource, SourceItemInfo, SourceSecret } from '@aab/sources';
import { beforeEach, describe, expect, it } from 'vitest';
import {
  type ApprovalStatement,
  type FillField,
  fillScope,
  type SignedApproval,
  sha256B64url,
} from '../src/approval.ts';
import { KeyStore } from '../src/keystore.ts';
import type { SignerRequest, SignerResponse } from '../src/protocol.ts';
import { isHighRisk } from '../src/risk.ts';
import { SignerHandler } from '../src/server.ts';
import { clientData, statement, testApprover, testPhone, tmpDir } from './helpers.ts';

const REF = 'proton-pass:SHARE:bankitem';
const BANK_SECRET = 'BARCLAYS-SECRET';

class MemorySource implements CredentialSource {
  readonly kind = 'proton-pass';
  secret: SourceSecret = { hosts: ['www.barclays.co.uk'], password: BANK_SECRET, totp: null };
  fetches = 0;
  async list(): Promise<SourceItemInfo[]> {
    return [];
  }
  async fetch(): Promise<SourceSecret> {
    this.fetches++;
    return this.secret;
  }
}

describe('invariant 3/6: the signer refuses public-suffix rpIds itself (M1)', () => {
  const terminal = testApprover();
  let phone: ReturnType<typeof testPhone>;
  let source: MemorySource;
  let handler: SignerHandler;
  let logs: { event: string; fields: Record<string, unknown> }[];
  let now = Date.now();

  const call = (req: unknown) => handler.dispatch(req as SignerRequest);
  const pair = () => handler.handle({ op: 'add_approver', key: phone.key } as SignerRequest);

  const fill = (
    over: Partial<ApprovalStatement> & { fields?: FillField[] } = {},
  ): ApprovalStatement => {
    const { fields = ['password'], ...rest } = over;
    return {
      ...statement({ clientDataJSON: '' }),
      kind: 'fill',
      verifiedOrigin: 'https://www.bbc.co.uk',
      rpId: 'bbc.co.uk',
      credentialId: REF,
      clientDataHash: sha256B64url(fillScope(fields)),
      issuedAt: now,
      expiresAt: now + 60_000,
      ...rest,
    };
  };
  const release = (approval: SignedApproval, itemId = REF): Promise<SignerResponse> =>
    call({ op: 'release_secret', itemId, field: 'password', approval });

  beforeEach(() => {
    now = Date.now();
    phone = testPhone();
    source = new MemorySource();
    logs = [];
    handler = new SignerHandler({
      store: KeyStore.open(join(tmpDir(), 'keys'), 'pw'),
      trustedApproverKeys: terminal.trusted,
      sources: [source],
      now: () => now,
      log: (event, fields) => logs.push({ event, fields }),
    });
  });

  it('an approval for bbc.co.uk with rpId co.uk does not release a barclays.co.uk item', async () => {
    const res = await release(terminal.sign(fill({ rpId: 'co.uk' })));
    expect(res).toEqual({ ok: false, error: 'approval_rp_mismatch' });
    expect(source.fetches).toBe(0);
  });

  it('nor with rpId co.uk and a grant (no 12 h grant for a suffix)', async () => {
    const st = fill({ rpId: 'co.uk', grant: { agentId: 'a1', until: now + 12 * 3600_000 } });
    expect((await release(terminal.sign(st))).ok).toBe(false);
    expect(logs.some((l) => l.event === 'grant_recorded')).toBe(false);
  });

  it("an external item's rpId must be exactly the origin's registrable domain", async () => {
    source.secret = { hosts: ['www.bbc.co.uk'], password: 'bbc password', totp: null };
    for (const [origin, rpId, error] of [
      ['https://www.bbc.co.uk', 'www.bbc.co.uk', 'approval_rp_mismatch'],
      ['https://www.bbc.co.uk', 'uk', 'approval_rp_mismatch'],
      ['https://www.bbc.co.uk', 'barclays.co.uk', 'origin_not_within_rp_id'],
      ['https://a.github.io', 'github.io', 'approval_rp_mismatch'],
      ['https://www.bbc.co.uk.', 'bbc.co.uk', 'origin_not_within_rp_id'],
    ] as const) {
      expect(await release(terminal.sign(fill({ verifiedOrigin: origin, rpId })))).toEqual({
        ok: false,
        error,
      });
    }
    expect(source.fetches).toBe(0);
    const ok = await release(terminal.sign(fill()));
    expect(ok).toEqual({ ok: true, result: { value: 'bbc password' } });
  });

  it('the live item must have a host of that registrable domain (not only a shared suffix)', async () => {
    expect(await release(terminal.sign(fill()))).toEqual({
      ok: false,
      error: 'item_not_for_domain',
    });
    expect(source.fetches).toBe(1);
  });

  it('every live host of the item counts for the high-risk tier', async () => {
    source.secret = {
      hosts: ['www.bbc.co.uk', 'www.barclays.co.uk'],
      password: BANK_SECRET,
      totp: null,
    };
    expect(await release(terminal.sign(fill()))).toEqual({
      ok: false,
      error: 'user_verification_required',
    });
    expect(pair().ok).toBe(true);
    const granted = fill({ userVerified: true, grant: { agentId: 'a1', until: now + 30_000 } });
    expect(await release(phone.approve(granted))).toEqual({
      ok: false,
      error: 'grant_not_allowed',
    });
    expect(logs.some((l) => l.event === 'grant_recorded')).toBe(false);
    expect(await release(phone.approve(fill({ userVerified: true })))).toEqual({
      ok: true,
      result: { value: BANK_SECRET },
    });
  });

  it('a grant recorded for a plain item never releases it once its live hosts are high-risk', async () => {
    source.secret = { hosts: ['www.bbc.co.uk'], password: 'bbc password', totp: null };
    const st = fill({ grant: { agentId: 'a1', until: now + 3600_000 } });
    expect((await release(terminal.sign(st))).ok).toBe(true);
    expect(logs.some((l) => l.event === 'grant_recorded')).toBe(true);
    source.secret = { ...source.secret, hosts: ['www.bbc.co.uk', 'barclays.co.uk'] };
    const use = {
      grantId: st.requestId,
      agentId: 'a1',
      statement: { ...fill(), grant: undefined },
    };
    expect(await release(use as unknown as SignedApproval)).toEqual({
      ok: false,
      error: 'user_verification_required',
    });
  });

  it('no passkey is created or used for a public suffix rpId', () => {
    for (const [rpId, origin] of [
      ['co.uk', 'https://www.bbc.co.uk'],
      ['github.io', 'https://victim.github.io'],
      ['com', 'https://example.com'],
      ['localhost', 'http://rp.localhost:3000'],
    ] as const) {
      const cd = clientData('webauthn.create', origin);
      const st = statement({
        clientDataJSON: cd,
        kind: 'webauthn.create',
        rpId,
        verifiedOrigin: origin,
        clientDataHash: sha256B64url(Buffer.from(cd, 'base64url')),
      });
      const res = handler.handle({
        op: 'create_credential',
        rpId,
        userHandle: 'dXNlcg',
        clientDataJSON: cd,
        approval: terminal.sign(st),
      } as SignerRequest);
      expect(res).toEqual({ ok: false, error: 'origin_not_within_rp_id' });
    }
  });

  it('a native item is stored only for a registrable domain', () => {
    for (const domain of ['co.uk', 'github.io', 'com', 'www.example.com', 'Example.com']) {
      expect(handler.handle({ op: 'store_item', domain, password: 'hunter2hunter2' })).toEqual({
        ok: false,
        error: 'bad_domain',
      });
    }
    expect(
      handler.handle({ op: 'store_item', domain: 'bbc.co.uk', password: 'hunter2hunter2' }).ok,
    ).toBe(true);
  });

  it('high-risk classification: a public suffix or a non-host is high-risk', () => {
    expect(isHighRisk('co.uk')).toBe(true);
    expect(isHighRisk('github.io')).toBe(true);
    expect(isHighRisk('com')).toBe(true);
    expect(isHighRisk('not a host')).toBe(true);
    expect(isHighRisk('www.barclays.co.uk')).toBe(true);
    expect(isHighRisk('bbc.co.uk')).toBe(false);
    expect(isHighRisk('rp.localhost')).toBe(false);
    expect(isHighRisk('localhost')).toBe(false);
  });
});
