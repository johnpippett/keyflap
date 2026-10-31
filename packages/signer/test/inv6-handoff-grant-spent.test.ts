import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { beforeEach, describe, expect, it } from 'vitest';
import {
  type ApprovalStatement,
  fillScope,
  type GrantedApproval,
  HANDOFF_GRANT_MAX_MS,
  handoffSignInClientDataHash,
  sha256B64url,
} from '../src/approval.ts';
import { KeyStore } from '../src/keystore.ts';
import { SignerHandler } from '../src/server.ts';
import { authData, clientData, statement, testPhone, tmpDir } from './helpers.ts';

type Res = { ok: true; result: Record<string, unknown> } | { ok: false; error: string };

const DOMAIN = 'example.com';
const ORIGIN = 'https://login.example.com';
const AGENT = 'agent-1';
const PASSWORD = 'correct horse battery staple';
const HANDOFF = randomUUID();

describe('invariant 6 (P3b): a single-use grant is spent before the use is fully checked', () => {
  let handler: SignerHandler;
  let now: number;
  let phone: ReturnType<typeof testPhone>;
  let itemId: string;
  let credentialId: string;

  const call = (req: unknown) => handler.handle(req as never) as Res;

  const grant = (over: Partial<ApprovalStatement>): string => {
    const s: ApprovalStatement = {
      ...statement({ clientDataJSON: '' }),
      userVerified: true,
      issuedAt: now,
      expiresAt: now + 60_000,
      grant: { agentId: AGENT, until: now + HANDOFF_GRANT_MAX_MS, uses: 1 },
      handoff: { id: HANDOFF },
      verifiedOrigin: ORIGIN,
      rpId: DOMAIN,
      ...over,
    };
    const r = call({ op: 'accept_handoff_grant', approval: phone.approve(s) });
    if (!r.ok) throw new Error(r.error);
    return s.requestId;
  };
  const passkeyGrant = () =>
    grant({
      kind: 'webauthn.get',
      credentialId,
      clientDataHash: handoffSignInClientDataHash(HANDOFF),
    });
  const fillGrant = () =>
    grant({
      kind: 'fill',
      credentialId: itemId,
      clientDataHash: sha256B64url(fillScope(['password'])),
    });

  const sign = (grantId: string, o: { sentClientData?: string } = {}) => {
    const cd = clientData('webauthn.get', ORIGIN);
    return call({
      op: 'sign',
      credentialId,
      authenticatorData: authData(DOMAIN, 0x01),
      clientDataJSON: o.sentClientData ?? cd,
      approval: {
        statement: statement({
          kind: 'webauthn.get',
          verifiedOrigin: ORIGIN,
          rpId: DOMAIN,
          credentialId,
          clientDataJSON: cd,
          issuedAt: now,
          expiresAt: now + 60_000,
        }),
        grantId,
        agentId: AGENT,
      } satisfies GrantedApproval,
    });
  };
  const release = (grantId: string, over: Partial<ApprovalStatement> = {}) =>
    call({
      op: 'release_secret',
      itemId,
      field: 'password',
      approval: {
        statement: {
          ...statement({ clientDataJSON: '' }),
          kind: 'fill',
          verifiedOrigin: ORIGIN,
          rpId: DOMAIN,
          credentialId: itemId,
          clientDataHash: sha256B64url(fillScope(['password'])),
          issuedAt: now,
          expiresAt: now + 60_000,
          ...over,
        },
        grantId,
        agentId: AGENT,
      } satisfies GrantedApproval,
    });

  beforeEach(() => {
    now = Date.now();
    phone = testPhone();
    const store = KeyStore.open(join(tmpDir(), 'keys'), 'pw');
    handler = new SignerHandler({ store, trustedApproverKeys: {}, now: () => now });
    expect(call({ op: 'add_approver', key: phone.key }).ok).toBe(true);
    const item = call({ op: 'store_item', domain: DOMAIN, password: PASSWORD });
    if (!item.ok) throw new Error(item.error);
    itemId = item.result.itemId as string;
    credentialId = store.createP256(DOMAIN, 'dXNlcg').credentialId;
  });

  it('a sign that fails on its client data after the grant check still burns the grant', () => {
    const grantId = passkeyGrant();
    const wrongClientData = clientData('webauthn.get', ORIGIN, { challenge: 'b3RoZXI' });
    expect(sign(grantId, { sentClientData: wrongClientData })).toEqual({
      ok: false,
      error: 'client_data_hash_mismatch',
    });
    expect(sign(grantId)).toEqual({ ok: false, error: 'grant_used' });
  });

  it('a release that fails on its statement after the grant check still burns the grant', () => {
    const grantId = fillGrant();
    expect(release(grantId, { intentHash: '' })).toEqual({
      ok: false,
      error: 'approval_missing_intent',
    });
    expect(release(grantId)).toEqual({ ok: false, error: 'grant_used' });
  });

  it('control: the same correct requests on an unburned grant succeed', () => {
    expect(sign(passkeyGrant()).ok).toBe(true);
    expect(release(fillGrant())).toEqual({ ok: true, result: { value: PASSWORD } });
  });
});
