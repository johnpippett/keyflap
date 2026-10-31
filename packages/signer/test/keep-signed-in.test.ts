import { join } from 'node:path';
import { beforeEach, describe, expect, it } from 'vitest';
import { type ApprovalStatement, keepSignedInOk, statementExtrasOk } from '../src/approval.ts';
import { KeyStore } from '../src/keystore.ts';
import { SignerHandler } from '../src/server.ts';
import { authData, clientData, statement, testApprover, tmpDir } from './helpers.ts';

type Res = { ok: true; result: Record<string, unknown> } | { ok: false; error: string };
const RP = 'example.com';
const ORIGIN = 'https://login.example.com';

describe('keepSignedIn in the signed statement', () => {
  const approver = testApprover();
  let handler: SignerHandler;
  let credentialId: string;
  const call = (req: unknown) => handler.handle(req as never) as Res;

  beforeEach(() => {
    handler = new SignerHandler({
      store: KeyStore.open(join(tmpDir(), 'keys'), 'pw'),
      trustedApproverKeys: approver.trusted,
      highRiskDomains: [],
    });
    const cd = clientData('webauthn.create', ORIGIN);
    const r = call({
      op: 'create_credential',
      rpId: RP,
      userHandle: 'dXNlcg',
      clientDataJSON: cd,
      approval: approver.sign(
        statement({
          kind: 'webauthn.create',
          rpId: RP,
          verifiedOrigin: ORIGIN,
          clientDataJSON: cd,
        }),
      ),
    });
    if (!r.ok) throw new Error(r.error);
    credentialId = r.result.credentialId as string;
  });

  const getStatement = (over: Partial<ApprovalStatement> = {}) =>
    statement({
      kind: 'webauthn.get',
      verifiedOrigin: ORIGIN,
      rpId: RP,
      credentialId,
      clientDataJSON: clientData('webauthn.get', ORIGIN),
      ...over,
    });
  const signWith = (approval: unknown) =>
    call({
      op: 'sign',
      credentialId,
      authenticatorData: authData(RP, 0x01),
      clientDataJSON: clientData('webauthn.get', ORIGIN),
      approval,
    });

  it('a signed statement may carry it', () => {
    expect(signWith(approver.sign(getStatement({ keepSignedIn: { site: RP } }))).ok).toBe(true);
  });

  it('added or changed after signing: the signature no longer matches', () => {
    const plain = approver.sign(getStatement());
    const forged = { ...plain, statement: { ...plain.statement, keepSignedIn: { site: RP } } };
    expect(signWith(forged)).toEqual({ ok: false, error: 'bad_signature' });
    const kept = approver.sign(getStatement({ keepSignedIn: { site: RP } }));
    const moved = {
      ...kept,
      statement: { ...kept.statement, keepSignedIn: { site: 'bank.example' } },
    };
    expect(signWith(moved)).toEqual({ ok: false, error: 'bad_signature' });
  });

  it('a malformed value is a bad statement, even when signed', () => {
    for (const bad of [
      true,
      'example.com',
      { site: '' },
      { site: 'Example.COM' },
      { site: RP, x: 1 },
      { site: 'a b' },
      null,
    ]) {
      expect(keepSignedInOk(bad), JSON.stringify(bad)).toBe(false);
      const s = getStatement({ keepSignedIn: bad as never });
      expect(statementExtrasOk(s)).toBe(false);
      expect(signWith(approver.sign(s))).toEqual({ ok: false, error: 'bad_statement' });
    }
    expect(keepSignedInOk(undefined)).toBe(true);
    expect(keepSignedInOk({ site: 'rp.localhost' })).toBe(true);
  });
});
