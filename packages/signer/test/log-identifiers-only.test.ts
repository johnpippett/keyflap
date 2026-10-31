import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { approvalChallenge, type SignedApproval } from '../src/approval.ts';
import { KeyStore } from '../src/keystore.ts';
import { SignerHandler } from '../src/server.ts';
import { authData, clientData, statement, testApprover, testPhone, tmpDir } from './helpers.ts';

const ORIGIN = 'https://example.com';
const RP = 'example.com';
const CLIENT_DATA_CHALLENGE = 'Y2hhbGxlbmdlLWNoYWxsZW5nZQ';

type Res = { ok: true; result: Record<string, unknown> } | { ok: false; error: string };

function secretsOf(store: KeyStore, credentialId: string): string[] {
  const key = store.privateKeyFor(credentialId);
  if (!key) throw new Error('no private key');
  const der = key.export({ format: 'der', type: 'pkcs8' });
  return [der.toString('base64'), der.toString('base64url'), key.export({ format: 'jwk' }).d ?? ''];
}

describe('the signer log carries identifiers only', () => {
  it('never holds a signature, an approval signature, client data, a challenge or private key material', () => {
    const lines: string[] = [];
    const log = (event: string, fields?: Record<string, unknown>) =>
      lines.push(JSON.stringify({ event, fields }));
    const secrets: string[] = [CLIENT_DATA_CHALLENGE];
    const open = (approvers: ReturnType<typeof testApprover>[]) => {
      const store = KeyStore.open(join(tmpDir(), 'keys'), 'pw');
      const handler = new SignerHandler({
        store,
        trustedApproverKeys: Object.assign({}, ...approvers.map((a) => a.trusted)),
        log,
      });
      return { store, call: (req: unknown) => handler.handle(req as never) as Res };
    };

    const run = (
      s: ReturnType<typeof open>,
      approve: (
        kind: 'webauthn.create' | 'webauthn.get',
        credentialId?: string,
      ) => {
        approval: SignedApproval;
        clientDataJSON: string;
      },
    ) => {
      const create = approve('webauthn.create');
      const created = s.call({
        op: 'create_credential',
        rpId: RP,
        userHandle: 'dXNlcg',
        clientDataJSON: create.clientDataJSON,
        approval: create.approval,
      });
      if (!created.ok) throw new Error(created.error);
      const credentialId = created.result.credentialId as string;
      secrets.push(...secretsOf(s.store, credentialId), create.clientDataJSON);

      const get = approve('webauthn.get', credentialId);
      const signed = s.call({
        op: 'sign',
        credentialId,
        authenticatorData: authData(RP),
        clientDataJSON: get.clientDataJSON,
        approval: get.approval,
      });
      if (!signed.ok) throw new Error(signed.error);
      secrets.push(signed.result.signature as string, get.clientDataJSON);

      const again = approve('webauthn.get', credentialId);
      secrets.push(again.clientDataJSON);
      const refused = s.call({
        op: 'sign',
        credentialId,
        authenticatorData: authData(RP),
        clientDataJSON: again.clientDataJSON,
        approval: {
          ...again.approval,
          statement: { ...again.approval.statement, rpId: 'evil.com' },
        },
      });
      expect(refused.ok).toBe(false);
    };

    const terminal = testApprover('terminal');
    run(open([terminal]), (kind, credentialId) => {
      const cd = clientData(kind, ORIGIN);
      const approval = terminal.sign(
        statement({ kind, clientDataJSON: cd, ...(credentialId ? { credentialId } : {}) }),
      );
      secrets.push(approval.signature as string);
      return { approval, clientDataJSON: cd };
    });

    const phone = testPhone();
    const withPhone = open([]);
    expect(withPhone.call({ op: 'add_approver', key: phone.key }).ok).toBe(true);
    run(withPhone, (kind, credentialId) => {
      const cd = clientData(kind, ORIGIN);
      const s = statement({
        kind,
        clientDataJSON: cd,
        userVerified: true,
        ...(credentialId ? { credentialId } : {}),
      });
      const approval = phone.approve(s);
      secrets.push(approval.webauthn?.signature as string, approvalChallenge(s));
      return { approval, clientDataJSON: cd };
    });

    const events = lines.map((l) => (JSON.parse(l) as { event: string }).event);
    expect(events.filter((e) => e === 'created')).toHaveLength(2);
    expect(events.filter((e) => e === 'signed')).toHaveLength(2);
    expect(events.filter((e) => e === 'denied')).toHaveLength(2);
    const all = lines.join('\n');
    expect(secrets.length).toBeGreaterThanOrEqual(16);
    for (const secret of secrets) {
      expect(secret.length).toBeGreaterThan(20);
      expect(all).not.toContain(secret);
    }
  });
});
