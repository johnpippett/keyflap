import { randomUUID } from 'node:crypto';
import { type ApprovalRequest, ApproverKey, ScriptedApprover } from '@aab/approver';
import { sha256B64url } from '@aab/signer/approval';
import { SignerDenied } from '@aab/signer/client';
import { afterEach, describe, expect, it } from 'vitest';
import { type Daemon, startDaemon } from '../src/daemon.ts';
import { tmpDir } from './harness.ts';

const EXTRA_HIGH_RISK = 'bank.example.net';
const ORDINARY = 'shop.example.net';

function registerPasskeyAt(key: ApproverKey, host: string) {
  const origin = `https://${host}`;
  const clientDataJSON = Buffer.from(
    JSON.stringify({
      type: 'webauthn.create',
      challenge: 'Y2hhbGxlbmdl',
      origin,
      crossOrigin: false,
    }),
  ).toString('base64url');
  const request: ApprovalRequest = {
    display: {
      intentText: 'register a passkey',
      intentAt: Date.now(),
      verifiedOrigin: origin,
      agentName: 'agent',
      credentialType: 'passkey',
      action: 'register',
    },
    policy: { tier: 'ask' },
    binding: {
      requestId: randomUUID(),
      kind: 'webauthn.create',
      rpId: host,
      credentialId: null,
      intentHash: 'aW50ZW50',
      clientDataHash: sha256B64url(Buffer.from(clientDataJSON, 'base64url')),
    },
  };
  return {
    rpId: host,
    userHandle: 'dXNlcg',
    clientDataJSON,
    approval: key.approve(request, { userVerified: false }),
  };
}

describe('invariant 6: the signer knows the same extra high-risk sites as the broker', () => {
  let daemon: Daemon | undefined;
  afterEach(async () => {
    await daemon?.stop();
    daemon = undefined;
  });

  it('a site that is high-risk only through DaemonOptions.highRiskDomains needs a phone approval at the signer', async () => {
    const approverKey = ApproverKey.generate('test-approver');
    daemon = await startDaemon({
      dataDir: tmpDir(),
      passphrase: 'test-passphrase',
      approver: new ScriptedApprover(approverKey),
      trustedApproverKeys: approverKey.trustEntry(),
      highRiskDomains: [EXTRA_HIGH_RISK],
    });
    const { client } = daemon.signer;

    expect(
      (await client.createCredential(registerPasskeyAt(approverKey, ORDINARY))).credentialId,
    ).toEqual(expect.any(String));
    await expect(
      client.createCredential(registerPasskeyAt(approverKey, EXTRA_HIGH_RISK)),
    ).rejects.toThrow(new SignerDenied('user_verification_required'));
  });
});
