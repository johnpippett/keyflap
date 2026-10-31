import { randomUUID } from 'node:crypto';
import type { ApprovalRequest, ApproverKey } from '@aab/approver';
import { sha256B64url } from '@aab/signer/approval';

const RP = 'example.com';
const ORIGIN = 'https://example.com';

export function createCredentialAs(key: ApproverKey) {
  const clientDataJSON = Buffer.from(
    JSON.stringify({
      type: 'webauthn.create',
      challenge: 'Y2hhbGxlbmdl',
      origin: ORIGIN,
      crossOrigin: false,
    }),
  ).toString('base64url');
  const request: ApprovalRequest = {
    display: {
      intentText: 'register a passkey',
      intentAt: Date.now(),
      verifiedOrigin: ORIGIN,
      agentName: 'agent',
      credentialType: 'passkey',
      action: 'register',
    },
    policy: { tier: 'ask' },
    binding: {
      requestId: randomUUID(),
      kind: 'webauthn.create',
      rpId: RP,
      credentialId: null,
      intentHash: 'aW50ZW50',
      clientDataHash: sha256B64url(Buffer.from(clientDataJSON, 'base64url')),
    },
  };
  return {
    rpId: RP,
    userHandle: 'dXNlcg',
    clientDataJSON,
    approval: key.approve(request, { userVerified: false }),
  };
}
