import {
  createHash,
  generateKeyPairSync,
  type KeyObject,
  randomBytes,
  randomUUID,
  sign,
} from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  type ApprovalStatement,
  approvalChallenge,
  approvalSigningBytes,
  type NativeApproval,
  nativeApprovalSigningBytes,
  nativeApproverDescriptor,
  nativeKeyId,
  nativePairingProofBytes,
  type SignedApproval,
  sha256B64url,
  type WebAuthnApproval,
} from '../src/approval.ts';

export function tmpDir(): string {
  return mkdtempSync(join(tmpdir(), 'keyflap-signer-'));
}

export function testApprover(keyId = 'test-approver') {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const x = publicKey.export({ format: 'jwk' }).x as string;
  return {
    keyId,
    trusted: { [keyId]: x },
    sign(statement: ApprovalStatement): SignedApproval {
      return {
        statement,
        approverKeyId: keyId,
        signature: sign(null, approvalSigningBytes(statement), privateKey).toString('base64url'),
      };
    },
  };
}

export function clientData(
  type: string,
  origin: string,
  extra: Record<string, unknown> = {},
): string {
  return Buffer.from(
    JSON.stringify({
      type,
      challenge: 'Y2hhbGxlbmdlLWNoYWxsZW5nZQ',
      origin,
      crossOrigin: false,
      ...extra,
    }),
  ).toString('base64url');
}

export function authData(rpId: string, flags = 0x01): string {
  const hash = createHash('sha256').update(rpId).digest();
  return Buffer.concat([hash, Buffer.of(flags), Buffer.alloc(4)]).toString('base64url');
}

export function statement(
  overrides: Partial<ApprovalStatement> & { clientDataJSON: string },
): ApprovalStatement {
  const now = Date.now();
  const { clientDataJSON, ...rest } = overrides;
  return {
    v: 1,
    requestId: randomUUID(),
    kind: 'webauthn.get',
    verifiedOrigin: 'https://example.com',
    rpId: 'example.com',
    credentialId: null,
    intentHash: 'aW50ZW50',
    clientDataHash: sha256B64url(Buffer.from(clientDataJSON, 'base64url')),
    userVerified: false,
    issuedAt: now,
    expiresAt: now + 60_000,
    ...rest,
  };
}

export function testPhone(opts: { rpId?: string; origin?: string; credentialId?: string } = {}) {
  const rpId = opts.rpId ?? 'approver.example.net';
  const origin = opts.origin ?? `https://${rpId}`;
  const credentialId = opts.credentialId ?? randomBytes(32).toString('base64url');
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' });
  const key = { credentialId, x: jwk.x as string, y: jwk.y as string, rpId, origin };
  let counter = 0;
  return {
    key,
    approve(
      statement: ApprovalStatement,
      o: {
        flags?: number;
        signCount?: number;
        challenge?: string;
        origin?: string;
        type?: string;
        rpId?: string;
        clientData?: Record<string, unknown>;
        signWith?: KeyObject;
      } = {},
    ): WebAuthnApproval {
      const cd = Buffer.from(
        JSON.stringify({
          type: o.type ?? 'webauthn.get',
          challenge: o.challenge ?? approvalChallenge(statement),
          origin: o.origin ?? origin,
          crossOrigin: false,
          ...o.clientData,
        }),
      );
      const count = Buffer.alloc(4);
      count.writeUInt32BE(o.signCount ?? counter);
      const ad = Buffer.concat([
        createHash('sha256')
          .update(o.rpId ?? rpId)
          .digest(),
        Buffer.of(o.flags ?? 0x05),
        count,
      ]);
      const sig = sign('sha256', Buffer.concat([ad, createHash('sha256').update(cd).digest()]), {
        key: o.signWith ?? privateKey,
        dsaEncoding: 'der',
      });
      return {
        statement,
        approverKeyId: credentialId,
        webauthn: {
          authenticatorData: ad.toString('base64url'),
          clientDataJSON: cd.toString('base64url'),
          signature: sig.toString('base64url'),
        },
      };
    },
    setCounter(n: number) {
      counter = n;
    },
  };
}

export function testNativePhone(opts: { origin?: string } = {}) {
  const origin = opts.origin ?? 'https://approver.example.net';
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' });
  const x = jwk.x as string;
  const y = jwk.y as string;
  const keyId = nativeKeyId(x, y);
  const key = { x, y, origin, userVerification: 'biometry' as const };
  const descriptor = nativeApproverDescriptor({ keyId, ...key });
  return {
    key,
    keyId,
    descriptor,
    privateKey,
    proof(signWith: KeyObject = privateKey): string {
      return sign('sha256', nativePairingProofBytes(descriptor), {
        key: signWith,
        dsaEncoding: 'der',
      }).toString('base64url');
    },
    approve(
      statement: ApprovalStatement,
      o: { signWith?: KeyObject; bytes?: Buffer; encoding?: 'der' | 'ieee-p1363' } = {},
    ): NativeApproval {
      const sig = sign('sha256', o.bytes ?? nativeApprovalSigningBytes(statement), {
        key: o.signWith ?? privateKey,
        dsaEncoding: o.encoding ?? 'der',
      });
      return { statement, approverKeyId: keyId, native: { signature: sig.toString('base64url') } };
    },
  };
}
