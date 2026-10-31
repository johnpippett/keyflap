import {
  createPrivateKey,
  generateKeyPairSync,
  type KeyObject,
  randomBytes,
  sign,
} from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { approvalSigningBytes, type Ed25519Approval } from '@aab/signer/approval';
import { buildStatement } from './statement.ts';
import type { ApprovalRequest } from './types.ts';

export { APPROVAL_TTL_MS } from './statement.ts';

export class ApproverKey {
  readonly keyId: string;
  readonly publicKey: string;
  private readonly privateKey: KeyObject;

  private constructor(keyId: string, privateKey: KeyObject) {
    this.keyId = keyId;
    this.privateKey = privateKey;
    const jwk = privateKey.export({ format: 'jwk' });
    if (!jwk.x) throw new Error('bad approver key');
    this.publicKey = jwk.x;
  }

  static generate(keyId = `approver-${randomBytes(4).toString('hex')}`): ApproverKey {
    return new ApproverKey(keyId, generateKeyPairSync('ed25519').privateKey);
  }

  static loadOrCreate(path: string, keyId = 'terminal'): ApproverKey {
    if (existsSync(path)) {
      const { keyId: id, pkcs8 } = JSON.parse(readFileSync(path, 'utf8')) as {
        keyId: string;
        pkcs8: string;
      };
      return new ApproverKey(
        id,
        createPrivateKey({ key: Buffer.from(pkcs8, 'base64'), format: 'der', type: 'pkcs8' }),
      );
    }
    const key = ApproverKey.generate(keyId);
    const pkcs8 = (key.privateKey.export({ format: 'der', type: 'pkcs8' }) as Buffer).toString(
      'base64',
    );
    writeFileSync(path, JSON.stringify({ keyId, pkcs8 }), { mode: 0o600 });
    return key;
  }

  trustEntry(): Record<string, string> {
    return { [this.keyId]: this.publicKey };
  }

  approve(
    req: ApprovalRequest,
    opts: { userVerified: boolean; now?: number; ttlMs?: number; keepSignedIn?: boolean },
  ): Ed25519Approval {
    const statement = buildStatement(req, opts);
    return {
      statement,
      approverKeyId: this.keyId,
      signature: sign(null, approvalSigningBytes(statement), this.privateKey).toString('base64url'),
    };
  }
}
