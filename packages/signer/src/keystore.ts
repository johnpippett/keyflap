import {
  createCipheriv,
  createDecipheriv,
  createPrivateKey,
  generateKeyPairSync,
  type KeyObject,
  randomBytes,
  scryptSync,
} from 'node:crypto';
import { existsSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import type { NativeApproverKey, WebAuthnApproverKey } from './approval.ts';
import type { AddressTrip } from './approver-address.ts';
import type { TotpParams } from './totp.ts';

export interface StoredCredential {
  rpId: string;
  userHandle: string;
  privateKey: string;
  createdAt: number;
}

export interface StoredItem {
  domain: string;
  password: string;
  totp?: TotpParams;
  createdAt: number;
}

interface StoreContents {
  v: 1;
  credentials: Record<string, StoredCredential>;
  items?: Record<string, StoredItem>;
  approvers?: Record<string, WebAuthnApproverKey>;
  nativeApprovers?: Record<string, NativeApproverKey>;
  phoneLatched?: boolean;
  addressTrip?: AddressTrip;
  stateKeys?: { browser?: string };
}

interface StoreFile {
  v: 1;
  kdf: { name: 'scrypt'; salt: string; N: number; r: number; p: number };
  iv: string;
  tag: string;
  ciphertext: string;
}

interface ScryptParams {
  N: number;
  r: number;
  p: number;
}

export const SCRYPT: Readonly<ScryptParams> = { N: 1 << 15, r: 8, p: 1 };
const AAD = Buffer.from('aab-keystore-v1');

export class KeyStore {
  private contents: StoreContents;
  private key: Buffer;
  private salt: Buffer;
  private kdf: ScryptParams;
  private readonly path: string;

  private constructor(
    path: string,
    key: Buffer,
    salt: Buffer,
    kdf: ScryptParams,
    contents: StoreContents,
  ) {
    this.path = path;
    this.key = key;
    this.salt = salt;
    this.kdf = { ...kdf };
    this.contents = contents;
  }

  static open(path: string, passphrase: string): KeyStore {
    if (!passphrase) throw new Error('empty passphrase');
    if (!existsSync(path)) {
      const salt = randomBytes(16);
      const store = new KeyStore(path, derive(passphrase, salt, SCRYPT), salt, SCRYPT, {
        v: 1,
        credentials: {},
      });
      store.flush();
      return store;
    }
    const file = parseStoreFile(readFileSync(path, 'utf8'));
    const salt = Buffer.from(file.kdf.salt, 'base64');
    const kdf = { N: file.kdf.N, r: file.kdf.r, p: file.kdf.p };
    const key = derive(passphrase, salt, kdf);
    const contents = JSON.parse(decrypt(file, key).toString('utf8')) as StoreContents;
    const store = new KeyStore(path, key, salt, kdf, contents);
    if (!sameParams(kdf, SCRYPT)) store.migrate(passphrase);
    return store;
  }

  get kdfParams(): Readonly<ScryptParams> {
    return { ...this.kdf };
  }

  private migrate(passphrase: string): void {
    const salt = randomBytes(16);
    const key = derive(passphrase, salt, SCRYPT);
    const tmp = `${this.path}.migrate`;
    try {
      writeFileSync(tmp, JSON.stringify(this.encrypt(key, salt, SCRYPT)), { mode: 0o600 });
      const back = parseStoreFile(readFileSync(tmp, 'utf8'));
      const check = derive(passphrase, Buffer.from(back.kdf.salt, 'base64'), back.kdf);
      if (decrypt(back, check).toString('utf8') !== JSON.stringify(this.contents)) {
        throw new Error('key store migration check failed');
      }
      renameSync(tmp, this.path);
    } catch {
      try {
        unlinkSync(tmp);
      } catch {}
      return;
    }
    this.key = key;
    this.salt = salt;
    this.kdf = { ...SCRYPT };
  }

  get(credentialId: string): StoredCredential | undefined {
    return Object.hasOwn(this.contents.credentials, credentialId)
      ? this.contents.credentials[credentialId]
      : undefined;
  }

  privateKeyFor(credentialId: string): KeyObject | undefined {
    const c = this.get(credentialId);
    if (!c) return undefined;
    return createPrivateKey({
      key: Buffer.from(c.privateKey, 'base64'),
      format: 'der',
      type: 'pkcs8',
    });
  }

  item(itemId: string): StoredItem | undefined {
    const items = this.contents.items ?? {};
    return Object.hasOwn(items, itemId) ? items[itemId] : undefined;
  }

  addItem(item: Omit<StoredItem, 'createdAt'>): string {
    const itemId = `pw_${randomBytes(16).toString('base64url')}`;
    this.contents.items ??= {};
    this.contents.items[itemId] = { ...item, createdAt: Date.now() };
    this.flush();
    return itemId;
  }

  deleteItem(itemId: string): boolean {
    if (!this.item(itemId)) return false;
    delete (this.contents.items as Record<string, StoredItem>)[itemId];
    this.flush();
    return true;
  }

  approver(credentialId: string): WebAuthnApproverKey | undefined {
    const a = this.contents.approvers ?? {};
    return Object.hasOwn(a, credentialId) ? a[credentialId] : undefined;
  }

  approvers(): WebAuthnApproverKey[] {
    return Object.values(this.contents.approvers ?? {});
  }

  get phoneLatched(): boolean {
    return this.contents.phoneLatched === true;
  }

  addApprover(key: WebAuthnApproverKey): void {
    this.contents.phoneLatched = true;
    this.contents.approvers ??= {};
    this.contents.approvers[key.credentialId] = { ...key };
    this.flush();
  }

  nativeApprover(keyId: string): NativeApproverKey | undefined {
    const a = this.contents.nativeApprovers ?? {};
    return Object.hasOwn(a, keyId) ? a[keyId] : undefined;
  }

  nativeApprovers(): NativeApproverKey[] {
    return Object.values(this.contents.nativeApprovers ?? {});
  }

  get approverCount(): number {
    return this.approvers().length + this.nativeApprovers().length;
  }

  addNativeApprover(key: NativeApproverKey): void {
    this.contents.phoneLatched = true;
    this.contents.nativeApprovers ??= {};
    this.contents.nativeApprovers[key.keyId] = { ...key };
    this.flush();
  }

  removeApprover(id: string, unlatch = false): boolean {
    if (this.approver(id)) {
      delete (this.contents.approvers as Record<string, WebAuthnApproverKey>)[id];
    } else if (this.nativeApprover(id)) {
      delete (this.contents.nativeApprovers as Record<string, NativeApproverKey>)[id];
    } else {
      return false;
    }
    if (unlatch && this.approverCount === 0) this.contents.phoneLatched = false;
    this.flush();
    return true;
  }

  removeAllApprovers(): number {
    const n = this.approverCount;
    if (n === 0) return 0;
    delete this.contents.approvers;
    delete this.contents.nativeApprovers;
    this.flush();
    return n;
  }

  get addressTrip(): AddressTrip | undefined {
    const t = this.contents.addressTrip;
    return t ? { ...t } : undefined;
  }

  setAddressTrip(trip: AddressTrip): void {
    this.contents.addressTrip = { at: trip.at, seen: trip.seen };
    this.flush();
  }

  clearAddressTrip(): void {
    if (this.contents.addressTrip === undefined) return;
    delete this.contents.addressTrip;
    if (this.approverCount === 0) this.contents.phoneLatched = false;
    this.flush();
  }

  setApproverSignCount(credentialId: string, signCount: number): void {
    const a = this.approver(credentialId);
    if (!a || signCount <= a.signCount) return;
    a.signCount = signCount;
    this.flush();
  }

  browserStateKey(): Buffer {
    const existing = this.contents.stateKeys?.browser;
    if (typeof existing === 'string') {
      const k = Buffer.from(existing, 'base64url');
      if (k.length === 32) return k;
      throw new Error('stored browser state key is malformed');
    }
    const key = randomBytes(32);
    this.contents.stateKeys = {
      ...(this.contents.stateKeys ?? {}),
      browser: key.toString('base64url'),
    };
    this.flush();
    return key;
  }

  createP256(rpId: string, userHandle: string): { credentialId: string; x: string; y: string } {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const credentialId = randomBytes(32).toString('base64url');
    const jwk = publicKey.export({ format: 'jwk' });
    if (!jwk.x || !jwk.y) throw new Error('key export failed');
    this.contents.credentials[credentialId] = {
      rpId,
      userHandle,
      privateKey: (privateKey.export({ format: 'der', type: 'pkcs8' }) as Buffer).toString(
        'base64',
      ),
      createdAt: Date.now(),
    };
    this.flush();
    return { credentialId, x: jwk.x, y: jwk.y };
  }

  private encrypt(key: Buffer, salt: Buffer, kdf: ScryptParams): StoreFile {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(AAD);
    const ciphertext = Buffer.concat([
      cipher.update(Buffer.from(JSON.stringify(this.contents), 'utf8')),
      cipher.final(),
    ]);
    return {
      v: 1,
      kdf: { name: 'scrypt', salt: salt.toString('base64'), N: kdf.N, r: kdf.r, p: kdf.p },
      iv: iv.toString('base64'),
      tag: cipher.getAuthTag().toString('base64'),
      ciphertext: ciphertext.toString('base64'),
    };
  }

  private flush(): void {
    const file = this.encrypt(this.key, this.salt, this.kdf);
    const tmp = `${this.path}.tmp`;
    writeFileSync(tmp, JSON.stringify(file), { mode: 0o600 });
    renameSync(tmp, this.path);
  }
}

const B64 = /^[A-Za-z0-9+/]*={0,2}$/;

function b64Bytes(v: unknown, min: number, max: number): boolean {
  if (typeof v !== 'string' || !B64.test(v)) return false;
  const n = Buffer.from(v, 'base64').length;
  return n >= min && n <= max;
}

function parseStoreFile(text: string): StoreFile {
  const f = JSON.parse(text) as Partial<StoreFile> | null;
  const k = f?.kdf;
  const int = (v: unknown, lo: number, hi: number) =>
    typeof v === 'number' && Number.isInteger(v) && v >= lo && v <= hi;
  if (
    !f ||
    typeof f !== 'object' ||
    f.v !== 1 ||
    !k ||
    typeof k !== 'object' ||
    k.name !== 'scrypt' ||
    !int(k.N, 1 << 10, 1 << 20) ||
    (k.N & (k.N - 1)) !== 0 ||
    !int(k.r, 1, 32) ||
    !int(k.p, 1, 16) ||
    scryptMaxmem(k) > 256 * 1024 * 1024 ||
    !b64Bytes(k.salt, 16, 64) ||
    !b64Bytes(f.iv, 12, 12) ||
    !b64Bytes(f.tag, 16, 16) ||
    !b64Bytes(f.ciphertext, 0, 64 * 1024 * 1024)
  ) {
    throw new Error('key store file is malformed or uses unsupported parameters');
  }
  return f as StoreFile;
}

function decrypt(file: StoreFile, key: Buffer): Buffer {
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(file.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(file.tag, 'base64'));
  decipher.setAAD(AAD);
  return Buffer.concat([decipher.update(Buffer.from(file.ciphertext, 'base64')), decipher.final()]);
}

function sameParams(a: ScryptParams, b: ScryptParams): boolean {
  return a.N === b.N && a.r === b.r && a.p === b.p;
}

function scryptMaxmem(params: ScryptParams): number {
  return 128 * params.N * params.r * 2;
}

function derive(passphrase: string, salt: Buffer, params: ScryptParams): Buffer {
  return scryptSync(passphrase, salt, 32, {
    N: params.N,
    r: params.r,
    p: params.p,
    maxmem: scryptMaxmem(params),
  });
}
