import { createCipheriv, randomBytes, scryptSync } from 'node:crypto';
import { chmodSync, existsSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { KeyStore, SCRYPT } from '../src/keystore.ts';
import { testNativePhone, testPhone, tmpDir } from './helpers.ts';

function writeStore(
  path: string,
  passphrase: string,
  kdf: { N: number; r: number; p: number },
  contents: unknown = { v: 1, credentials: {} },
  extra: Record<string, unknown> = {},
) {
  const salt = randomBytes(16);
  const key = scryptSync(passphrase, salt, 32, { ...kdf, maxmem: 128 * kdf.N * kdf.r * 2 });
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', key, iv);
  c.setAAD(Buffer.from('aab-keystore-v1'));
  const ct = Buffer.concat([c.update(JSON.stringify(contents)), c.final()]);
  writeFileSync(
    path,
    JSON.stringify({
      v: 1,
      kdf: { name: 'scrypt', salt: salt.toString('base64'), ...kdf },
      iv: iv.toString('base64'),
      tag: c.getAuthTag().toString('base64'),
      ciphertext: ct.toString('base64'),
      ...extra,
    }),
  );
}

const header = (path: string) => JSON.parse(readFileSync(path, 'utf8'));

describe('key store', () => {
  it('encrypts keys at rest and reopens with the right passphrase only', () => {
    const path = join(tmpDir(), 'keys');
    const store = KeyStore.open(path, 'correct');
    const { credentialId } = store.createP256('example.com', 'dXNlcg');
    const pkcs8 = store.get(credentialId)?.privateKey as string;

    const onDisk = readFileSync(path, 'utf8');
    expect(onDisk).not.toContain(pkcs8);
    expect(onDisk).not.toContain('example.com');
    expect(onDisk).not.toContain(credentialId);

    expect(KeyStore.open(path, 'correct').get(credentialId)?.rpId).toBe('example.com');
    expect(() => KeyStore.open(path, 'wrong')).toThrow();
  });

  it('is written 0600 and leaves no temporary file', () => {
    const path = join(tmpDir(), 'keys');
    KeyStore.open(path, 'pw').createP256('example.com', 'dXNlcg');
    expect(statSync(path).mode & 0o777).toBe(0o600);
    expect(readdirSync(dirname(path))).toEqual(['keys']);
  });

  it('refuses a tampered file', () => {
    const path = join(tmpDir(), 'keys');
    KeyStore.open(path, 'pw').createP256('example.com', 'dXNlcg');
    const f = header(path);
    const ct = Buffer.from(f.ciphertext, 'base64');
    ct[0] = (ct[0] ?? 0) ^ 1;
    writeFileSync(path, JSON.stringify({ ...f, ciphertext: ct.toString('base64') }));
    expect(() => KeyStore.open(path, 'pw')).toThrow();
  });
});

describe('key store: scrypt parameters (L6)', () => {
  it('a new store records the current parameters and round-trips through writes', () => {
    const path = join(tmpDir(), 'keys');
    const s = KeyStore.open(path, 'pw');
    expect(s.kdfParams).toEqual(SCRYPT);
    s.createP256('example.com', 'dXNlcg');
    expect(header(path).kdf).toMatchObject({ name: 'scrypt', ...SCRYPT });
    expect(() => KeyStore.open(path, 'pw')).not.toThrow();
  });

  it('a store with other parameters still opens after a write (no bricking)', () => {
    const path = join(tmpDir(), 'keys.enc.json');
    writeStore(path, 'pw', { N: 1 << 14, r: 8, p: 1 });
    const { credentialId } = KeyStore.open(path, 'pw').createP256('example.com', 'dXNlcg');
    expect(KeyStore.open(path, 'pw').get(credentialId)?.rpId).toBe('example.com');
  });

  it('migrates an old-parameter store to the current ones, keeping every entry', () => {
    const path = join(tmpDir(), 'keys');
    const contents = {
      v: 1,
      credentials: {
        c1: { rpId: 'example.com', userHandle: 'dXNlcg', privateKey: 'AAAA', createdAt: 1 },
      },
      items: { pw_1: { domain: 'example.com', password: 'hunter2hunter2', createdAt: 2 } },
      phoneLatched: true,
    };
    writeStore(path, 'pw', { N: 1 << 12, r: 8, p: 1 }, contents);
    const oldSalt = header(path).kdf.salt;
    const s = KeyStore.open(path, 'pw');
    expect(s.kdfParams).toEqual(SCRYPT);
    const h = header(path);
    expect(h.kdf).toMatchObject({ name: 'scrypt', ...SCRYPT });
    expect(h.kdf.salt).not.toBe(oldSalt);
    expect(statSync(path).mode & 0o777).toBe(0o600);
    expect(readdirSync(dirname(path))).toEqual(['keys']);
    const again = KeyStore.open(path, 'pw');
    expect(again.get('c1')?.rpId).toBe('example.com');
    expect(again.item('pw_1')?.password).toBe('hunter2hunter2');
    expect(again.phoneLatched).toBe(true);
    expect(() => KeyStore.open(path, 'wrong')).toThrow();
  });

  it('a migration that cannot be written leaves the old file and parameters in use', () => {
    const dir = tmpDir();
    const path = join(dir, 'keys');
    const old = { N: 1 << 12, r: 8, p: 1 };
    writeStore(path, 'pw', old);
    const before = readFileSync(path, 'utf8');
    chmodSync(dir, 0o500);
    try {
      const s = KeyStore.open(path, 'pw');
      expect(s.kdfParams).toEqual(old);
      expect(readFileSync(path, 'utf8')).toBe(before);
    } finally {
      chmodSync(dir, 0o700);
    }
    expect(existsSync(`${path}.migrate`)).toBe(false);
    const s = KeyStore.open(path, 'pw');
    expect(s.kdfParams).toEqual(SCRYPT);
    s.createP256('example.com', 'dXNlcg');
    expect(() => KeyStore.open(path, 'pw')).not.toThrow();
  });

  it('refuses unsupported or out-of-bounds parameters before deriving a key', () => {
    const cases: [string, Record<string, unknown>][] = [
      ['another KDF', { name: 'argon2id' }],
      ['N not a power of two', { N: 3 << 12 }],
      ['N too small', { N: 1 << 8 }],
      ['N too large (memory)', { N: 1 << 30 }],
      ['r too large', { r: 1000 }],
      ['p zero', { p: 0 }],
      ['p fractional', { p: 1.5 }],
      ['N a string', { N: '32768' }],
      ['memory over 256 MiB', { N: 1 << 18, r: 8 }],
      ['short salt', { salt: Buffer.alloc(4).toString('base64') }],
    ];
    for (const [name, kdf] of cases) {
      const path = join(tmpDir(), 'keys');
      writeStore(path, 'pw', { N: 1 << 12, r: 8, p: 1 });
      const f = header(path);
      writeFileSync(path, JSON.stringify({ ...f, kdf: { ...f.kdf, ...kdf } }));
      const start = Date.now();
      expect(() => KeyStore.open(path, 'pw'), name).toThrow(/malformed or uses unsupported/);
      expect(Date.now() - start, name).toBeLessThan(1000);
    }
    const path = join(tmpDir(), 'keys');
    writeStore(path, 'pw', { N: 1 << 12, r: 8, p: 1 });
    const f = header(path);
    for (const bad of [{ ...f, v: 2 }, { ...f, iv: 'AAAA' }, { ...f, tag: 'AAAA' }, null, []]) {
      writeFileSync(path, JSON.stringify(bad));
      expect(() => KeyStore.open(path, 'pw')).toThrow();
    }
  });

  it('persists an address trip; removing every approver keeps the phone latch; clearing the trip reopens first use only when no approver is left', () => {
    const path = join(tmpDir(), 'keys');
    const store = KeyStore.open(path, 'pw');
    store.addApprover({ ...testPhone().key, signCount: 0, createdAt: 1 });
    const native = testNativePhone();
    store.addNativeApprover({ keyId: native.keyId, ...native.key, createdAt: 1 });
    expect(store.addressTrip).toBeUndefined();
    store.setAddressTrip({ at: 5, seen: 'elsewhere' });
    expect(store.removeAllApprovers()).toBe(2);
    expect(store.removeAllApprovers()).toBe(0);

    const again = KeyStore.open(path, 'pw');
    expect(again.addressTrip).toEqual({ at: 5, seen: 'elsewhere' });
    expect(again.approverCount).toBe(0);
    expect(again.phoneLatched).toBe(true);
    again.clearAddressTrip();
    again.clearAddressTrip();
    expect(again.addressTrip).toBeUndefined();
    expect(again.phoneLatched).toBe(false);

    const paired = KeyStore.open(join(tmpDir(), 'keys'), 'pw');
    paired.addApprover({ ...testPhone().key, signCount: 0, createdAt: 1 });
    paired.setAddressTrip({ at: 6, seen: 'x' });
    paired.clearAddressTrip();
    expect(paired.phoneLatched).toBe(true);
    expect(paired.approverCount).toBe(1);
  });
});
