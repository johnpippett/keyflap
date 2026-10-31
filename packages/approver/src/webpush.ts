import {
  createCipheriv,
  createECDH,
  createPrivateKey,
  generateKeyPairSync,
  hkdfSync,
  type KeyObject,
  randomBytes,
  sign,
} from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';

export interface PushSubscription {
  endpoint: string;
  keys: { p256dh: string; auth: string };
}

export class VapidKey {
  readonly publicKey: string;
  private readonly privateKey: KeyObject;

  private constructor(privateKey: KeyObject) {
    this.privateKey = privateKey;
    const jwk = privateKey.export({ format: 'jwk' });
    this.publicKey = Buffer.concat([
      Buffer.of(4),
      Buffer.from(jwk.x as string, 'base64url'),
      Buffer.from(jwk.y as string, 'base64url'),
    ]).toString('base64url');
  }

  static generate(): VapidKey {
    return new VapidKey(generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey);
  }

  static loadOrCreate(path: string): VapidKey {
    if (existsSync(path)) {
      const { pkcs8 } = JSON.parse(readFileSync(path, 'utf8')) as { pkcs8: string };
      return new VapidKey(
        createPrivateKey({ key: Buffer.from(pkcs8, 'base64'), format: 'der', type: 'pkcs8' }),
      );
    }
    const key = VapidKey.generate();
    const pkcs8 = (key.privateKey.export({ format: 'der', type: 'pkcs8' }) as Buffer).toString(
      'base64',
    );
    writeFileSync(path, JSON.stringify({ pkcs8 }), { mode: 0o600, flag: 'wx' });
    return key;
  }

  authorization(endpoint: string, subject: string, now = Date.now()): string {
    const aud = new URL(endpoint).origin;
    const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const unsigned = `${enc({ typ: 'JWT', alg: 'ES256' })}.${enc({
      aud,
      exp: Math.floor(now / 1000) + 12 * 3600,
      sub: subject,
    })}`;
    const sig = sign('sha256', Buffer.from(unsigned), {
      key: this.privateKey,
      dsaEncoding: 'ieee-p1363',
    });
    return `vapid t=${unsigned}.${sig.toString('base64url')}, k=${this.publicKey}`;
  }
}

const RECORD_SIZE = 4096;

export function encryptPush(
  sub: PushSubscription,
  plaintext: Buffer,
  opts: { ephemeralPrivateKey?: Buffer; salt?: Buffer } = {},
): Buffer {
  const uaPublic = Buffer.from(sub.keys.p256dh, 'base64url');
  const authSecret = Buffer.from(sub.keys.auth, 'base64url');
  if (uaPublic.length !== 65 || uaPublic[0] !== 4) throw new Error('bad p256dh');
  if (authSecret.length !== 16) throw new Error('bad auth secret');
  if (plaintext.length > RECORD_SIZE - 17 - 86) throw new Error('payload too large');

  const ecdh = createECDH('prime256v1');
  if (opts.ephemeralPrivateKey) ecdh.setPrivateKey(opts.ephemeralPrivateKey);
  else ecdh.generateKeys();
  const asPublic = ecdh.getPublicKey();
  const ecdhSecret = ecdh.computeSecret(uaPublic);
  const salt = opts.salt ?? randomBytes(16);

  const keyInfo = Buffer.concat([Buffer.from('WebPush: info\0'), uaPublic, asPublic]);
  const ikm = Buffer.from(hkdfSync('sha256', ecdhSecret, authSecret, keyInfo, 32));
  const cek = Buffer.from(hkdfSync('sha256', ikm, salt, 'Content-Encoding: aes128gcm\0', 16));
  const nonce = Buffer.from(hkdfSync('sha256', ikm, salt, 'Content-Encoding: nonce\0', 12));

  const cipher = createCipheriv('aes-128-gcm', cek, nonce);
  const body = Buffer.concat([
    cipher.update(Buffer.concat([plaintext, Buffer.of(2)])),
    cipher.final(),
    cipher.getAuthTag(),
  ]);
  const header = Buffer.alloc(21);
  salt.copy(header, 0);
  header.writeUInt32BE(RECORD_SIZE, 16);
  header[20] = asPublic.length;
  return Buffer.concat([header, asPublic, body]);
}

export const PUSH_SERVICE_HOSTS: readonly string[] = [
  'fcm.googleapis.com',
  'android.googleapis.com',
  'push.apple.com',
  'push.services.mozilla.com',
  'notify.windows.com',
];

export function validPushEndpoint(endpoint: unknown, allowInsecure = false): endpoint is string {
  if (typeof endpoint !== 'string' || endpoint.length > 2048) return false;
  let url: URL;
  try {
    url = new URL(endpoint);
  } catch {
    return false;
  }
  if (allowInsecure) return url.protocol === 'https:' || url.protocol === 'http:';
  const host = url.hostname;
  return (
    url.protocol === 'https:' &&
    url.username === '' &&
    url.password === '' &&
    host.includes('.') &&
    !/^[0-9.]+$/.test(host) &&
    !host.startsWith('[') &&
    url.port === '' &&
    PUSH_SERVICE_HOSTS.some((h) => host === h || host.endsWith(`.${h}`))
  );
}

export type PushResult = 'sent' | 'gone' | 'failed';

export async function sendPush(
  sub: PushSubscription,
  vapid: VapidKey,
  opts: { subject: string; payload?: Buffer; ttlSeconds?: number; timeoutMs?: number },
): Promise<PushResult> {
  try {
    const body = encryptPush(sub, opts.payload ?? Buffer.from('{"t":"approval"}'));
    const res = await fetch(sub.endpoint, {
      method: 'POST',
      headers: {
        authorization: vapid.authorization(sub.endpoint, opts.subject),
        ttl: String(opts.ttlSeconds ?? 60),
        urgency: 'high',
        'content-encoding': 'aes128gcm',
        'content-type': 'application/octet-stream',
      },
      body: new Uint8Array(body),
      redirect: 'error',
      signal: AbortSignal.timeout(opts.timeoutMs ?? 10_000),
    });
    await res.body?.cancel();
    if (res.status === 404 || res.status === 410) return 'gone';
    return res.ok ? 'sent' : 'failed';
  } catch {
    return 'failed';
  }
}
