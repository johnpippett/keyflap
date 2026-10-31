import { createPrivateKey, type KeyObject, sign } from 'node:crypto';
import { type ClientHttp2Session, connect, constants } from 'node:http2';

export type ApnsEnvironment = 'sandbox' | 'production';

export const APNS_HOSTS: Record<ApnsEnvironment, string> = {
  sandbox: 'https://api.sandbox.push.apple.com',
  production: 'https://api.push.apple.com',
};

export interface ApnsOptions {
  key: string | Buffer;
  keyId: string;
  teamId: string;
  bundleId: string;
  defaultEnvironment?: ApnsEnvironment;
  generic?: boolean;
  hosts?: Partial<Record<ApnsEnvironment, string>>;
  ca?: string | Buffer;
  timeoutMs?: number;
  now?: () => number;
}

export type ApnsResult = 'sent' | 'gone' | 'failed';

export interface ApnsNotification {
  requestId: string;
  kind: 'sign-in' | 'register' | 'pair' | 'handoff';
  verifiedOrigin: string | null;
  ttlSeconds?: number;
}

const TOKEN_REFRESH_MS = 50 * 60_000;
export const APNS_CATEGORY = 'AAB_APPROVAL';
export const APNS_HANDOFF_CATEGORY = 'AAB_HANDOFF';

export function checkApnsOptions(o: Pick<ApnsOptions, 'keyId' | 'teamId' | 'bundleId'>): void {
  if (!/^[A-Z0-9]{10}$/.test(o.keyId)) throw new Error('APNs key id must be 10 characters A-Z0-9');
  if (!/^[A-Z0-9]{10}$/.test(o.teamId))
    throw new Error('APNs team id must be 10 characters A-Z0-9');
  if (!/^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$/.test(o.bundleId)) {
    throw new Error('APNs bundle id must look like com.example.App');
  }
}

export function validDeviceToken(t: unknown): t is string {
  return typeof t === 'string' && /^[0-9a-f]{64,200}$/.test(t) && t.length % 2 === 0;
}

export function apnsPayload(n: ApnsNotification, generic = false): Buffer {
  let host: string | null = null;
  if (n.verifiedOrigin) {
    try {
      host = new URL(n.verifiedOrigin).host;
    } catch {
      host = null;
    }
  }
  if (host !== null && !/^[a-z0-9.:[\]-]+$/.test(host)) host = null;
  const site = generic || host === null ? null : host;
  if (n.kind === 'handoff') {
    return Buffer.from(
      JSON.stringify({
        aps: {
          alert: {
            title: 'Human check',
            body:
              site === null ? 'Open Keyflap: a human check is waiting.' : `Human check on ${site}`,
          },
          sound: 'default',
          category: APNS_HANDOFF_CATEGORY,
          'thread-id': 'aab-handoffs',
          'interruption-level': 'time-sensitive',
        },
        aab: { v: 1, handoff: n.requestId },
      }),
    );
  }
  let body: string;
  if (n.kind === 'pair') body = 'Approve adding a new approver phone?';
  else if (site === null) body = 'Open Keyflap to review the request.';
  else if (n.kind === 'register') body = `Approve a new passkey for ${site}?`;
  else body = `Approve sign-in to ${site}?`;
  return Buffer.from(
    JSON.stringify({
      aps: {
        alert: { title: n.kind === 'pair' ? 'New phone' : 'Sign-in request', body },
        sound: 'default',
        category: APNS_CATEGORY,
        'thread-id': 'aab-approvals',
        'interruption-level': 'time-sensitive',
      },
      aab: { v: 1, rid: n.requestId },
    }),
  );
}

export class ApnsSender {
  private readonly key: KeyObject;
  private readonly opts: ApnsOptions;
  private readonly now: () => number;
  private token: { jwt: string; at: number } | null = null;
  private readonly sessions = new Map<ApnsEnvironment, ClientHttp2Session>();

  constructor(opts: ApnsOptions) {
    checkApnsOptions(opts);
    const key = createPrivateKey(opts.key);
    if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') {
      throw new Error('APNs auth key must be an EC P-256 (.p8) key');
    }
    this.key = key;
    this.opts = opts;
    this.now = opts.now ?? Date.now;
  }

  get defaultEnvironment(): ApnsEnvironment {
    return this.opts.defaultEnvironment ?? 'production';
  }

  providerToken(): string {
    const now = this.now();
    if (this.token && now - this.token.at < TOKEN_REFRESH_MS) return this.token.jwt;
    const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const unsigned = `${enc({ alg: 'ES256', kid: this.opts.keyId })}.${enc({
      iss: this.opts.teamId,
      iat: Math.floor(now / 1000),
    })}`;
    const sig = sign('sha256', Buffer.from(unsigned), { key: this.key, dsaEncoding: 'ieee-p1363' });
    this.token = { jwt: `${unsigned}.${sig.toString('base64url')}`, at: now };
    return this.token.jwt;
  }

  async send(
    deviceToken: string,
    environment: ApnsEnvironment | undefined,
    n: ApnsNotification,
  ): Promise<ApnsResult> {
    if (!validDeviceToken(deviceToken)) return 'gone';
    const env = environment ?? this.defaultEnvironment;
    try {
      const { status, reason } = await this.post(env, deviceToken, n);
      if (status === 200) return 'sent';
      if (status === 410 || reason === 'BadDeviceToken' || reason === 'DeviceTokenNotForTopic') {
        return 'gone';
      }
      if (status === 403 && reason === 'ExpiredProviderToken') this.token = null;
      return 'failed';
    } catch {
      this.dropSession(env);
      return 'failed';
    }
  }

  close(): void {
    for (const env of [...this.sessions.keys()]) this.dropSession(env);
  }

  private session(env: ApnsEnvironment): ClientHttp2Session {
    const existing = this.sessions.get(env);
    if (existing && !existing.closed && !existing.destroyed) return existing;
    const authority = this.opts.hosts?.[env] ?? APNS_HOSTS[env];
    const s = connect(authority, this.opts.ca ? { ca: this.opts.ca } : {});
    s.on('error', () => this.dropSession(env));
    s.on('goaway', () => this.dropSession(env));
    s.unref();
    this.sessions.set(env, s);
    return s;
  }

  private dropSession(env: ApnsEnvironment): void {
    const s = this.sessions.get(env);
    this.sessions.delete(env);
    if (s && !s.destroyed) s.destroy();
  }

  private post(
    env: ApnsEnvironment,
    deviceToken: string,
    n: ApnsNotification,
  ): Promise<{ status: number; reason: string | null }> {
    const body = apnsPayload(n, this.opts.generic === true);
    const ttl = n.ttlSeconds ?? 120;
    return new Promise((resolve, reject) => {
      const session = this.session(env);
      session.ref();
      const req = session.request({
        [constants.HTTP2_HEADER_METHOD]: 'POST',
        [constants.HTTP2_HEADER_PATH]: `/3/device/${deviceToken}`,
        authorization: `bearer ${this.providerToken()}`,
        'apns-topic': this.opts.bundleId,
        'apns-push-type': 'alert',
        'apns-priority': '10',
        'apns-expiration': String(Math.floor(this.now() / 1000) + ttl),
        'apns-collapse-id': n.requestId.slice(0, 64),
        'content-type': 'application/json',
        'content-length': body.length,
      });
      const timer = setTimeout(() => {
        req.close(constants.NGHTTP2_CANCEL);
        reject(new Error('timeout'));
      }, this.opts.timeoutMs ?? 10_000);
      let status = 0;
      const chunks: Buffer[] = [];
      req.on('response', (h) => {
        status = Number(h[constants.HTTP2_HEADER_STATUS] ?? 0);
      });
      req.on('data', (c: Buffer) => {
        if (chunks.reduce((a, b) => a + b.length, 0) < 4096) chunks.push(c);
      });
      req.on('end', () => {
        clearTimeout(timer);
        session.unref();
        let reason: string | null = null;
        try {
          const j = JSON.parse(Buffer.concat(chunks).toString('utf8')) as { reason?: unknown };
          if (typeof j.reason === 'string') reason = j.reason.slice(0, 64);
        } catch {}
        resolve({ status, reason });
      });
      req.on('error', (err) => {
        clearTimeout(timer);
        session.unref();
        reject(err);
      });
      req.end(body);
    });
  }
}
