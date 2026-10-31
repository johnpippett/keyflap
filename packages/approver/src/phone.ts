import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { chmodSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import {
  createServer as createHttpServer,
  type IncomingMessage,
  type ServerResponse,
} from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import type { AddressInfo } from 'node:net';
import { join } from 'node:path';
import {
  type ApprovalStatement,
  approvalChallenge,
  approverDescriptor,
  type NativeApproval,
  type NativeApproverKey,
  nativeApproverDescriptor,
  nativeKeyId,
  nativePairingProofBytes,
  type SignedApproval,
  sha256B64url,
  verifyNativeApproval,
  verifyNativeSignature,
  verifyWebAuthnAssertion,
  type WebAuthnApproval,
  type WebAuthnApproverKey,
} from '@aab/signer/approval';
import { type AddressState, addressPhase } from '@aab/signer/approver-address';
import { assertUnixSocketPath } from '@aab/signer/platform';
import {
  generateRegistrationOptions,
  type RegistrationResponseJSON,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import { decodeCredentialPublicKey, isoCBOR } from '@simplewebauthn/server/helpers';
import { ADDRESS_REFUSAL, addressRefusal } from './address-sync.ts';
import { type ApnsSender, validDeviceToken } from './apns.ts';
import { type Device, type DeviceKind, DeviceStore } from './devices.ts';
import {
  allowedHostsFor,
  approverOriginUrl,
  isLoopback,
  loadPageFiles,
  STATIC,
  securityHeaders,
} from './page-files.ts';
import { APPROVAL_TTL_MS, buildStatement, requestProblem } from './statement.ts';
import {
  type ApprovalDecision,
  type ApprovalRequest,
  type Approver,
  HANDOFF_KEYS,
  type HandoffClip,
  type HandoffInput,
  type HandoffKey,
  type HandoffPoint,
  type HandoffPort,
  type HandoffSurface,
  type HandoffView,
} from './types.ts';
import { type PushSubscription, sendPush, VapidKey, validPushEndpoint } from './webpush.ts';

export interface ApproverSignerPort {
  listApprovers(): Promise<{ approvers: WebAuthnApproverKey[]; native?: NativeApproverKey[] }>;
  addApprover(req: {
    key: { credentialId: string; x: string; y: string; rpId: string; origin: string };
    approval?: SignedApproval;
  }): Promise<{ added: true }>;
  addNativeApprover?(req: {
    key: { x: string; y: string; origin: string; userVerification: 'biometry' };
    proof: string;
    approval?: SignedApproval;
  }): Promise<{ added: true; keyId: string }>;
  removeApprover?(id: string): Promise<{ removed: boolean }>;
}

export interface PhoneApproverOptions {
  dir: string;
  origin: string;
  listen: { host: string; port: number } | { fd: number } | { path: string };
  apiOnly?: boolean;
  tls?: { cert: string | Buffer; key: string | Buffer };
  signer: ApproverSignerPort;
  pushSubject?: string;
  allowInsecurePushEndpoints?: boolean;
  apns?: ApnsSender;
  timeoutMs?: number;
  pairingTtlMs?: number;
  platformWord?: PlatformWord;
  log?: (line: string) => void;
  onEvent?: (event: string, fields: Record<string, unknown>) => void;
  auditBefore: (event: string, fields: Record<string, unknown>) => void;
  now?: () => number;
}

export type PlatformWord = 'Mac' | 'computer';

export class PairingRefused extends Error {
  readonly state: AddressState;
  constructor(state: AddressState) {
    super(`approver address ${state.kind}`);
    this.state = state;
  }
}

export const HANDOFF_START_DOMAIN = 'aab-handoff-start-v1\n';

export function handoffStartChallenge(id: string, nonce: string): string {
  return createHash('sha256').update(`${HANDOFF_START_DOMAIN}${id}\n${nonce}`).digest('base64url');
}

const HANDOFF_START_TTL_MS = 2 * 60_000;
const MAX_HANDOFF_TEXT = 256;
const MAX_SCROLL = 5_000;
// biome-ignore lint/suspicious/noControlCharactersInRegex: refusing them is the point
const TEXT_CONTROL = /[\u0000-\u001f\u007f-\u009f]/;

type View =
  | { kind: 'credential'; display: ApprovalRequest['display'] }
  | {
      kind: 'pair';
      requestedAt: number;
      check: string;
      newDevice: 'passkey' | 'ios-app';
    };

interface Pending {
  id: string;
  handoff: boolean;
  createdAt: number;
  expiresAt: number;
  view: View;
  makeStatement: (now: number, o?: { keepSignedIn?: boolean }) => ApprovalStatement;
  statement: ApprovalStatement | null;
  descriptor?: string;
  finish: (
    d:
      | { approved: true; approval: WebAuthnApproval | NativeApproval; deviceId?: string }
      | { approved: false; reason: string },
  ) => void;
}

interface Pairing {
  codeHash: Buffer;
  expiresAt: number;
  challenge: string | null;
  state: 'open' | 'waiting' | 'paired' | 'failed';
  token: string | null;
  kind: DeviceKind | null;
}

const COOKIE = '__Host-aab_device';
const MAX_BODY = 16 * 1024;

class HttpError extends Error {
  readonly status: number;
  readonly extra: Record<string, unknown>;
  constructor(status: number, message: string, extra: Record<string, unknown> = {}) {
    super(message);
    this.status = status;
    this.extra = extra;
  }
}

function handoffId(v: unknown): string {
  if (typeof v !== 'string' || !/^[A-Za-z0-9-]{1,64}$/.test(v)) throw new HttpError(400, 'bad_id');
  return v;
}

const isUnit = (v: unknown): v is number =>
  typeof v === 'number' && Number.isFinite(v) && v >= 0 && v <= 1;

function point(v: unknown): HandoffPoint | null {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) return null;
  const o = v as Record<string, unknown>;
  if (Object.keys(o).length !== 2 || !isUnit(o.x) || !isUnit(o.y)) return null;
  return { x: o.x, y: o.y };
}

export function parseHandoffInput(v: unknown): HandoffInput | null {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) return null;
  const o = v as Record<string, unknown>;
  const keys = Object.keys(o).sort().join(',');
  switch (o.type) {
    case 'click':
      return keys === 'type,x,y' && isUnit(o.x) && isUnit(o.y)
        ? { type: 'click', x: o.x, y: o.y }
        : null;
    case 'scroll':
      return keys === 'dy,type' &&
        typeof o.dy === 'number' &&
        Number.isInteger(o.dy) &&
        Math.abs(o.dy) <= MAX_SCROLL
        ? { type: 'scroll', dy: o.dy }
        : null;
    case 'drag': {
      const from = point(o.from);
      const to = point(o.to);
      return keys === 'from,to,type' && from && to ? { type: 'drag', from, to } : null;
    }
    case 'key':
      return keys === 'key,type' && (HANDOFF_KEYS as readonly unknown[]).includes(o.key)
        ? { type: 'key', key: o.key as HandoffKey }
        : null;
    case 'text':
      return keys === 'text,type' &&
        typeof o.text === 'string' &&
        o.text.length > 0 &&
        o.text.length <= MAX_HANDOFF_TEXT &&
        !TEXT_CONTROL.test(o.text)
        ? { type: 'text', text: o.text }
        : null;
    default:
      return null;
  }
}

const MIN_CLIP = 0.05;
export function parseHandoffClip(v: string | null): HandoffClip | null {
  if (v === null) return null;
  const bad = () => new HttpError(400, 'bad_clip');
  if (!/^(?:[01](?:\.\d{1,4})?,){3}[01](?:\.\d{1,4})?$/.test(v)) throw bad();
  const [x, y, w, h] = v.split(',').map(Number) as [number, number, number, number];
  const ok =
    [x, y, w, h].every(isUnit) &&
    w >= MIN_CLIP &&
    h >= MIN_CLIP &&
    x + w <= 1 + 1e-9 &&
    y + h <= 1 + 1e-9;
  if (!ok) throw bad();
  return { x, y, w, h };
}

function coseKey(k: WebAuthnApproverKey): Uint8Array<ArrayBuffer> {
  const encoded = isoCBOR.encode(
    new Map<number, number | Uint8Array>([
      [1, 2],
      [3, -7],
      [-1, 1],
      [-2, Buffer.from(k.x, 'base64url')],
      [-3, Buffer.from(k.y, 'base64url')],
    ]),
  );
  return new Uint8Array(encoded);
}

export class PhoneApprover implements Approver, HandoffSurface {
  readonly origin: string;
  readonly rpId: string;
  listenUrl = '';
  private readonly opts: PhoneApproverOptions;
  private readonly devices: DeviceStore;
  private readonly vapid: VapidKey;
  private readonly pending = new Map<string, Pending>();
  private readonly allowedHosts: Set<string>;
  private readonly files: Map<string, Buffer> = new Map();
  private readonly now: () => number;
  private readonly platformWord: PlatformWord;
  private addressState: AddressState = { kind: 'unwatched' };
  private pairing: Pairing | null = null;
  private server: ReturnType<typeof createHttpServer> | null = null;
  private handoffs: HandoffPort | null = null;
  private readonly handoffStarts = new Map<string, { challenge: string; expiresAt: number }>();

  private constructor(opts: PhoneApproverOptions) {
    this.opts = opts;
    this.now = opts.now ?? Date.now;
    this.platformWord = opts.platformWord ?? 'computer';
    const url = approverOriginUrl(opts.origin);
    const l = opts.listen;
    if ('host' in l) {
      if (!opts.tls && !isLoopback(l.host)) {
        throw new Error('without TLS the approver must listen on loopback, behind a TLS proxy');
      }
    } else if (!opts.apiOnly || opts.tls) {
      throw new Error('a socket listener is for the service-mode front only (apiOnly, no TLS)');
    }
    this.origin = opts.origin;
    this.rpId = url.hostname;
    this.allowedHosts = new Set([url.host]);
    mkdirSync(opts.dir, { recursive: true, mode: 0o700 });
    chmodSync(opts.dir, 0o700);
    this.devices = new DeviceStore(join(opts.dir, 'devices.json'));
    this.vapid = VapidKey.loadOrCreate(join(opts.dir, 'vapid.json'));
    if (!opts.apiOnly) this.files = loadPageFiles();
  }

  static async start(opts: PhoneApproverOptions): Promise<PhoneApprover> {
    const a = new PhoneApprover(opts);
    await a.syncDevices();
    await a.listen();
    return a;
  }

  private async listen(): Promise<void> {
    const handler = (req: IncomingMessage, res: ServerResponse) => {
      this.handle(req, res).catch(() => {
        if (!res.headersSent) this.send(res, 500, { error: 'internal_error' });
        else res.destroy();
      });
    };
    const server = this.opts.tls
      ? createHttpsServer({ cert: this.opts.tls.cert, key: this.opts.tls.key }, handler)
      : createHttpServer(handler);
    server.headersTimeout = 10_000;
    server.requestTimeout = 30_000;
    const l = this.opts.listen;
    if ('path' in l) assertUnixSocketPath(l.path, 'approver API socket');
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      if ('fd' in l) server.listen({ fd: l.fd }, () => resolve());
      else if ('path' in l) server.listen(l.path, () => resolve());
      else server.listen(l.port, l.host, () => resolve());
    });
    this.server = server;
    if (!('host' in l)) {
      this.listenUrl = 'path' in l ? `unix:${l.path}` : `fd:${l.fd}`;
      return;
    }
    const addr = server.address() as AddressInfo;
    const host = addr.family === 'IPv6' ? `[${addr.address}]` : addr.address;
    this.listenUrl = `${this.opts.tls ? 'https' : 'http'}://${host}:${addr.port}`;
    for (const h of allowedHostsFor(
      this.origin,
      { host: l.host, port: l.port, tls: this.opts.tls !== undefined },
      addr.port,
    )) {
      this.allowedHosts.add(h);
    }
  }

  async close(): Promise<void> {
    this.cancelAll('approver_closed');
    const s = this.server;
    this.server = null;
    if (s) {
      s.closeAllConnections?.();
      await new Promise<void>((resolve) => s.close(() => resolve()));
    }
  }

  busy(): boolean {
    return this.pending.size > 0 || this.pairing !== null;
  }

  setAddressState(state: AddressState): void {
    this.addressState = state;
  }

  private requireAddressOk(): void {
    const refusal = addressRefusal(this.addressState, this.now());
    if (refusal) throw new HttpError(503, refusal);
  }

  cancelAll(reason: string): void {
    for (const p of [...this.pending.values()]) p.finish({ approved: false, reason });
    this.pending.clear();
    this.handoffStarts.clear();
    this.clearPairing();
  }

  async warnAddressChanged(): Promise<void> {
    const subject = this.opts.pushSubject ?? this.origin;
    const payload = Buffer.from(JSON.stringify({ t: 'address', on: this.platformWord }));
    await Promise.all(
      this.devices.list().map(async (d) => {
        if (!d.push) return;
        const r = await sendPush(d.push, this.vapid, { subject, payload, ttlSeconds: 300 }).catch(
          () => 'failed',
        );
        if (r !== 'sent') this.opts.log?.(`approver: address warning to ${d.id} ${r}`);
      }),
    );
  }

  signOutAll(): void {
    const port = this.handoffs;
    const dropped = new Set(this.devices.list().map((d) => d.id));
    this.devices.retainCredentials(new Set());
    for (const v of port?.list() ?? []) {
      const c = port?.controller(v.id);
      if (c && dropped.has(c)) port?.finish(v.id, c, 'cancelled');
    }
  }

  async request(req: ApprovalRequest, o?: { signal?: AbortSignal }): Promise<ApprovalDecision> {
    const problem = requestProblem(req);
    if (problem) return { approved: false, reason: problem };
    const refusal = addressRefusal(this.addressState, this.now());
    if (refusal) return { approved: false, reason: refusal };
    let count: number;
    try {
      const all = await this.trustedAll();
      count = all.passkeys.length + all.native.length;
    } catch {
      return { approved: false, reason: 'signer_unavailable' };
    }
    if (count === 0) return { approved: false, reason: 'no_approver_paired' };
    const d = await this.enqueue(
      { kind: 'credential', display: { ...req.display } },
      (now, o) =>
        buildStatement(req, {
          userVerified: true,
          now,
          ttlMs: APPROVAL_TTL_MS,
          keepSignedIn: o?.keepSignedIn === true,
        }),
      req.binding.requestId,
      o?.signal,
      { handoff: req.binding.handoff !== undefined },
    );
    return d;
  }

  startPairing(): string {
    if (addressRefusal(this.addressState, this.now())) throw new PairingRefused(this.addressState);
    const code = randomBytes(32).toString('base64url');
    this.pairing = {
      codeHash: Buffer.from(sha256B64url(code)),
      expiresAt: this.now() + (this.opts.pairingTtlMs ?? 10 * 60_000),
      challenge: null,
      state: 'open',
      token: null,
      kind: null,
    };
    const url = `${this.origin}/pair#${code}`;
    writeFileSync(join(this.opts.dir, 'pairing-url'), `${url}\n`, { mode: 0o600 });
    this.opts.onEvent?.('approver.pairing_started', { origin: this.origin });
    return url;
  }

  attachHandoffs(port: HandoffPort): void {
    this.handoffs = port;
  }

  handoffAvailable(): boolean {
    return this.devices.list().some((d) => (d.kind ?? 'web') === 'web');
  }

  notifyHandoff(view: HandoffView): Promise<void> {
    return this.notifyHandoffAll(view).catch(() => {
      this.opts.log?.('approver: handoff push failed');
    });
  }

  private async notifyHandoffAll(view: HandoffView): Promise<void> {
    const subject = this.opts.pushSubject ?? this.origin;
    const host = /^[a-z0-9.:[\]-]{1,260}$/.test(view.host) ? view.host : null;
    const payload = Buffer.from(JSON.stringify(host ? { t: 'handoff', host } : { t: 'handoff' }));
    const ttlSeconds = Math.max(1, Math.min(300, Math.ceil((view.expiresAt - this.now()) / 1000)));
    const apns = this.opts.apns;
    await Promise.all(
      this.devices.list().map(async (d) => {
        if (d.push) {
          const r = await sendPush(d.push, this.vapid, { subject, payload, ttlSeconds });
          if (r === 'gone') this.devices.setPush(d.id, undefined);
          if (r !== 'sent') this.opts.log?.(`approver: push to ${d.id} ${r}`);
        }
        if (d.apns && apns) {
          const r = await apns.send(d.apns.token, d.apns.environment, {
            requestId: view.id,
            kind: 'handoff',
            verifiedOrigin: host ? `https://${host}` : null,
            ttlSeconds,
          });
          if (r === 'gone') this.devices.setApns(d.id, undefined);
          if (r !== 'sent') this.opts.log?.(`approver: APNs to ${d.id} ${r}`);
        }
      }),
    );
  }

  private async trustedKeys(): Promise<WebAuthnApproverKey[]> {
    return (await this.trustedAll()).passkeys;
  }

  private async trustedAll(): Promise<{
    passkeys: WebAuthnApproverKey[];
    native: NativeApproverKey[];
    anywhere: number;
  }> {
    const { approvers, native = [] } = await this.opts.signer.listApprovers();
    return {
      passkeys: approvers.filter((k) => k.rpId === this.rpId && k.origin === this.origin),
      native: native.filter((k) => k.origin === this.origin),
      anywhere: approvers.length + native.length,
    };
  }

  private async syncDevices(): Promise<void> {
    const { passkeys, native } = await this.trustedAll();
    this.devices.retainCredentials(
      new Set([...passkeys.map((k) => k.credentialId), ...native.map((k) => k.keyId)]),
    );
  }

  private enqueue(
    view: View,
    makeStatement: Pending['makeStatement'],
    id: string,
    signal: AbortSignal | undefined,
    extra: { descriptor?: string; handoff?: boolean } = {},
  ): Promise<ApprovalDecision> {
    const descriptor = extra.descriptor;
    return new Promise((resolve) => {
      let done = false;
      const timeoutMs = this.opts.timeoutMs ?? 120_000;
      const timer = setTimeout(() => finish({ approved: false, reason: 'timeout' }), timeoutMs);
      const onAbort = () => finish({ approved: false, reason: 'aborted' });
      const finish: Pending['finish'] = (d) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        signal?.removeEventListener('abort', onAbort);
        this.pending.delete(id);
        resolve(d);
      };
      if (this.pending.has(id) || signal?.aborted) {
        done = true;
        clearTimeout(timer);
        resolve({ approved: false, reason: signal?.aborted ? 'aborted' : 'duplicate_request' });
        return;
      }
      signal?.addEventListener('abort', onAbort);
      const createdAt = this.now();
      const entry: Pending = {
        id,
        handoff: extra.handoff === true,
        createdAt,
        expiresAt: createdAt + timeoutMs,
        view,
        makeStatement,
        statement: null,
        ...(descriptor !== undefined ? { descriptor } : {}),
        finish,
      };
      this.pending.set(id, entry);
      void this.notify(entry);
    });
  }

  private notify(p: Pending): Promise<void> {
    return this.notifyAll(p).catch(() => {
      this.opts.log?.('approver: push failed');
    });
  }

  private async notifyAll(p: Pending): Promise<void> {
    const subject = this.opts.pushSubject ?? this.origin;
    const apns = this.opts.apns;
    const n = {
      requestId: p.id,
      kind:
        p.view.kind === 'pair'
          ? ('pair' as const)
          : p.view.display.action === 'register'
            ? ('register' as const)
            : ('sign-in' as const),
      verifiedOrigin: p.view.kind === 'pair' ? null : p.view.display.verifiedOrigin,
      ttlSeconds: Math.max(1, Math.ceil((p.expiresAt - this.now()) / 1000)),
    };
    await Promise.all(
      this.devices.list().map(async (d) => {
        if (d.push) {
          const r = await sendPush(d.push, this.vapid, { subject });
          if (r === 'gone') this.devices.setPush(d.id, undefined);
          if (r !== 'sent') this.opts.log?.(`approver: push to ${d.id} ${r}`);
        }
        if (d.apns && apns && !p.handoff) {
          const r = await apns.send(d.apns.token, d.apns.environment, n);
          if (r === 'gone') this.devices.setApns(d.id, undefined);
          if (r !== 'sent') this.opts.log?.(`approver: APNs to ${d.id} ${r}`);
        }
      }),
    );
  }

  private clearPairing(): void {
    this.pairing = null;
    rmSync(join(this.opts.dir, 'pairing-url'), { force: true });
  }

  private checkPairing(code: unknown): Pairing {
    const p = this.pairing;
    if (!p || typeof code !== 'string' || code.length !== 43) throw new HttpError(403, 'bad_code');
    const h = Buffer.from(sha256B64url(code));
    if (h.length !== p.codeHash.length || !timingSafeEqual(h, p.codeHash)) {
      throw new HttpError(403, 'bad_code');
    }
    if (this.now() > p.expiresAt) {
      this.clearPairing();
      throw new HttpError(403, 'code_expired');
    }
    return p;
  }

  private send(
    res: ServerResponse,
    status: number,
    body: unknown,
    extra: Record<string, string> = {},
  ): void {
    const json = Buffer.from(JSON.stringify(body));
    res.writeHead(status, {
      ...this.securityHeaders(),
      'content-type': 'application/json; charset=utf-8',
      'content-length': json.length,
      ...extra,
    });
    res.end(json);
  }

  private securityHeaders(): Record<string, string> {
    return securityHeaders(this.origin);
  }

  private async body(req: IncomingMessage): Promise<Record<string, unknown>> {
    if (!/^application\/json(;|$)/i.test(req.headers['content-type'] ?? '')) {
      throw new HttpError(415, 'json_only');
    }
    const declared = Number(req.headers['content-length'] ?? 0);
    if (declared > MAX_BODY) throw new HttpError(413, 'too_large');
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const c of req) {
      size += (c as Buffer).length;
      if (size > MAX_BODY) throw new HttpError(413, 'too_large');
      chunks.push(c as Buffer);
    }
    let v: unknown;
    try {
      v = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } catch {
      throw new HttpError(400, 'bad_json');
    }
    if (!v || typeof v !== 'object' || Array.isArray(v)) throw new HttpError(400, 'bad_json');
    return v as Record<string, unknown>;
  }

  private async device(req: IncomingMessage): Promise<Device> {
    const cookies = (req.headers.cookie ?? '').split(';').map((c) => c.trim());
    const raw = cookies.find((c) => c.startsWith(`${COOKIE}=`))?.slice(COOKIE.length + 1);
    const d = this.devices.byToken(raw);
    if (!d) {
      if (this.addressState.kind === 'latched') {
        throw new HttpError(401, ADDRESS_REFUSAL.latched, { on: this.platformWord });
      }
      throw new HttpError(401, 'not_paired');
    }
    return this.stillTrusted(d);
  }

  private async stillTrusted(d: Device): Promise<Device> {
    let trusted: { passkeys: WebAuthnApproverKey[]; native: NativeApproverKey[] };
    try {
      trusted = await this.trustedAll();
    } catch {
      throw new HttpError(503, 'signer_unavailable');
    }
    const ok =
      (d.kind ?? 'web') === 'native'
        ? trusted.native.some((k) => k.keyId === d.credentialId)
        : trusted.passkeys.some((k) => k.credentialId === d.credentialId);
    if (ok) return d;
    this.devices.remove(d.id);
    const port = this.handoffs;
    for (const v of port?.list() ?? []) {
      if (port?.controller(v.id) === d.id) port.finish(v.id, d.id, 'cancelled');
    }
    this.opts.onEvent?.('approver.device_untrusted', { deviceId: d.id });
    throw new HttpError(401, 'not_paired');
  }

  private cookie(token: string): string {
    return `${COOKIE}=${token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=31536000`;
  }

  private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    try {
      if (!this.allowedHosts.has(req.headers.host ?? '')) throw new HttpError(421, 'bad_host');
      const path = (req.url ?? '/').split('?')[0] as string;
      const method = req.method ?? 'GET';
      if (
        (method === 'GET' || method === 'HEAD') &&
        !this.opts.apiOnly &&
        Object.hasOwn(STATIC, path)
      ) {
        const s = STATIC[path] as { file: string; type: string };
        const buf = this.files.get(s.file) as Buffer;
        res.writeHead(200, {
          ...this.securityHeaders(),
          'content-type': s.type,
          'content-length': buf.length,
        });
        res.end(buf);
        return;
      }
      if (method === 'GET' && path === '/api/state') return await this.state(req, res);
      if (path.startsWith('/api/handoff/')) return await this.handleHandoff(req, res, method, path);
      if (path.startsWith('/api/native/')) return await this.handleNative(req, res, method, path);
      if (method !== 'POST') throw new HttpError(404, 'not_found');
      if (req.headers.origin !== this.origin) throw new HttpError(403, 'bad_origin');
      const site = req.headers['sec-fetch-site'];
      if (site !== undefined && site !== 'same-origin') throw new HttpError(403, 'bad_origin');
      const body = await this.body(req);
      switch (path) {
        case '/api/pair/options':
          return await this.pairOptions(res, body);
        case '/api/pair/finish':
          return await this.pairFinish(res, body);
        case '/api/pair/status':
          return this.pairStatus(res, body);
        case '/api/challenge':
          return await this.challenge(req, res, body);
        case '/api/decide':
          return await this.decide(req, res, body);
        case '/api/push':
          return await this.push(req, res, body);
        default:
          throw new HttpError(404, 'not_found');
      }
    } catch (err) {
      if (err instanceof HttpError) {
        return this.send(res, err.status, { error: err.message, ...err.extra });
      }
      throw err;
    }
  }

  private async state(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const d = await this.device(req);
    const pending = [...this.pending.values()]
      .sort((a, b) => a.createdAt - b.createdAt)
      .map((p) => ({ id: p.id, createdAt: p.createdAt, ...p.view }));
    const port = this.handoffs;
    const handoffs = (port?.list() ?? [])
      .filter((v) => v.withSignIn !== true || port?.controller(v.id) !== null)
      .map((v) => ({
        id: v.id,
        host: v.host,
        agentName: v.agentName,
      }));
    const a = this.addressState;
    this.send(res, 200, {
      now: this.now(),
      pending,
      handoffs,
      vapidPublicKey: this.vapid.publicKey,
      push: d.push !== undefined,
      ...(a.kind === 'paused' && addressPhase(a, this.now()) === 'paused'
        ? { address: { kind: a.kind, detail: a.detail, on: this.platformWord } }
        : {}),
    });
  }

  private async pairOptions(res: ServerResponse, body: Record<string, unknown>): Promise<void> {
    this.requireAddressOk();
    const p = this.checkPairing(body.code);
    if (p.state !== 'open') throw new HttpError(409, 'pairing_in_progress');
    const keys = await this.trustedKeys();
    p.kind = 'web';
    const options = await generateRegistrationOptions({
      rpName: 'Keyflap approver',
      rpID: this.rpId,
      userName: 'approver',
      userDisplayName: 'Keyflap approver',
      attestationType: 'none',
      excludeCredentials: keys.map((k) => ({ id: k.credentialId })),
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
      supportedAlgorithmIDs: [-7],
      timeout: 120_000,
    });
    p.challenge = options.challenge;
    this.send(res, 200, options);
  }

  private async pairFinish(res: ServerResponse, body: Record<string, unknown>): Promise<void> {
    this.requireAddressOk();
    const p = this.checkPairing(body.code);
    if (p.state !== 'open' || !p.challenge) throw new HttpError(409, 'no_ceremony');
    const expectedChallenge = p.challenge;
    p.challenge = null;
    let key: { credentialId: string; x: string; y: string; rpId: string; origin: string };
    try {
      const v = await verifyRegistrationResponse({
        response: body.response as RegistrationResponseJSON,
        expectedChallenge,
        expectedOrigin: this.origin,
        expectedRPID: this.rpId,
        requireUserVerification: true,
        supportedAlgorithmIDs: [-7],
      });
      if (!v.verified) throw new Error('not verified');
      const cose = decodeCredentialPublicKey(
        v.registrationInfo.credential.publicKey,
      ) as unknown as Map<number, unknown>;
      const x = cose.get(-2);
      const y = cose.get(-3);
      if (
        cose.get(1) !== 2 ||
        cose.get(3) !== -7 ||
        cose.get(-1) !== 1 ||
        !(x instanceof Uint8Array) ||
        !(y instanceof Uint8Array) ||
        x.length !== 32 ||
        y.length !== 32
      ) {
        throw new Error('not ES256');
      }
      key = {
        credentialId: v.registrationInfo.credential.id,
        x: Buffer.from(x).toString('base64url'),
        y: Buffer.from(y).toString('base64url'),
        rpId: this.rpId,
        origin: this.origin,
      };
    } catch {
      throw new HttpError(400, 'registration_failed');
    }

    const trusted = await this.trustedAll();
    const existing = trusted.passkeys.length + trusted.native.length;
    if (existing === 0 && trusted.anywhere > 0) {
      throw new HttpError(409, 'paired_at_other_origin');
    }
    if (existing === 0) {
      try {
        this.acceptPairing(key.credentialId, true, 'web');
        await this.opts.signer.addApprover({ key });
      } catch {
        throw new HttpError(409, 'pairing_refused');
      }
      this.paired(p, key.credentialId, true, 'web');
      const token = p.token as string;
      this.clearPairing();
      this.send(res, 200, { status: 'paired' }, { 'set-cookie': this.cookie(token) });
      return;
    }
    const descriptor = approverDescriptor(key);
    const check = this.awaitApprovalToAdd(p, {
      kind: 'web',
      credentialId: key.credentialId,
      descriptor,
      add: (approval) => this.opts.signer.addApprover({ key, approval }).then(() => {}),
    });
    this.send(res, 202, { status: 'waiting', check });
  }

  private awaitApprovalToAdd(
    p: Pairing,
    n: {
      kind: DeviceKind;
      credentialId: string;
      descriptor: string;
      add: (approval: SignedApproval) => Promise<void>;
    },
  ): string {
    p.state = 'waiting';
    p.kind = n.kind;
    const check = checkCode(n.descriptor);
    const what = n.kind === 'native' ? 'iOS app' : 'phone';
    this.opts.log?.(`approver: new ${what} waiting for approval, check code ${check}`);
    const requestId = randomUUID();
    void this.enqueue(
      {
        kind: 'pair',
        requestedAt: this.now(),
        check,
        newDevice: n.kind === 'native' ? 'ios-app' : 'passkey',
      },
      (now) => ({
        v: 1,
        requestId,
        kind: 'approver.add',
        verifiedOrigin: this.origin,
        rpId: this.rpId,
        credentialId: n.credentialId,
        intentHash: sha256B64url(n.descriptor),
        clientDataHash: sha256B64url(n.descriptor),
        userVerified: true,
        issuedAt: now,
        expiresAt: now + APPROVAL_TTL_MS,
      }),
      requestId,
      undefined,
      { descriptor: n.descriptor },
    ).then(async (d) => {
      if (this.pairing !== p) return;
      try {
        if (!d.approved) throw new Error(d.reason);
        this.acceptPairing(n.credentialId, false, n.kind);
        await n.add(d.approval);
        this.paired(p, n.credentialId, false, n.kind);
      } catch {
        p.state = 'failed';
        this.opts.onEvent?.('approver.pairing_failed', { origin: this.origin });
      }
    });
    return check;
  }

  private acceptPairing(credentialId: string, first: boolean, kind: DeviceKind): void {
    this.opts.auditBefore('approver.pairing_accepted', {
      origin: this.origin,
      credentialId,
      first,
      kind,
    });
  }

  private paired(p: Pairing, credentialId: string, first: boolean, kind: DeviceKind): void {
    const { device, token } = this.devices.add(credentialId, this.now(), kind);
    p.state = 'paired';
    p.token = token;
    p.kind = kind;
    rmSync(join(this.opts.dir, 'pairing-url'), { force: true });
    this.opts.onEvent?.('approver.paired', { credentialId, deviceId: device.id, first, kind });
    const what = kind === 'native' ? 'iOS app key' : 'passkey';
    this.opts.log?.(`approver: paired device ${device.id} (${what} ${credentialId.slice(0, 8)}…)`);
  }

  private pairStatus(res: ServerResponse, body: Record<string, unknown>): void {
    const p = this.checkPairing(body.code);
    if (p.kind === 'native') throw new HttpError(409, 'pairing_in_progress');
    if (p.state === 'paired' && p.token) {
      const token = p.token;
      p.token = null;
      this.clearPairing();
      this.send(res, 200, { status: 'paired' }, { 'set-cookie': this.cookie(token) });
      return;
    }
    if (p.state === 'failed') this.clearPairing();
    this.send(res, 200, { status: p.state === 'paired' ? 'done' : p.state });
  }

  private async pendingFor(req: IncomingMessage, id: unknown): Promise<Pending> {
    await this.device(req);
    if (typeof id !== 'string') throw new HttpError(400, 'bad_id');
    const p = this.pending.get(id);
    if (!p) throw new HttpError(404, 'no_such_request');
    return p;
  }

  private async challenge(
    req: IncomingMessage,
    res: ServerResponse,
    body: Record<string, unknown>,
  ): Promise<void> {
    const p = await this.pendingFor(req, body.id);
    this.requireAddressOk();
    const keep = body.keepSignedIn;
    if (keep !== undefined && typeof keep !== 'boolean') throw new HttpError(400, 'bad_keep');
    if (
      keep === true &&
      (p.view.kind !== 'credential' || p.view.display.keepSignedInSite === undefined)
    ) {
      throw new HttpError(400, 'keep_not_offered');
    }
    let keys = await this.trustedKeys();
    if (p.handoff) {
      const d = await this.device(req);
      keys = keys.filter((k) => k.credentialId === d.credentialId);
      if (keys.length === 0) throw new HttpError(403, 'unknown_approver');
    }
    p.statement = p.makeStatement(this.now(), { keepSignedIn: keep === true });
    this.send(res, 200, {
      statement: p.statement,
      descriptor: p.descriptor ?? null,
      challenge: approvalChallenge(p.statement),
      rpId: this.rpId,
      allowCredentials: keys.map((k) => k.credentialId),
      timeout: 60_000,
    });
  }

  private async decide(
    req: IncomingMessage,
    res: ServerResponse,
    body: Record<string, unknown>,
  ): Promise<void> {
    const p = await this.pendingFor(req, body.id);
    const device = await this.device(req);
    if (body.decision === 'deny') {
      p.finish({ approved: false, reason: 'user_denied' });
      return this.send(res, 200, { ok: true });
    }
    if (body.decision !== 'approve' || !p.statement) throw new HttpError(400, 'bad_decision');
    this.requireAddressOk();
    const c = body.credential as { id?: unknown; response?: Record<string, unknown> } | undefined;
    const r = c?.response;
    if (
      typeof c?.id !== 'string' ||
      typeof r?.authenticatorData !== 'string' ||
      typeof r.clientDataJSON !== 'string' ||
      typeof r.signature !== 'string'
    ) {
      throw new HttpError(400, 'bad_credential');
    }
    const approval: WebAuthnApproval = {
      statement: p.statement,
      approverKeyId: c.id,
      webauthn: {
        authenticatorData: r.authenticatorData,
        clientDataJSON: r.clientDataJSON,
        signature: r.signature,
      },
    };
    const key = (await this.trustedKeys()).find((k) => k.credentialId === c.id);
    if (!key) throw new HttpError(403, 'unknown_approver');
    if (p.handoff && c.id !== device.credentialId) throw new HttpError(403, 'unknown_approver');
    const check = verifyWebAuthnAssertion(approval, key);
    if (!check.ok) throw new HttpError(400, check.reason);
    if (this.now() > p.statement.expiresAt) throw new HttpError(400, 'expired');
    p.finish(
      p.handoff ? { approved: true, approval, deviceId: device.id } : { approved: true, approval },
    );
    this.send(res, 200, { ok: true });
  }

  private async handleNative(
    req: IncomingMessage,
    res: ServerResponse,
    method: string,
    path: string,
  ): Promise<void> {
    const origin = req.headers.origin;
    if (origin !== undefined && origin !== this.origin) throw new HttpError(403, 'bad_origin');
    if (method === 'GET' && path === '/api/native/state') return await this.nativeState(req, res);
    if (method !== 'POST') throw new HttpError(404, 'not_found');
    const body = await this.body(req);
    switch (path) {
      case '/api/native/pair':
        return await this.nativePair(res, body);
      case '/api/native/pair/status':
        return this.nativePairStatus(res, body);
      case '/api/native/challenge':
        return await this.nativeChallenge(req, res, body);
      case '/api/native/decide':
        return await this.nativeDecide(req, res, body);
      case '/api/native/apns':
        return await this.nativeApns(req, res, body);
      case '/api/native/unpair':
        return await this.nativeUnpair(req, res);
      default:
        throw new HttpError(404, 'not_found');
    }
  }

  private async nativeDevice(req: IncomingMessage): Promise<Device> {
    const m = /^Bearer ([A-Za-z0-9_-]{43})$/.exec(req.headers.authorization ?? '');
    const d = m ? this.devices.byToken(m[1], 'native') : undefined;
    if (!d) throw new HttpError(401, 'not_paired');
    return this.stillTrusted(d);
  }

  private async nativeState(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const d = await this.nativeDevice(req);
    const pending = [...this.pending.values()]
      .filter((p) => !p.handoff)
      .sort((a, b) => a.createdAt - b.createdAt)
      .map((p) => ({
        id: p.id,
        createdAt: p.createdAt,
        expiresAt: p.expiresAt,
        ...(p.view.kind === 'credential'
          ? { kind: p.view.kind, display: withoutKeepOffer(p.view.display) }
          : p.view),
      }));
    this.send(res, 200, {
      now: this.now(),
      pending,
      device: { id: d.id, keyId: d.credentialId },
      apns: { configured: this.opts.apns !== undefined, registered: d.apns !== undefined },
    });
  }

  private async nativePair(res: ServerResponse, body: Record<string, unknown>): Promise<void> {
    this.requireAddressOk();
    const p = this.checkPairing(body.code);
    if (p.state !== 'open' || p.challenge !== null) {
      throw new HttpError(409, 'pairing_in_progress');
    }
    const add = this.opts.signer.addNativeApprover?.bind(this.opts.signer);
    if (!add) throw new HttpError(501, 'native_unsupported');
    const k = body.key as { x?: unknown; y?: unknown } | undefined;
    if (typeof k?.x !== 'string' || typeof k.y !== 'string' || typeof body.proof !== 'string') {
      throw new HttpError(400, 'bad_key');
    }
    if (body.userVerification !== 'biometry') {
      throw new HttpError(400, 'user_verification_required');
    }
    const key = {
      x: k.x,
      y: k.y,
      origin: this.origin,
      userVerification: 'biometry' as const,
    };
    let keyId: string;
    try {
      keyId = nativeKeyId(key.x, key.y);
    } catch {
      throw new HttpError(400, 'bad_key');
    }
    const descriptor = nativeApproverDescriptor({ keyId, ...key });
    const proof = body.proof;
    if (!verifyNativeSignature(key, nativePairingProofBytes(descriptor), proof)) {
      throw new HttpError(400, 'bad_proof');
    }
    const trusted = await this.trustedAll();
    const existing = trusted.passkeys.length + trusted.native.length;
    if (existing === 0 && trusted.anywhere > 0) throw new HttpError(409, 'paired_at_other_origin');
    if (existing === 0) {
      try {
        this.acceptPairing(keyId, true, 'native');
        await add({ key, proof });
      } catch {
        throw new HttpError(409, 'pairing_refused');
      }
      this.paired(p, keyId, true, 'native');
      const token = p.token as string;
      this.clearPairing();
      this.send(res, 200, { status: 'paired', deviceToken: token, keyId });
      return;
    }
    const check = this.awaitApprovalToAdd(p, {
      kind: 'native',
      credentialId: keyId,
      descriptor,
      add: (approval) => add({ key, proof, approval }).then(() => {}),
    });
    this.send(res, 202, { status: 'waiting', check, keyId });
  }

  private nativePairStatus(res: ServerResponse, body: Record<string, unknown>): void {
    const p = this.checkPairing(body.code);
    if (p.kind !== 'native') throw new HttpError(409, 'pairing_in_progress');
    if (p.state === 'paired' && p.token) {
      const token = p.token;
      p.token = null;
      this.clearPairing();
      this.send(res, 200, { status: 'paired', deviceToken: token });
      return;
    }
    if (p.state === 'failed') this.clearPairing();
    this.send(res, 200, { status: p.state === 'paired' ? 'done' : p.state });
  }

  private async nativePending(
    req: IncomingMessage,
    id: unknown,
  ): Promise<{ device: Device; p: Pending }> {
    const device = await this.nativeDevice(req);
    if (typeof id !== 'string') throw new HttpError(400, 'bad_id');
    const p = this.pending.get(id);
    if (!p || p.handoff) throw new HttpError(404, 'no_such_request');
    return { device, p };
  }

  private async nativeChallenge(
    req: IncomingMessage,
    res: ServerResponse,
    body: Record<string, unknown>,
  ): Promise<void> {
    const { p } = await this.nativePending(req, body.id);
    this.requireAddressOk();
    p.statement = p.makeStatement(this.now());
    this.send(res, 200, { statement: p.statement, descriptor: p.descriptor ?? null });
  }

  private async nativeDecide(
    req: IncomingMessage,
    res: ServerResponse,
    body: Record<string, unknown>,
  ): Promise<void> {
    const { device, p } = await this.nativePending(req, body.id);
    if (body.decision === 'deny') {
      p.finish({ approved: false, reason: 'user_denied' });
      return this.send(res, 200, { ok: true });
    }
    if (body.decision !== 'approve' || !p.statement || typeof body.signature !== 'string') {
      throw new HttpError(400, 'bad_decision');
    }
    this.requireAddressOk();
    const key = (await this.trustedAll()).native.find((k) => k.keyId === device.credentialId);
    if (!key) throw new HttpError(403, 'unknown_approver');
    const approval: NativeApproval = {
      statement: p.statement,
      approverKeyId: key.keyId,
      native: { signature: body.signature },
    };
    const check = verifyNativeApproval(approval, key);
    if (!check.ok) throw new HttpError(400, check.reason);
    if (this.now() > p.statement.expiresAt) throw new HttpError(400, 'expired');
    p.finish({ approved: true, approval });
    this.send(res, 200, { ok: true });
  }

  private async nativeApns(
    req: IncomingMessage,
    res: ServerResponse,
    body: Record<string, unknown>,
  ): Promise<void> {
    const d = await this.nativeDevice(req);
    if (body.token === null) {
      this.devices.setApns(d.id, undefined);
      this.send(res, 200, { ok: true });
      return;
    }
    const env = body.environment;
    if (!validDeviceToken(body.token) || (env !== 'sandbox' && env !== 'production')) {
      throw new HttpError(400, 'bad_token');
    }
    this.devices.setApns(d.id, { token: body.token, environment: env });
    this.send(res, 200, { ok: true, configured: this.opts.apns !== undefined });
  }

  private async nativeUnpair(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const d = await this.nativeDevice(req);
    this.devices.remove(d.id);
    let keyRemoved = false;
    try {
      keyRemoved = (await this.opts.signer.removeApprover?.(d.credentialId))?.removed === true;
    } catch {
      keyRemoved = false;
    }
    this.opts.onEvent?.('approver.unpaired', { deviceId: d.id, keyRemoved });
    this.send(res, 200, { ok: true, keyRemoved });
  }

  private async handleHandoff(
    req: IncomingMessage,
    res: ServerResponse,
    method: string,
    path: string,
  ): Promise<void> {
    const port = this.handoffs;
    if (!port) throw new HttpError(404, 'not_found');
    const site = req.headers['sec-fetch-site'];
    if (site !== undefined && site !== 'same-origin') throw new HttpError(403, 'bad_origin');
    if (method === 'GET') {
      if (path === '/api/handoff/state') return await this.handoffState(req, res, port);
      if (path === '/api/handoff/frame') return await this.handoffFrame(req, res, port);
      throw new HttpError(404, 'not_found');
    }
    if (method !== 'POST') throw new HttpError(404, 'not_found');
    if (req.headers.origin !== this.origin) throw new HttpError(403, 'bad_origin');
    const body = await this.body(req);
    switch (path) {
      case '/api/handoff/challenge':
        return await this.handoffChallenge(req, res, body, port);
      case '/api/handoff/start':
        return await this.handoffStart(req, res, body, port);
      case '/api/handoff/input':
        return await this.handoffInput(req, res, body, port);
      case '/api/handoff/finish':
        return await this.handoffFinish(req, res, body, port);
      default:
        throw new HttpError(404, 'not_found');
    }
  }

  private async handoffState(
    req: IncomingMessage,
    res: ServerResponse,
    port: HandoffPort,
  ): Promise<void> {
    const d = await this.device(req);
    const handoffs = port.list().map((v) => {
      const c = port.controller(v.id);
      return {
        id: v.id,
        host: v.host,
        agentName: v.agentName,
        intentText: v.intentText,
        intentAt: v.intentAt,
        openedAt: v.openedAt,
        expiresAt: v.expiresAt,
        withSignIn: v.withSignIn === true,
        started: c !== null,
        mine: c === d.id,
      };
    });
    this.send(res, 200, { now: this.now(), handoffs });
  }

  private openHandoff(port: HandoffPort, id: string): HandoffView {
    const v = port.get(id);
    if (!v) throw new HttpError(404, 'no_such_handoff');
    return v;
  }

  private async handoffChallenge(
    req: IncomingMessage,
    res: ServerResponse,
    body: Record<string, unknown>,
    port: HandoffPort,
  ): Promise<void> {
    const d = await this.device(req);
    const id = handoffId(body.id);
    this.requireAddressOk();
    if (this.openHandoff(port, id).withSignIn === true) {
      throw new HttpError(409, 'started_by_approval');
    }
    const c = port.controller(id);
    if (c !== null && c !== d.id) throw new HttpError(409, 'taken');
    const key = (await this.trustedKeys()).find((k) => k.credentialId === d.credentialId);
    if (!key) throw new HttpError(403, 'unknown_approver');
    const nonce = randomBytes(32).toString('base64url');
    const challenge = handoffStartChallenge(id, nonce);
    for (const [k, v] of this.handoffStarts) {
      if (this.now() > v.expiresAt) this.handoffStarts.delete(k);
    }
    this.handoffStarts.set(`${d.id}\n${id}`, {
      challenge,
      expiresAt: this.now() + HANDOFF_START_TTL_MS,
    });
    this.send(res, 200, {
      nonce,
      challenge,
      rpId: this.rpId,
      allowCredentials: [key.credentialId],
      timeout: 60_000,
    });
  }

  private async handoffStart(
    req: IncomingMessage,
    res: ServerResponse,
    body: Record<string, unknown>,
    port: HandoffPort,
  ): Promise<void> {
    const d = await this.device(req);
    const id = handoffId(body.id);
    this.requireAddressOk();
    const slot = `${d.id}\n${id}`;
    const started = this.handoffStarts.get(slot);
    this.handoffStarts.delete(slot);
    if (!started || this.now() > started.expiresAt) throw new HttpError(400, 'no_ceremony');
    if (this.openHandoff(port, id).withSignIn === true) {
      throw new HttpError(409, 'started_by_approval');
    }
    const c = body.credential as { id?: unknown; response?: Record<string, unknown> } | undefined;
    const r = c?.response;
    if (
      typeof c?.id !== 'string' ||
      typeof r?.authenticatorData !== 'string' ||
      typeof r.clientDataJSON !== 'string' ||
      typeof r.signature !== 'string'
    ) {
      throw new HttpError(400, 'bad_credential');
    }
    if (c.id !== d.credentialId) throw new HttpError(403, 'unknown_approver');
    const key = (await this.trustedKeys()).find((k) => k.credentialId === d.credentialId);
    if (!key) throw new HttpError(403, 'unknown_approver');
    let ok = false;
    try {
      const cd = JSON.parse(Buffer.from(r.clientDataJSON, 'base64url').toString('utf8')) as {
        crossOrigin?: unknown;
        topOrigin?: unknown;
      };
      if (cd.crossOrigin === true || cd.topOrigin !== undefined) throw new Error('cross-origin');
      const v = await verifyAuthenticationResponse({
        response: {
          id: c.id,
          rawId: c.id,
          type: 'public-key',
          response: {
            authenticatorData: r.authenticatorData,
            clientDataJSON: r.clientDataJSON,
            signature: r.signature,
          },
          clientExtensionResults: {},
        },
        expectedChallenge: started.challenge,
        expectedOrigin: this.origin,
        expectedRPID: this.rpId,
        credential: { id: key.credentialId, publicKey: coseKey(key), counter: 0 },
        requireUserVerification: true,
      });
      ok = v.verified;
    } catch {
      ok = false;
    }
    if (!ok) throw new HttpError(400, 'bad_assertion');
    const result = port.start(id, d.id);
    if (result === 'not_found') throw new HttpError(404, 'no_such_handoff');
    if (result === 'taken') throw new HttpError(409, 'taken');
    if (result === 'approval_only') throw new HttpError(409, 'started_by_approval');
    this.send(res, 200, { ok: true });
  }

  private async controllerOf(req: IncomingMessage, port: HandoffPort, id: string): Promise<string> {
    const d = await this.device(req);
    this.openHandoff(port, id);
    if (port.controller(id) !== d.id) throw new HttpError(403, 'not_controller');
    return d.id;
  }

  private async handoffFrame(
    req: IncomingMessage,
    res: ServerResponse,
    port: HandoffPort,
  ): Promise<void> {
    const q = new URL(req.url ?? '/', 'http://x').searchParams;
    const id = handoffId(q.get('id'));
    const clip = parseHandoffClip(q.get('clip'));
    const deviceId = await this.controllerOf(req, port, id);
    const img = await (clip ? port.frame(id, deviceId, clip) : port.frame(id, deviceId)).catch(
      () => null,
    );
    if (!img) throw new HttpError(503, 'unavailable');
    res.writeHead(200, {
      ...this.securityHeaders(),
      'content-type': 'image/jpeg',
      'content-length': img.length,
    });
    res.end(img);
  }

  private async handoffInput(
    req: IncomingMessage,
    res: ServerResponse,
    body: Record<string, unknown>,
    port: HandoffPort,
  ): Promise<void> {
    const id = handoffId(body.id);
    const deviceId = await this.controllerOf(req, port, id);
    const input = parseHandoffInput(body.input);
    if (!input) throw new HttpError(400, 'bad_input');
    const r = await port.input(id, deviceId, input).catch(() => ({
      ok: false as const,
      reason: 'failed' as const,
    }));
    if (r.ok) return this.send(res, 200, { ok: true });
    switch (r.reason) {
      case 'sensitive_field':
        return this.send(res, 422, {
          error: 'sensitive_field',
          message: "Use the broker's sign-in for passwords",
        });
      case 'not_open':
        throw new HttpError(404, 'no_such_handoff');
      case 'not_controller':
        throw new HttpError(403, 'not_controller');
      default:
        throw new HttpError(409, 'input_failed');
    }
  }

  private async handoffFinish(
    req: IncomingMessage,
    res: ServerResponse,
    body: Record<string, unknown>,
    port: HandoffPort,
  ): Promise<void> {
    const id = handoffId(body.id);
    const deviceId = await this.controllerOf(req, port, id);
    const outcome = body.outcome;
    if (outcome !== 'done' && outcome !== 'cancelled') throw new HttpError(400, 'bad_outcome');
    if (!port.finish(id, deviceId, outcome)) throw new HttpError(404, 'no_such_handoff');
    this.send(res, 200, { ok: true });
  }

  private async push(
    req: IncomingMessage,
    res: ServerResponse,
    body: Record<string, unknown>,
  ): Promise<void> {
    const d = await this.device(req);
    const sub = body.subscription as Partial<PushSubscription> | null | undefined;
    if (sub === null) {
      this.devices.setPush(d.id, undefined);
      this.send(res, 200, { ok: true });
      return;
    }
    const keys = sub?.keys;
    if (
      !validPushEndpoint(sub?.endpoint, this.opts.allowInsecurePushEndpoints) ||
      typeof keys?.p256dh !== 'string' ||
      typeof keys.auth !== 'string' ||
      Buffer.from(keys.p256dh, 'base64url').length !== 65 ||
      Buffer.from(keys.auth, 'base64url').length !== 16
    ) {
      throw new HttpError(400, 'bad_subscription');
    }
    this.devices.setPush(d.id, {
      endpoint: sub?.endpoint as string,
      keys: { p256dh: keys.p256dh, auth: keys.auth },
    });
    this.send(res, 200, { ok: true });
  }
}

function withoutKeepOffer(d: ApprovalRequest['display']): ApprovalRequest['display'] {
  const { keepSignedInSite: _offer, ...rest } = d;
  return rest;
}

export function checkCode(descriptor: string): string {
  const hex = sha256B64url(descriptor);
  const h = Buffer.from(hex, 'base64url').toString('hex').toUpperCase();
  return `${h.slice(0, 4)}-${h.slice(4, 8)}-${h.slice(8, 12)}`;
}
