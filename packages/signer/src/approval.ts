import { createHash, createPublicKey, type KeyObject, verify } from 'node:crypto';
import { fromB64url } from './b64url.ts';

export type ApprovalKind = 'webauthn.get' | 'webauthn.create' | 'fill' | 'approver.add';

export type FillField = 'password' | 'totp';
export const FILL_FIELDS: readonly FillField[] = ['password', 'totp'];

export interface ApprovalStatement {
  v: 1;
  requestId: string;
  kind: ApprovalKind;
  verifiedOrigin: string;
  rpId: string;
  credentialId: string | null;
  intentHash: string;
  clientDataHash: string;
  userVerified: boolean;
  issuedAt: number;
  expiresAt: number;
  strong?: true;
  grant?: ApprovalGrant;
  keepSignedIn?: { site: string };
  handoff?: { id: string };
}

export interface ApprovalGrant {
  agentId: string;
  until: number;
  uses?: 1;
}

export const MAX_GRANT_MS = 24 * 60 * 60_000;

export const HANDOFF_GRANT_MAX_MS = 7 * 60_000;

const HANDOFF_ID = /^[A-Za-z0-9-]{1,64}$/;

export function handoffSignInClientDataHash(handoffId: string): string {
  return sha256B64url(`aab-handoff-signin-v1\n${handoffId}`);
}

export interface Ed25519Approval {
  statement: ApprovalStatement;
  approverKeyId: string;
  signature: string;
  webauthn?: undefined;
  native?: undefined;
}

export interface WebAuthnApproval {
  statement: ApprovalStatement;
  approverKeyId: string;
  webauthn: {
    authenticatorData: string;
    clientDataJSON: string;
    signature: string;
  };
  signature?: undefined;
  native?: undefined;
}

export interface NativeApproval {
  statement: ApprovalStatement;
  approverKeyId: string;
  native: {
    signature: string;
  };
  signature?: undefined;
  webauthn?: undefined;
}

export type SignedApproval = Ed25519Approval | WebAuthnApproval | NativeApproval;

export interface GrantedApproval {
  statement: ApprovalStatement;
  grantId: string;
  agentId: string;
  approverKeyId?: undefined;
  signature?: undefined;
  webauthn?: undefined;
  native?: undefined;
}

export type SignerAuthorization = SignedApproval | GrantedApproval;

export function isGrantedApproval(a: unknown): a is GrantedApproval {
  return typeof a === 'object' && a !== null && (a as { grantId?: unknown }).grantId !== undefined;
}

const KEEP_SITE =
  /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;

export function keepSignedInOk(k: unknown): boolean {
  if (k === undefined) return true;
  if (typeof k !== 'object' || k === null || Array.isArray(k)) return false;
  const keys = Object.keys(k);
  const site = (k as Record<string, unknown>).site;
  return keys.length === 1 && typeof site === 'string' && KEEP_SITE.test(site);
}

function handoffOk(h: unknown): boolean {
  if (h === undefined) return true;
  if (typeof h !== 'object' || h === null || Array.isArray(h)) return false;
  const id = (h as Record<string, unknown>).id;
  return Object.keys(h).length === 1 && typeof id === 'string' && HANDOFF_ID.test(id);
}

export function statementExtrasOk(s: ApprovalStatement): boolean {
  if (s.strong !== undefined && s.strong !== true) return false;
  if (!keepSignedInOk(s.keepSignedIn)) return false;
  if (!handoffOk(s.handoff)) return false;
  const g = s.grant as unknown;
  if (g === undefined) return s.handoff === undefined;
  if (typeof g !== 'object' || g === null || Array.isArray(g)) return false;
  const keys = Object.keys(g);
  const { agentId, until, uses } = g as Record<string, unknown>;
  const single = uses !== undefined;
  if (single !== (s.handoff !== undefined)) return false;
  if (single && uses !== 1) return false;
  return (
    keys.length === (single ? 3 : 2) &&
    typeof agentId === 'string' &&
    agentId.length > 0 &&
    agentId.length <= 128 &&
    typeof until === 'number' &&
    Number.isFinite(until)
  );
}

export interface WebAuthnApproverKey {
  credentialId: string;
  x: string;
  y: string;
  rpId: string;
  origin: string;
  signCount: number;
  createdAt: number;
}

export interface NativeApproverKey {
  keyId: string;
  x: string;
  y: string;
  origin: string;
  userVerification: 'biometry';
  createdAt: number;
}

export const MAX_APPROVAL_LIFETIME_MS = 5 * 60_000;
const CLOCK_SKEW_MS = 30_000;
const DOMAIN = 'aab-approval-v1\n';
const NATIVE_DOMAIN = 'aab-native-approval-v1\n';

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const entries = Object.keys(value as Record<string, unknown>)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonicalJson((value as Record<string, unknown>)[k])}`);
  return `{${entries.join(',')}}`;
}

export function approvalSigningBytes(statement: ApprovalStatement): Buffer {
  return Buffer.from(DOMAIN + canonicalJson(statement), 'utf8');
}

export function nativeApprovalSigningBytes(statement: ApprovalStatement): Buffer {
  return Buffer.from(NATIVE_DOMAIN + canonicalJson(statement), 'utf8');
}

export function nativeKeyId(x: string, y: string): string {
  const X = fromB64url(x);
  const Y = fromB64url(y);
  if (X.length !== 32 || Y.length !== 32) throw new Error('bad P-256 coordinates');
  return createHash('sha256')
    .update(Buffer.concat([Buffer.of(4), X, Y]))
    .digest('base64url');
}

export function nativeApproverDescriptor(k: {
  keyId: string;
  x: string;
  y: string;
  origin: string;
  userVerification: string;
}): string {
  return `aab-native-approver-add-v1\n${canonicalJson({
    keyId: k.keyId,
    origin: k.origin,
    userVerification: k.userVerification,
    x: k.x,
    y: k.y,
  })}`;
}

export function nativePairingProofBytes(descriptor: string): Buffer {
  return Buffer.from(`aab-native-pair-v1\n${descriptor}`, 'utf8');
}

export function verifyNativeSignature(
  key: { x: string; y: string },
  data: Uint8Array,
  signatureB64url: unknown,
): boolean {
  if (typeof signatureB64url !== 'string' || signatureB64url.length > 200) return false;
  try {
    const pub = createPublicKey({
      key: { kty: 'EC', crv: 'P-256', x: key.x, y: key.y },
      format: 'jwk',
    });
    return verify('sha256', data, { key: pub, dsaEncoding: 'der' }, fromB64url(signatureB64url));
  } catch {
    return false;
  }
}

export function approvalChallenge(statement: ApprovalStatement): string {
  return sha256B64url(approvalSigningBytes(statement));
}

export function sha256B64url(data: string | Uint8Array): string {
  return createHash('sha256').update(data).digest('base64url');
}

export type TrustedApproverKeys = Record<string, string>;

export function ed25519PublicKey(rawB64url: string): KeyObject {
  return createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: rawB64url }, format: 'jwk' });
}

export interface ApprovalTrust {
  ed25519: TrustedApproverKeys;
  webauthn: (credentialId: string) => WebAuthnApproverKey | undefined;
  native?: (keyId: string) => NativeApproverKey | undefined;
  counterAccepted?: (approval: WebAuthnApproval) => boolean;
}

export type ApprovalCheck =
  | { ok: true; method: 'ed25519' }
  | { ok: true; method: 'webauthn'; key: WebAuthnApproverKey; signCount: number }
  | { ok: true; method: 'native'; key: NativeApproverKey }
  | { ok: false; reason: string };

export function isUserVerifiedMethod(method: string): boolean {
  return method === 'webauthn' || method === 'native';
}

const FLAG_UP = 0x01;
const FLAG_UV = 0x04;
const FLAG_AT = 0x40;
const FLAG_ED = 0x80;

export function verifyApproval(
  approval: SignedApproval,
  trust: ApprovalTrust,
  now: number,
): ApprovalCheck {
  if (!approval || typeof approval !== 'object') return { ok: false, reason: 'missing_approval' };
  const s = approval.statement;
  if (!s || typeof s !== 'object' || s.v !== 1) return { ok: false, reason: 'bad_statement' };
  if (!statementExtrasOk(s)) return { ok: false, reason: 'bad_statement' };
  if (typeof approval.approverKeyId !== 'string')
    return { ok: false, reason: 'untrusted_approver' };
  let result: ApprovalCheck;
  if (approval.webauthn !== undefined && approval.native !== undefined) {
    return { ok: false, reason: 'bad_approval' };
  }
  if (approval.native !== undefined) {
    const key = trust.native?.(approval.approverKeyId);
    if (!key) return { ok: false, reason: 'untrusted_approver' };
    const r = verifyNativeApproval(approval as NativeApproval, key);
    if (!r.ok) return r;
    if (s.userVerified !== true) return { ok: false, reason: 'user_not_verified' };
    result = { ok: true, method: 'native', key };
  } else if (approval.webauthn !== undefined) {
    const key = trust.webauthn(approval.approverKeyId);
    if (!key) return { ok: false, reason: 'untrusted_approver' };
    const r = verifyWebAuthnAssertion(approval as WebAuthnApproval, key, trust.counterAccepted);
    if (!r.ok) return r;
    if (s.userVerified !== true) return { ok: false, reason: 'user_not_verified' };
    result = { ok: true, method: 'webauthn', key, signCount: r.signCount };
  } else {
    const raw = Object.hasOwn(trust.ed25519, approval.approverKeyId)
      ? trust.ed25519[approval.approverKeyId]
      : undefined;
    if (!raw) return { ok: false, reason: 'untrusted_approver' };
    let sigOk = false;
    try {
      sigOk = verify(
        null,
        approvalSigningBytes(s),
        ed25519PublicKey(raw),
        fromB64url(approval.signature as string),
      );
    } catch {
      sigOk = false;
    }
    if (!sigOk) return { ok: false, reason: 'bad_signature' };
    result = { ok: true, method: 'ed25519' };
  }
  if (typeof s.issuedAt !== 'number' || typeof s.expiresAt !== 'number') {
    return { ok: false, reason: 'bad_statement' };
  }
  if (s.expiresAt - s.issuedAt > MAX_APPROVAL_LIFETIME_MS)
    return { ok: false, reason: 'lifetime_too_long' };
  if (now > s.expiresAt) return { ok: false, reason: 'expired' };
  if (now + CLOCK_SKEW_MS < s.issuedAt) return { ok: false, reason: 'not_yet_valid' };
  return result;
}

export function verifyWebAuthnAssertion(
  approval: WebAuthnApproval,
  key: WebAuthnApproverKey,
  counterAccepted?: (approval: WebAuthnApproval) => boolean,
): { ok: true; signCount: number } | { ok: false; reason: string } {
  const w = approval.webauthn;
  if (
    !w ||
    typeof w !== 'object' ||
    typeof w.authenticatorData !== 'string' ||
    typeof w.clientDataJSON !== 'string' ||
    typeof w.signature !== 'string' ||
    w.clientDataJSON.length > 8192 ||
    w.authenticatorData.length > 1024 ||
    w.signature.length > 1024
  ) {
    return { ok: false, reason: 'bad_assertion' };
  }
  let clientDataBytes: Buffer;
  let authData: Buffer;
  let signature: Buffer;
  try {
    clientDataBytes = fromB64url(w.clientDataJSON);
    authData = fromB64url(w.authenticatorData);
    signature = fromB64url(w.signature);
  } catch {
    return { ok: false, reason: 'bad_assertion' };
  }
  let cd: Record<string, unknown>;
  try {
    cd = JSON.parse(clientDataBytes.toString('utf8')) as Record<string, unknown>;
  } catch {
    return { ok: false, reason: 'bad_assertion' };
  }
  if (!cd || typeof cd !== 'object' || Array.isArray(cd))
    return { ok: false, reason: 'bad_assertion' };
  if (cd.type !== 'webauthn.get') return { ok: false, reason: 'assertion_type_mismatch' };
  if (cd.challenge !== approvalChallenge(approval.statement)) {
    return { ok: false, reason: 'assertion_challenge_mismatch' };
  }
  if (cd.origin !== key.origin) return { ok: false, reason: 'assertion_origin_mismatch' };
  if (cd.crossOrigin === true || cd.topOrigin !== undefined) {
    return { ok: false, reason: 'assertion_cross_origin' };
  }
  if (authData.length !== 37) return { ok: false, reason: 'bad_assertion' };
  const rpIdHash = createHash('sha256').update(key.rpId).digest();
  if (!authData.subarray(0, 32).equals(rpIdHash)) {
    return { ok: false, reason: 'assertion_rp_id_mismatch' };
  }
  const flags = authData[32] ?? 0;
  if (!(flags & FLAG_UP)) return { ok: false, reason: 'missing_user_presence' };
  if (!(flags & FLAG_UV)) return { ok: false, reason: 'user_not_verified' };
  if (flags & (FLAG_AT | FLAG_ED)) return { ok: false, reason: 'unexpected_flags' };
  const signCount = authData.readUInt32BE(33);
  let sigOk = false;
  try {
    const pub = createPublicKey({
      key: { kty: 'EC', crv: 'P-256', x: key.x, y: key.y },
      format: 'jwk',
    });
    const clientDataHash = createHash('sha256').update(clientDataBytes).digest();
    sigOk = verify(
      'sha256',
      Buffer.concat([authData, clientDataHash]),
      { key: pub, dsaEncoding: 'der' },
      signature,
    );
  } catch {
    sigOk = false;
  }
  if (!sigOk) return { ok: false, reason: 'bad_signature' };
  if (
    (signCount !== 0 || key.signCount !== 0) &&
    signCount <= key.signCount &&
    counterAccepted?.(approval) !== true
  ) {
    return { ok: false, reason: 'sign_count_regressed' };
  }
  return { ok: true, signCount };
}

export function webAuthnAssertionDigest(approval: WebAuthnApproval): string {
  const w = approval.webauthn;
  return sha256B64url(
    JSON.stringify([
      approval.approverKeyId,
      w.authenticatorData,
      w.clientDataJSON,
      w.signature,
      approval.statement.requestId,
    ]),
  );
}

export function verifyNativeApproval(
  approval: NativeApproval,
  key: NativeApproverKey,
): { ok: true } | { ok: false; reason: string } {
  const n = approval.native;
  if (!n || typeof n !== 'object' || typeof n.signature !== 'string') {
    return { ok: false, reason: 'bad_assertion' };
  }
  if (key.userVerification !== 'biometry') return { ok: false, reason: 'user_not_verified' };
  let bytes: Buffer;
  try {
    bytes = nativeApprovalSigningBytes(approval.statement);
  } catch {
    return { ok: false, reason: 'bad_statement' };
  }
  if (!verifyNativeSignature(key, bytes, n.signature))
    return { ok: false, reason: 'bad_signature' };
  return { ok: true };
}

export function approverDescriptor(k: {
  credentialId: string;
  x: string;
  y: string;
  rpId: string;
  origin: string;
}): string {
  return `aab-approver-add-v1\n${canonicalJson({
    credentialId: k.credentialId,
    origin: k.origin,
    rpId: k.rpId,
    x: k.x,
    y: k.y,
  })}`;
}

export function fillScope(fields: readonly FillField[]): string {
  const set = new Set(fields);
  return `aab-fill-v1\n${FILL_FIELDS.filter((f) => set.has(f)).join(',')}`;
}
