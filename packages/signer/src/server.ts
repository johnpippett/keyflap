import { createHash, createPublicKey, sign as cryptoSign, randomBytes } from 'node:crypto';
import { chmodSync, lstatSync, mkdirSync, unlinkSync } from 'node:fs';
import { connect, createServer, type Server, type Socket } from 'node:net';
import { dirname } from 'node:path';
import {
  type CredentialSource,
  SourceError,
  type SourceSecret,
  type ToolTrust,
} from '@aab/sources';
import {
  type ApprovalCheck,
  type ApprovalKind,
  type ApprovalStatement,
  approverDescriptor,
  FILL_FIELDS,
  type FillField,
  fillScope,
  type GrantedApproval,
  HANDOFF_GRANT_MAX_MS,
  handoffSignInClientDataHash,
  isGrantedApproval,
  isUserVerifiedMethod,
  MAX_APPROVAL_LIFETIME_MS,
  MAX_GRANT_MS,
  nativeApproverDescriptor,
  nativeKeyId,
  nativePairingProofBytes,
  type SignedApproval,
  type SignerAuthorization,
  sha256B64url,
  statementExtrasOk,
  type TrustedApproverKeys,
  verifyApproval,
  verifyNativeSignature,
  type WebAuthnApproval,
  type WebAuthnApproverKey,
  webAuthnAssertionDigest,
} from './approval.ts';
import {
  type AddressState,
  type ApproverAddress,
  ApproverAddressWatch,
} from './approver-address.ts';
import { fromB64url } from './b64url.ts';
import type { KeyStore } from './keystore.ts';
import { assertUnixSocketPath } from './platform.ts';
import {
  type Frame,
  type ListSourceItemsResult,
  macEquals,
  macFor,
  readFrames,
  type SignerRequest,
  type SignerResponse,
  writeFrame,
} from './protocol.ts';
import { loadPublicSuffixList, registrableDomain, rpIdAllowedForHost } from './psl.ts';
import {
  isHighRisk,
  isHighRiskOrigin,
  normalizeRiskDomain,
  STRONG_APPROVAL_MAX_LIFETIME_MS,
} from './risk.ts';
import { normalizeTotp, totpCode } from './totp.ts';

const FLAG_UP = 0x01;
const FLAG_UV = 0x04;
const FLAG_BE = 0x08;
const FLAG_BS = 0x10;
const FLAG_AT = 0x40;

export class SignerError extends Error {}

interface Grant {
  grantId: string;
  agentId: string;
  kind: 'webauthn.get' | 'fill';
  verifiedOrigin: string;
  rpId: string;
  credentialId: string;
  scope: FillField[];
  until: number;
  singleUse: boolean;
  usedBy: string | null;
  handoffId: string | null;
}

type Check = Extract<ApprovalCheck, { ok: true }> | { ok: true; method: 'grant'; grant: Grant };

const MAX_GRANTS = 256;
const CLOCK_SKEW_MS = 30_000;

export interface SignerHandlerOptions {
  store: KeyStore;
  trustedApproverKeys: TrustedApproverKeys;
  highRiskDomains?: readonly string[];
  approverAdmin?: boolean;
  sources?: readonly CredentialSource[];
  approverAddress?: { address: ApproverAddress; trust: ToolTrust };
  now?: () => number;
  log?: (event: string, fields: Record<string, unknown>) => void;
}

export class SignerHandler {
  private readonly store: KeyStore;
  private readonly trusted: TrustedApproverKeys;
  private readonly highRisk: readonly string[];
  private readonly approverAdmin: boolean;
  private readonly sources: ReadonlyMap<string, CredentialSource>;
  private readonly address: ApproverAddressWatch | null;
  private readonly startedAt: number;
  private readonly now: () => number;
  private readonly log: (event: string, fields: Record<string, unknown>) => void;
  private readonly usedApprovals = new Map<string, number>();
  private readonly grants = new Map<string, Grant>();
  private readonly acceptedFillAssertions = new Map<
    string,
    { digest: string; expiresAt: number }
  >();

  constructor(opts: SignerHandlerOptions) {
    loadPublicSuffixList();
    this.store = opts.store;
    this.trusted = opts.trustedApproverKeys;
    this.approverAdmin = opts.approverAdmin === true;
    this.sources = new Map((opts.sources ?? []).map((src) => [src.kind, src]));
    this.highRisk = (opts.highRiskDomains ?? []).map((d) => {
      const n = normalizeRiskDomain(d);
      if (!n) throw new Error('bad high-risk domain');
      return n;
    });
    this.now = opts.now ?? Date.now;
    this.startedAt = this.now();
    this.log = opts.log ?? (() => {});
    const aa = opts.approverAddress;
    this.address = aa
      ? new ApproverAddressWatch({
          address: aa.address,
          trust: aa.trust,
          trip: {
            get: () => this.store.addressTrip,
            set: (t) => this.store.setAddressTrip(t),
            clear: () => this.store.clearAddressTrip(),
          },
          onTripped: (seen) =>
            this.log('approver_address_tripped', { seen, approversRemoved: this.dropApprovers() }),
          log: this.log,
          now: this.now,
        })
      : null;
    if (this.address?.state().kind === 'latched') this.dropApprovers();
  }

  addressState(): AddressState {
    return this.address?.state() ?? { kind: 'unwatched' };
  }

  async startAddressWatch(): Promise<void> {
    await this.address?.start();
  }

  stopAddressWatch(): void {
    this.address?.stop();
  }

  async clearApproverAddress(): Promise<AddressState> {
    return this.address ? this.address.clear() : this.addressState();
  }

  private requireAddressOk(): void {
    const s = this.addressState();
    if (s.kind === 'latched') throw new SignerError('approver_address_latched');
    if (s.kind === 'paused') throw new SignerError('approver_address_unverified');
  }

  private dropApprovers(): number {
    const n = this.store.removeAllApprovers();
    this.grants.clear();
    this.acceptedFillAssertions.clear();
    return n;
  }

  async dispatch(req: SignerRequest): Promise<SignerResponse> {
    const source =
      req?.op === 'release_secret' ? this.sourceFor(req.itemId) : req?.op === 'list_source_items';
    if (!source && req?.op !== 'clear_approver_address') return this.handle(req);
    try {
      if (req.op === 'clear_approver_address') {
        if (!this.approverAdmin) throw new SignerError('admin_required');
        return { ok: true, result: { state: await this.clearApproverAddress() } };
      }
      if (req.op === 'list_source_items') {
        return { ok: true, result: await this.listSourceItems(req) };
      }
      if (req.op === 'release_secret' && typeof source === 'object' && source !== null) {
        return { ok: true, result: await this.releaseSourceSecret(req, source) };
      }
      return { ok: false, error: 'unknown_op' };
    } catch (err) {
      const reason = err instanceof SignerError ? err.message : 'internal_error';
      this.log('denied', { op: req.op, reason });
      return { ok: false, error: reason };
    }
  }

  handle(req: SignerRequest): SignerResponse {
    try {
      switch (req?.op) {
        case 'ping':
          return { ok: true, result: { pong: true } };
        case 'create_credential':
          return { ok: true, result: this.createCredential(req) };
        case 'sign':
          return { ok: true, result: this.sign(req) };
        case 'store_item':
          return { ok: true, result: this.storeItem(req) };
        case 'delete_item':
          return { ok: true, result: this.deleteItem(req) };
        case 'release_secret':
          return { ok: true, result: this.releaseSecret(req) };
        case 'list_approvers':
          return {
            ok: true,
            result: { approvers: this.store.approvers(), native: this.store.nativeApprovers() },
          };
        case 'add_approver':
          return { ok: true, result: this.addApprover(req) };
        case 'add_native_approver':
          return { ok: true, result: this.addNativeApprover(req) };
        case 'remove_approver':
          return { ok: true, result: this.removeApprover(req) };
        case 'accept_handoff_grant':
          return { ok: true, result: this.acceptHandoffGrant(req) };
        case 'drop_grant':
          return { ok: true, result: this.dropGrant(req) };
        case 'browser_state_key':
          this.log('browser_state_key', {});
          return { ok: true, result: { key: this.store.browserStateKey().toString('base64url') } };
        case 'approver_address':
          this.address?.report(req.pending === true);
          return { ok: true, result: { state: this.addressState() } };
        default:
          return { ok: false, error: 'unknown_op' };
      }
    } catch (err) {
      const reason = err instanceof SignerError ? err.message : 'internal_error';
      this.log('denied', { op: (req as { op?: unknown })?.op, reason });
      return { ok: false, error: reason };
    }
  }

  private createCredential(req: Extract<SignerRequest, { op: 'create_credential' }>) {
    const { rpId, userHandle } = str(req, 'rpId', 'userHandle');
    const check = this.checkApproval(req.approval, {
      kind: 'webauthn.create',
      rpId,
      credentialId: null,
      clientDataJSON: req.clientDataJSON,
    });
    const handleLen = fromB64url(userHandle).length;
    if (handleLen === 0 || handleLen > 64) {
      throw new SignerError('bad_user_handle');
    }
    this.consume(req.approval, check);
    const { credentialId, x, y } = this.store.createP256(rpId, userHandle);
    this.log('created', { rpId, credentialId, requestId: req.approval.statement.requestId });
    return { credentialId, publicKey: { x, y } };
  }

  private sign(req: Extract<SignerRequest, { op: 'sign' }>) {
    const { credentialId, authenticatorData } = str(req, 'credentialId', 'authenticatorData');
    const cred = this.store.get(credentialId);
    if (!cred) throw new SignerError('unknown_credential');
    const approval = req.approval;
    const check = this.checkApproval(approval, {
      kind: 'webauthn.get',
      rpId: cred.rpId,
      credentialId,
      clientDataJSON: req.clientDataJSON,
    });

    const authData = fromB64url(authenticatorData);
    if (authData.length !== 37) throw new SignerError('bad_authenticator_data');
    const rpIdHash = createHash('sha256').update(cred.rpId).digest();
    if (!authData.subarray(0, 32).equals(rpIdHash)) throw new SignerError('rp_id_hash_mismatch');
    const flags = authData[32] ?? 0;
    if (!(flags & FLAG_UP)) throw new SignerError('missing_user_presence');
    if (flags & FLAG_UV && !approval.statement.userVerified) {
      throw new SignerError('uv_not_approved');
    }
    if (
      flags & (FLAG_BE | FLAG_BS | FLAG_AT) ||
      flags & ~(FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS | FLAG_AT)
    ) {
      throw new SignerError('unexpected_flags');
    }

    this.consume(approval, check);
    this.recordGrant(approval.statement, check, []);
    const key = this.store.privateKeyFor(credentialId);
    if (!key) throw new SignerError('unknown_credential');
    const clientDataHash = createHash('sha256').update(fromB64url(req.clientDataJSON)).digest();
    const signature = cryptoSign('sha256', Buffer.concat([authData, clientDataHash]), {
      key,
      dsaEncoding: 'der',
    });
    this.log('signed', { rpId: cred.rpId, credentialId, requestId: approval.statement.requestId });
    return { signature: signature.toString('base64url') };
  }

  private storeItem(req: Extract<SignerRequest, { op: 'store_item' }>) {
    const { domain } = str(req, 'domain');
    if (registrableDomain(domain) !== domain) throw new SignerError('bad_domain');
    const password = req.password;
    if (!validPassword(password)) throw new SignerError('bad_password');
    let totp: ReturnType<typeof normalizeTotp> | undefined;
    if (req.totp !== undefined) {
      totp = normalizeTotp(req.totp);
      if (!totp) throw new SignerError('bad_totp');
    }
    const itemId = this.store.addItem({ domain, password, ...(totp ? { totp } : {}) });
    this.log('item_stored', { itemId, domain, totp: totp !== undefined });
    return { itemId };
  }

  private deleteItem(req: Extract<SignerRequest, { op: 'delete_item' }>) {
    const { itemId } = str(req, 'itemId');
    const deleted = this.store.deleteItem(itemId);
    if (deleted) this.log('item_deleted', { itemId });
    return { deleted };
  }

  private releaseSecret(req: Extract<SignerRequest, { op: 'release_secret' }>) {
    const { itemId } = str(req, 'itemId');
    const field = req.field;
    if (!FILL_FIELDS.includes(field)) throw new SignerError('bad_field');
    const item = this.store.item(itemId);
    if (!item) throw new SignerError('unknown_item');
    const approval = req.approval;
    const now = this.now();
    const sig = this.verify(approval, now);
    const s = approval.statement;
    if (s.kind !== 'fill') throw new SignerError('approval_kind_mismatch');
    if (s.credentialId !== itemId) throw new SignerError('approval_credential_mismatch');
    if (s.rpId !== item.domain) throw new SignerError('approval_rp_mismatch');
    if (typeof s.intentHash !== 'string' || s.intentHash.length === 0) {
      throw new SignerError('approval_missing_intent');
    }
    if (!rpIdOk(s.verifiedOrigin, item.domain)) {
      throw new SignerError('origin_not_within_rp_id');
    }
    const scope = parseScope(s.clientDataHash);
    if (!scope.includes(field)) throw new SignerError('field_not_approved');
    if (field === 'totp' && !item.totp) throw new SignerError('no_totp');
    this.requireStrongIfHighRisk(sig, s, item.domain);
    this.checkGrant(sig, s, item.domain, scope);
    const key = `${s.requestId}\nfill:${field}`;
    if (this.usedApprovals.has(key) || this.usedApprovals.has(s.requestId)) {
      throw new SignerError('approval_replayed');
    }
    this.consumeKey(key, s.expiresAt);
    this.recordSignCount(sig);
    this.rememberFillAssertion(approval, sig);
    this.recordGrant(s, sig, scope);
    const value =
      field === 'password'
        ? item.password
        : totpCode(item.totp as NonNullable<typeof item.totp>, now);
    this.log('released', { itemId, field, requestId: s.requestId });
    return { value };
  }

  private sourceFor(itemId: unknown): CredentialSource | null {
    if (typeof itemId !== 'string') return null;
    const i = itemId.indexOf(':');
    return i > 0 ? (this.sources.get(itemId.slice(0, i)) ?? null) : null;
  }

  private async listSourceItems(
    req: Extract<SignerRequest, { op: 'list_source_items' }>,
  ): Promise<ListSourceItemsResult> {
    const src = typeof req.source === 'string' ? this.sources.get(req.source) : undefined;
    if (!src) throw new SignerError('unknown_source');
    let items: Awaited<ReturnType<CredentialSource['list']>>;
    try {
      items = await src.list();
    } catch (err) {
      throw new SignerError(err instanceof SourceError ? err.reason : 'source_failed');
    }
    return {
      items: items.map((i) => ({
        ref: i.ref,
        hosts: [...i.hosts],
        username: i.username,
        hasTotp: i.hasTotp === true,
      })),
    };
  }

  private async releaseSourceSecret(
    req: Extract<SignerRequest, { op: 'release_secret' }>,
    src: CredentialSource,
  ) {
    const { itemId } = str(req, 'itemId');
    const field = req.field;
    if (!FILL_FIELDS.includes(field)) throw new SignerError('bad_field');
    const approval = req.approval;
    const sig = this.verify(approval, this.now());
    const s = approval.statement;
    if (s.kind !== 'fill') throw new SignerError('approval_kind_mismatch');
    if (s.credentialId !== itemId) throw new SignerError('approval_credential_mismatch');
    if (typeof s.intentHash !== 'string' || s.intentHash.length === 0) {
      throw new SignerError('approval_missing_intent');
    }
    if (typeof s.rpId !== 'string' || registrableDomain(s.rpId) !== s.rpId) {
      throw new SignerError('approval_rp_mismatch');
    }
    if (!sourceRpIdOk(s.verifiedOrigin, s.rpId)) throw new SignerError('origin_not_within_rp_id');
    const scope = parseScope(s.clientDataHash);
    if (!scope.includes(field)) throw new SignerError('field_not_approved');
    this.requireStrongIfHighRisk(sig, s, s.rpId);
    this.checkGrant(sig, s, s.rpId, scope);
    const key = `${s.requestId}\nfill:${field}`;
    if (this.usedApprovals.has(key) || this.usedApprovals.has(s.requestId)) {
      throw new SignerError('approval_replayed');
    }
    this.consumeKey(key, s.expiresAt);
    this.recordSignCount(sig);
    this.rememberFillAssertion(approval, sig);

    let secret: SourceSecret;
    try {
      secret = await src.fetch(itemId, `Keyflap broker: approved sign-in on ${s.verifiedOrigin}`);
    } catch (err) {
      throw new SignerError(err instanceof SourceError ? err.reason : 'source_failed');
    }
    const hosts = Array.isArray(secret.hosts)
      ? secret.hosts.filter((h): h is string => typeof h === 'string')
      : [];
    if (!hosts.some((h) => registrableDomain(h) === s.rpId)) {
      throw new SignerError('item_not_for_domain');
    }
    for (const h of hosts) {
      this.requireStrongIfHighRisk(sig, s, h);
      this.checkGrant(sig, s, h, scope);
    }
    this.recordGrant(s, sig, scope);
    let value: string;
    if (field === 'password') {
      if (!validPassword(secret.password)) throw new SignerError('bad_password');
      value = secret.password;
    } else {
      const totp = secret.totp ? normalizeTotp(secret.totp) : null;
      if (!totp) throw new SignerError('no_totp');
      value = totpCode(totp, this.now());
    }
    this.log('released', { itemId, field, requestId: s.requestId, source: src.kind });
    return { value };
  }

  private checkApproval(
    approval: SignerAuthorization,
    expect: {
      kind: ApprovalKind;
      rpId: string;
      credentialId: string | null;
      clientDataJSON: string;
    },
  ): Check {
    const now = this.now();
    const sig = this.verify(approval, now);
    const s = approval.statement;
    if (s.kind !== expect.kind) throw new SignerError('approval_kind_mismatch');
    if (s.rpId !== expect.rpId) throw new SignerError('approval_rp_mismatch');
    if (s.credentialId !== expect.credentialId)
      throw new SignerError('approval_credential_mismatch');
    if (typeof s.intentHash !== 'string' || s.intentHash.length === 0) {
      throw new SignerError('approval_missing_intent');
    }
    const used = this.usedApprovals.get(s.requestId);
    if (used !== undefined) throw new SignerError('approval_replayed');
    for (const f of FILL_FIELDS) {
      if (this.usedApprovals.has(`${s.requestId}\nfill:${f}`)) {
        throw new SignerError('approval_replayed');
      }
    }

    if (typeof expect.clientDataJSON !== 'string') throw new SignerError('bad_client_data');
    const clientDataBytes = fromB64url(expect.clientDataJSON);
    if (sha256B64url(clientDataBytes) !== s.clientDataHash) {
      throw new SignerError('client_data_hash_mismatch');
    }
    let clientData: {
      type?: unknown;
      origin?: unknown;
      crossOrigin?: unknown;
      challenge?: unknown;
    };
    try {
      clientData = JSON.parse(clientDataBytes.toString('utf8'));
    } catch {
      throw new SignerError('bad_client_data');
    }
    if (clientData.type !== expect.kind) throw new SignerError('client_data_type_mismatch');
    if (clientData.origin !== s.verifiedOrigin)
      throw new SignerError('client_data_origin_mismatch');
    if (clientData.crossOrigin !== false) throw new SignerError('cross_origin_not_allowed');
    if (typeof clientData.challenge !== 'string' || clientData.challenge.length === 0) {
      throw new SignerError('bad_client_data');
    }
    if (!rpIdOk(s.verifiedOrigin, s.rpId)) throw new SignerError('origin_not_within_rp_id');
    this.requireStrongIfHighRisk(sig, s, s.rpId);
    this.checkGrant(sig, s, s.rpId, []);
    return sig;
  }

  private verify(approval: SignerAuthorization, now: number, o: { handoff?: boolean } = {}): Check {
    this.requireAddressOk();
    if (isGrantedApproval(approval)) return this.verifyGrantUse(approval, now);
    if (
      o.handoff !== true &&
      approval &&
      typeof approval === 'object' &&
      approval.statement &&
      typeof approval.statement === 'object' &&
      approval.statement.handoff !== undefined
    ) {
      throw new SignerError('handoff_approval_not_an_operation');
    }
    const latched = this.store.phoneLatched || this.store.approverCount > 0;
    const sig = verifyApproval(
      approval,
      {
        ed25519: latched ? {} : this.trusted,
        webauthn: (id) => this.store.approver(id),
        native: (id) => this.store.nativeApprover(id),
        counterAccepted: (a) => this.isAcceptedFillAssertion(a),
      },
      now,
    );
    if (!sig.ok) throw new SignerError(sig.reason);
    if (approval.statement.issuedAt < this.startedAt) {
      throw new SignerError('issued_before_signer_start');
    }
    if (sig.method === 'ed25519' && approval.statement.userVerified !== false) {
      throw new SignerError('uv_requires_phone_approver');
    }
    return sig;
  }

  private verifyGrantUse(a: GrantedApproval, now: number): Check {
    const s = a.statement;
    if (
      a.approverKeyId !== undefined ||
      a.signature !== undefined ||
      a.webauthn !== undefined ||
      (a as { native?: unknown }).native !== undefined ||
      typeof a.grantId !== 'string' ||
      typeof a.agentId !== 'string' ||
      !s ||
      typeof s !== 'object' ||
      s.v !== 1 ||
      !statementExtrasOk(s) ||
      typeof s.issuedAt !== 'number' ||
      typeof s.expiresAt !== 'number'
    ) {
      throw new SignerError('bad_statement');
    }
    const g = this.grants.get(a.grantId);
    if (!g) throw new SignerError('unknown_grant');
    if (now > g.until) {
      this.grants.delete(g.grantId);
      throw new SignerError('grant_expired');
    }
    if (s.expiresAt - s.issuedAt > MAX_APPROVAL_LIFETIME_MS) {
      throw new SignerError('lifetime_too_long');
    }
    if (now > s.expiresAt) throw new SignerError('expired');
    if (now + CLOCK_SKEW_MS < s.issuedAt) throw new SignerError('not_yet_valid');
    if (
      s.strong !== undefined ||
      s.grant !== undefined ||
      s.keepSignedIn !== undefined ||
      s.handoff !== undefined
    ) {
      throw new SignerError('bad_statement');
    }
    if (s.userVerified !== false) throw new SignerError('uv_requires_phone_approver');
    if (a.agentId !== g.agentId) throw new SignerError('grant_agent_mismatch');
    if (s.kind !== g.kind) throw new SignerError('grant_kind_mismatch');
    if (s.verifiedOrigin !== g.verifiedOrigin) throw new SignerError('grant_origin_mismatch');
    if (s.rpId !== g.rpId) throw new SignerError('grant_rp_mismatch');
    if (s.credentialId !== g.credentialId) throw new SignerError('grant_credential_mismatch');
    if (g.kind === 'fill') {
      const scope = parseScope(s.clientDataHash);
      if (scope.length === 0 || !scope.every((f) => g.scope.includes(f))) {
        throw new SignerError('grant_scope_mismatch');
      }
    }
    if (g.singleUse) {
      if (typeof s.requestId !== 'string' || s.requestId.length === 0) {
        throw new SignerError('bad_statement');
      }
      if (g.usedBy !== null && g.usedBy !== s.requestId) throw new SignerError('grant_used');
      if (g.usedBy === null) {
        g.usedBy = s.requestId;
        this.log('grant_spent', { grantId: g.grantId, requestId: s.requestId });
      }
    }
    return { ok: true, method: 'grant', grant: g };
  }

  private acceptHandoffGrant(req: Extract<SignerRequest, { op: 'accept_handoff_grant' }>) {
    const approval = req.approval as SignedApproval;
    if (!approval || typeof approval !== 'object' || isGrantedApproval(approval)) {
      throw new SignerError('bad_approval');
    }
    const now = this.now();
    const sig = this.verify(approval, now, { handoff: true });
    if (!isUserVerifiedMethod(sig.method)) throw new SignerError('user_verification_required');
    const s = approval.statement;
    const g = s.grant;
    if (s.handoff === undefined || g === undefined || g.uses !== 1) {
      throw new SignerError('bad_statement');
    }
    if (s.kind !== 'webauthn.get' && s.kind !== 'fill') throw new SignerError('grant_not_allowed');
    if (typeof s.credentialId !== 'string' || s.credentialId.length === 0) {
      throw new SignerError('approval_credential_mismatch');
    }
    if (typeof s.intentHash !== 'string' || s.intentHash.length === 0) {
      throw new SignerError('approval_missing_intent');
    }
    if (typeof s.rpId !== 'string' || s.rpId.length === 0) {
      throw new SignerError('approval_rp_mismatch');
    }
    if (!rpIdOk(s.verifiedOrigin, s.rpId)) throw new SignerError('origin_not_within_rp_id');
    let scope: FillField[] = [];
    if (s.kind === 'webauthn.get') {
      const cred = this.store.get(s.credentialId);
      if (!cred) throw new SignerError('unknown_credential');
      if (cred.rpId !== s.rpId) throw new SignerError('approval_rp_mismatch');
      if (s.clientDataHash !== handoffSignInClientDataHash(s.handoff.id)) {
        throw new SignerError('client_data_hash_mismatch');
      }
    } else {
      scope = parseScope(s.clientDataHash);
      if (scope.length === 0) throw new SignerError('field_not_approved');
      if (this.sourceFor(s.credentialId)) {
        if (!sourceRpIdOk(s.verifiedOrigin, s.rpId)) throw new SignerError('approval_rp_mismatch');
      } else {
        const item = this.store.item(s.credentialId);
        if (!item) throw new SignerError('unknown_item');
        if (item.domain !== s.rpId) throw new SignerError('approval_rp_mismatch');
        if (scope.includes('totp') && !item.totp) throw new SignerError('no_totp');
      }
    }
    this.requireStrongIfHighRisk(sig, s, s.rpId);
    this.checkGrant(sig, s, s.rpId, scope);
    if (g.until - s.issuedAt > HANDOFF_GRANT_MAX_MS) throw new SignerError('grant_not_allowed');
    if (this.usedApprovals.has(s.requestId)) throw new SignerError('approval_replayed');
    for (const f of FILL_FIELDS) {
      if (this.usedApprovals.has(`${s.requestId}\nfill:${f}`)) {
        throw new SignerError('approval_replayed');
      }
    }
    this.consume(approval, sig);
    this.recordGrant(s, sig, scope);
    return { grantId: s.requestId, until: g.until };
  }

  private dropGrant(req: Extract<SignerRequest, { op: 'drop_grant' }>) {
    const { grantId } = str(req, 'grantId');
    const dropped = this.grants.delete(grantId);
    if (dropped) this.log('grant_dropped', { grantId });
    return { dropped };
  }

  private requireStrongIfHighRisk(sig: Check, s: ApprovalStatement, domain: string): void {
    if (
      s.strong !== true &&
      !isHighRisk(domain, this.highRisk) &&
      !isHighRiskOrigin(s.verifiedOrigin, this.highRisk)
    ) {
      return;
    }
    if (!isUserVerifiedMethod(sig.method)) throw new SignerError('user_verification_required');
    if (s.expiresAt - s.issuedAt > STRONG_APPROVAL_MAX_LIFETIME_MS) {
      throw new SignerError('lifetime_too_long');
    }
  }

  private checkGrant(sig: Check, s: ApprovalStatement, domain: string, scope: FillField[]): void {
    const g = s.grant;
    if (g === undefined) return;
    if (
      sig.method === 'grant' ||
      (s.kind !== 'webauthn.get' && s.kind !== 'fill') ||
      (s.kind === 'fill' && scope.length === 0) ||
      typeof s.credentialId !== 'string' ||
      s.strong === true ||
      isHighRisk(domain, this.highRisk) ||
      isHighRiskOrigin(s.verifiedOrigin, this.highRisk) ||
      g.until <= s.issuedAt ||
      g.until - s.issuedAt > MAX_GRANT_MS
    ) {
      throw new SignerError('grant_not_allowed');
    }
  }

  private recordGrant(s: ApprovalStatement, sig: Check, scope: FillField[]): void {
    const g = s.grant;
    if (g === undefined || sig.method === 'grant' || this.grants.has(s.requestId)) return;
    const now = this.now();
    for (const [id, x] of this.grants) if (x.until < now) this.grants.delete(id);
    while (this.grants.size >= MAX_GRANTS) {
      const oldest = this.grants.keys().next().value as string;
      this.grants.delete(oldest);
    }
    const single = g.uses === 1 && s.handoff !== undefined;
    this.grants.set(s.requestId, {
      grantId: s.requestId,
      agentId: g.agentId,
      kind: s.kind as Grant['kind'],
      verifiedOrigin: s.verifiedOrigin,
      rpId: s.rpId,
      credentialId: s.credentialId as string,
      scope: [...scope],
      until: g.until,
      singleUse: single,
      usedBy: null,
      handoffId: single ? (s.handoff?.id ?? null) : null,
    });
    this.log('grant_recorded', {
      grantId: s.requestId,
      agentId: g.agentId,
      kind: s.kind,
      rpId: s.rpId,
      until: g.until,
      ...(single ? { singleUse: true, handoffId: s.handoff?.id } : {}),
    });
  }

  private recordSignCount(sig: Check): void {
    if (sig.method === 'webauthn') {
      this.store.setApproverSignCount(sig.key.credentialId, sig.signCount);
    }
  }

  private rememberFillAssertion(approval: SignerAuthorization, sig: Check): void {
    if (sig.method !== 'webauthn' || approval.statement.kind !== 'fill') return;
    const now = this.now();
    for (const [id, x] of this.acceptedFillAssertions) {
      if (x.expiresAt < now) this.acceptedFillAssertions.delete(id);
    }
    this.acceptedFillAssertions.set(approval.statement.requestId, {
      digest: webAuthnAssertionDigest(approval as WebAuthnApproval),
      expiresAt: approval.statement.expiresAt,
    });
  }

  private isAcceptedFillAssertion(approval: WebAuthnApproval): boolean {
    const s = approval.statement;
    if (s.kind !== 'fill') return false;
    const e = this.acceptedFillAssertions.get(s.requestId);
    return (
      e !== undefined && this.now() <= e.expiresAt && e.digest === webAuthnAssertionDigest(approval)
    );
  }

  private consume(approval: SignerAuthorization, sig: Check): void {
    this.consumeKey(approval.statement.requestId, approval.statement.expiresAt);
    this.recordSignCount(sig);
  }

  private addApprover(req: Extract<SignerRequest, { op: 'add_approver' }>) {
    this.requireAddressOk();
    const k = req.key as Partial<WebAuthnApproverKey> | undefined;
    const { credentialId, x, y, rpId, origin } = str(k, 'credentialId', 'x', 'y', 'rpId', 'origin');
    if (!/^[A-Za-z0-9_-]{16,1023}$/.test(credentialId)) throw new SignerError('bad_credentialId');
    try {
      const jwk = { kty: 'EC', crv: 'P-256', x, y };
      createPublicKey({ key: jwk, format: 'jwk' });
    } catch {
      throw new SignerError('bad_public_key');
    }
    let url: URL;
    try {
      url = new URL(origin);
    } catch {
      throw new SignerError('bad_origin');
    }
    const local = url.hostname === 'localhost' || url.hostname.endsWith('.localhost');
    if (
      url.origin !== origin ||
      !(url.protocol === 'https:' || (url.protocol === 'http:' && local)) ||
      !rpIdOk(origin, rpId)
    ) {
      throw new SignerError('bad_origin');
    }
    if (this.store.approver(credentialId) || this.store.nativeApprover(credentialId)) {
      throw new SignerError('approver_exists');
    }
    const first = this.store.approverCount === 0;
    if (this.store.approverCount > 0 || this.store.phoneLatched) {
      const approval = req.approval as SignedApproval;
      const sig = this.verify(approval, this.now());
      if (!isUserVerifiedMethod(sig.method)) throw new SignerError('approver_add_needs_phone');
      const s = approval.statement;
      if (s.kind !== 'approver.add') throw new SignerError('approval_kind_mismatch');
      if (s.credentialId !== credentialId) throw new SignerError('approval_credential_mismatch');
      if (s.rpId !== rpId || s.verifiedOrigin !== origin) {
        throw new SignerError('approval_rp_mismatch');
      }
      const descriptor = approverDescriptor({ credentialId, x, y, rpId, origin });
      if (s.clientDataHash !== sha256B64url(descriptor)) {
        throw new SignerError('client_data_hash_mismatch');
      }
      if (this.usedApprovals.has(s.requestId)) throw new SignerError('approval_replayed');
      this.consume(approval, sig);
    }
    this.store.addApprover({
      credentialId,
      x,
      y,
      rpId,
      origin,
      signCount: 0,
      createdAt: this.now(),
    });
    this.log('approver_added', { credentialId, rpId, first });
    return { added: true };
  }

  private addNativeApprover(req: Extract<SignerRequest, { op: 'add_native_approver' }>) {
    this.requireAddressOk();
    const k = req.key as Partial<Extract<SignerRequest, { op: 'add_native_approver' }>['key']>;
    const { x, y, origin } = str(k, 'x', 'y', 'origin');
    if (k?.userVerification !== 'biometry') throw new SignerError('user_verification_required');
    let keyId: string;
    try {
      keyId = nativeKeyId(x, y);
      createPublicKey({ key: { kty: 'EC', crv: 'P-256', x, y }, format: 'jwk' });
    } catch {
      throw new SignerError('bad_public_key');
    }
    let url: URL;
    try {
      url = new URL(origin);
    } catch {
      throw new SignerError('bad_origin');
    }
    const local = url.hostname === 'localhost' || url.hostname.endsWith('.localhost');
    if (
      url.origin !== origin ||
      !(url.protocol === 'https:' || (url.protocol === 'http:' && local))
    ) {
      throw new SignerError('bad_origin');
    }
    const key = { keyId, x, y, origin, userVerification: 'biometry' as const };
    const descriptor = nativeApproverDescriptor(key);
    if (!verifyNativeSignature(key, nativePairingProofBytes(descriptor), req.proof)) {
      throw new SignerError('bad_proof');
    }
    if (this.store.nativeApprover(keyId) || this.store.approver(keyId)) {
      throw new SignerError('approver_exists');
    }
    const first = this.store.approverCount === 0;
    if (!first || this.store.phoneLatched) {
      const approval = req.approval as SignedApproval;
      const sig = this.verify(approval, this.now());
      if (!isUserVerifiedMethod(sig.method)) throw new SignerError('approver_add_needs_phone');
      const s = approval.statement;
      if (s.kind !== 'approver.add') throw new SignerError('approval_kind_mismatch');
      if (s.credentialId !== keyId) throw new SignerError('approval_credential_mismatch');
      if (s.rpId !== url.hostname || s.verifiedOrigin !== origin) {
        throw new SignerError('approval_rp_mismatch');
      }
      if (s.clientDataHash !== sha256B64url(descriptor)) {
        throw new SignerError('client_data_hash_mismatch');
      }
      if (this.usedApprovals.has(s.requestId)) throw new SignerError('approval_replayed');
      this.consume(approval, sig);
    }
    this.store.addNativeApprover({ ...key, createdAt: this.now() });
    this.log('approver_added', { keyId, origin, native: true, first });
    return { added: true as const, keyId };
  }

  private removeApprover(
    req: Extract<SignerRequest, { op: 'remove_approver' }>,
    admin: boolean = this.approverAdmin,
  ) {
    const { credentialId } = str(req, 'credentialId');
    const a = this.store.approver(credentialId) ?? this.store.nativeApprover(credentialId);
    if (a && this.store.approverCount === 1 && !admin) {
      throw new SignerError('last_approver_needs_admin');
    }
    const removed = this.store.removeApprover(credentialId, admin);
    if (removed) this.log('approver_removed', { credentialId });
    return { removed };
  }

  admin(op: string, params: Record<string, unknown>): Record<string, unknown> {
    switch (op) {
      case 'status':
        return {
          approvers: this.store.approverCount,
          phoneLatched: this.store.phoneLatched,
          sources: [...this.sources.keys()],
          address: this.addressState(),
        };
      case 'approver.list':
        return {
          approvers: this.store.approvers().map((a) => ({
            credentialId: a.credentialId,
            rpId: a.rpId,
            origin: a.origin,
            createdAt: a.createdAt,
          })),
          native: this.store.nativeApprovers().map((a) => ({
            keyId: a.keyId,
            origin: a.origin,
            createdAt: a.createdAt,
          })),
        };
      case 'approver.remove': {
        const res = this.removeApprover(
          { op: 'remove_approver', credentialId: params.credentialId as string },
          true,
        );
        this.log('admin_approver_removed', {
          credentialId: params.credentialId,
          removed: res.removed,
        });
        return res;
      }
      default:
        throw new SignerError('unknown_op');
    }
  }

  private consumeKey(key: string, expiresAt: number): void {
    const now = this.now();
    for (const [id, exp] of this.usedApprovals) if (exp < now) this.usedApprovals.delete(id);
    this.usedApprovals.set(key, expiresAt);
  }
}

function parseScope(hash: unknown): FillField[] {
  if (typeof hash !== 'string') return [];
  const subsets: FillField[][] = [['password'], ['totp'], ['password', 'totp']];
  return subsets.find((f) => sha256B64url(fillScope(f)) === hash) ?? [];
}

export function validPassword(p: unknown): p is string {
  return typeof p === 'string' && p.length >= 4 && p.length <= 1024 && !p.includes('\u0000');
}

function originHost(origin: unknown): string | null {
  if (typeof origin !== 'string') return null;
  try {
    const url = new URL(origin);
    return url.origin === origin ? url.hostname : null;
  } catch {
    return null;
  }
}

function rpIdOk(origin: string, rpId: unknown): boolean {
  const host = originHost(origin);
  return host !== null && typeof rpId === 'string' && rpIdAllowedForHost(rpId, host);
}

function sourceRpIdOk(origin: string, rpId: unknown): boolean {
  const host = originHost(origin);
  return host !== null && typeof rpId === 'string' && registrableDomain(host) === rpId;
}

function str<K extends string>(obj: unknown, ...keys: K[]): Record<K, string> {
  const out = {} as Record<K, string>;
  for (const k of keys) {
    const v = (obj as Record<string, unknown>)?.[k];
    if (typeof v !== 'string' || v.length === 0 || v.length > 4096) {
      throw new SignerError(`bad_${k}`);
    }
    out[k] = v;
  }
  return out;
}

export interface SignerServerOptions {
  socketPath?: string;
  listenFd?: number;
  channelKey: Buffer;
  handler: SignerHandler;
  log?: (event: string, fields: Record<string, unknown>) => void;
  handshakeTimeoutMs?: number;
}

const DEFAULT_HANDSHAKE_TIMEOUT_MS = 10_000;

export async function startSignerServer(opts: SignerServerOptions): Promise<Server> {
  if (opts.channelKey.length < 32) throw new Error('channel key too short');
  if ((opts.socketPath === undefined) === (opts.listenFd === undefined)) {
    throw new Error('pass exactly one of socketPath / listenFd');
  }
  const socketPath = opts.socketPath;
  if (socketPath !== undefined) {
    assertUnixSocketPath(socketPath, 'signer socket');
    const dir = dirname(socketPath);
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    chmodSync(dir, 0o700);
    await removeStaleSocket(socketPath);
  }
  const log = opts.log ?? (() => {});
  const handshakeTimeoutMs = opts.handshakeTimeoutMs ?? DEFAULT_HANDSHAKE_TIMEOUT_MS;
  const server = createServer((socket) =>
    serveConnection(socket, opts.channelKey, opts.handler, log, handshakeTimeoutMs),
  );
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    if (socketPath !== undefined) server.listen(socketPath, () => resolve());
    else server.listen({ fd: opts.listenFd as number }, () => resolve());
  });
  if (socketPath !== undefined) chmodSync(socketPath, 0o600);
  return server;
}

async function removeStaleSocket(path: string): Promise<void> {
  let isSocket: boolean;
  try {
    isSocket = lstatSync(path).isSocket();
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return;
    throw err;
  }
  if (!isSocket) throw new Error('socket path exists and is not a socket');
  const state = await new Promise<'live' | 'stale'>((resolve, reject) => {
    const probe = connect(path);
    const timer = setTimeout(() => {
      probe.destroy();
      resolve('live');
    }, 2_000);
    probe.once('connect', () => {
      clearTimeout(timer);
      probe.destroy();
      resolve('live');
    });
    probe.once('error', (err: NodeJS.ErrnoException) => {
      clearTimeout(timer);
      probe.destroy();
      if (err.code === 'ECONNREFUSED' || err.code === 'ENOENT') resolve('stale');
      else reject(err);
    });
  });
  if (state === 'live') throw new Error('another signer is already listening on the socket path');
  try {
    unlinkSync(path);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
  }
}

function serveConnection(
  socket: Socket,
  key: Buffer,
  handler: SignerHandler,
  log: (event: string, fields: Record<string, unknown>) => void,
  handshakeTimeoutMs: number,
): void {
  const nonce = randomBytes(32).toString('base64url');
  let lastSeq = 0;

  const reject = (reason: string) => {
    log('channel_rejected', { reason });
    socket.destroy();
  };

  let handshakeTimer: ReturnType<typeof setTimeout> | undefined = setTimeout(
    () => reject('handshake_timeout'),
    handshakeTimeoutMs,
  );
  const clearHandshake = () => {
    if (handshakeTimer !== undefined) clearTimeout(handshakeTimer);
    handshakeTimer = undefined;
  };
  socket.on('close', clearHandshake);
  socket.on('error', () => socket.destroy());
  writeFrame(socket, { t: 'hello', nonce });
  readFrames(
    socket,
    (frame: Frame) => {
      if (frame.t !== 'req' || typeof frame.body !== 'string' || typeof frame.mac !== 'string') {
        return reject('bad_frame');
      }
      if (!Number.isInteger(frame.seq) || frame.seq !== lastSeq + 1) return reject('bad_seq');
      if (!macEquals(frame.mac, macFor(key, 'req', nonce, frame.seq, frame.body))) {
        return reject('bad_mac');
      }
      lastSeq = frame.seq;
      clearHandshake();
      const seq = frame.seq;
      const respond = (res: SignerResponse) => {
        if (socket.destroyed) return;
        const body = JSON.stringify(res);
        writeFrame(socket, { t: 'res', seq, body, mac: macFor(key, 'res', nonce, seq, body) });
      };
      let req: SignerRequest;
      try {
        req = JSON.parse(frame.body) as SignerRequest;
      } catch {
        return respond({ ok: false, error: 'bad_request' });
      }
      handler
        .dispatch(req)
        .catch((): SignerResponse => ({ ok: false, error: 'internal_error' }))
        .then(respond);
    },
    (err) => reject(err.message),
  );
}
