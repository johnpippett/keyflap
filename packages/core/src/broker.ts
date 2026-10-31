import { randomUUID } from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';
import type { ApprovalRequest, Approver } from '@aab/approver';
import {
  AAGUID_NONE,
  b64url,
  buildAuthenticatorData,
  buildClientDataJSON,
  buildNoneAttestationObject,
  COSE_ALG_ES256,
  coseEs256PublicKey,
  FLAG_AT,
  FLAG_UP,
  FLAG_UV,
  type ShimWebAuthnRequest,
  type ShimWebAuthnResult,
  spkiP256,
} from '@aab/shim';
import type {
  ApprovalStatement,
  FillField,
  SignedApproval,
  SignerAuthorization,
} from '@aab/signer/approval';
import {
  fillScope,
  HANDOFF_GRANT_MAX_MS,
  handoffSignInClientDataHash,
  isGrantedApproval,
  sha256B64url,
} from '@aab/signer/approval';
import { SignerDenied } from '@aab/signer/client';
import type { CreateCredentialResult, ReleaseSecretResult, SignResult } from '@aab/signer/protocol';
import { isHighRisk, isHighRiskOrigin } from '@aab/signer/risk';
import { AgentRegistry } from './agents.ts';
import { AuditLog } from './audit.ts';
import { CredentialRepo, type PasswordRow, RequestRepo } from './db.ts';
import { type CoreGrant, GrantBook } from './grants.ts';
import { type Intent, IntentStore, intentHash } from './intents.ts';
import {
  checkOriginUrl,
  registrableDomain,
  rpIdAllowedForHost,
  verifiedOriginFromFrame,
} from './origin.ts';
import { type EffectivePolicy, PolicyStore } from './policy.ts';
import { Deny, parseCreateOptions, parseGetOptions } from './webauthn-options.ts';

export interface SignerPort {
  createCredential(req: {
    rpId: string;
    userHandle: string;
    clientDataJSON: string;
    approval: SignedApproval;
  }): Promise<CreateCredentialResult>;
  sign(req: {
    credentialId: string;
    authenticatorData: string;
    clientDataJSON: string;
    approval: SignerAuthorization;
  }): Promise<SignResult>;
  releaseSecret(req: {
    itemId: string;
    field: FillField;
    approval: SignerAuthorization;
  }): Promise<ReleaseSecretResult>;
  acceptHandoffGrant?(approval: SignedApproval): Promise<{ grantId: string; until: number }>;
  dropGrant?(grantId: string): Promise<{ dropped: boolean }>;
}

export type FillStepKind = 'identifier' | 'password' | 'otp';

export interface FillTarget {
  origin: { origin: string; host: string };
  first: FillStepKind;
  perform(ctx: {
    item: PasswordRow;
    release: (field: FillField) => Promise<string>;
  }): Promise<FillPerformResult>;
}

export type FillPerformResult =
  | { outcome: 'success' | 'failed' }
  | { outcome: 'challenge'; humanCheck: string };

export type FillOutcome = 'success' | 'failed' | 'challenge' | 'denied';

export interface AgentIdentity {
  id: string;
  name: string;
}

export interface KeepSignedInHooks {
  offer(agentId: string, site: string): boolean;
  record(agentId: string, site: string): void;
}

export interface BrokerOptions {
  db: DatabaseSync;
  signer: SignerPort;
  approver: Approver;
  now?: () => number;
  approvalTimeoutMs?: number;
  intentTtlMs?: number;
  highRiskDomains?: readonly string[];
  keepSignedIn?: KeepSignedInHooks;
}

export type CeremonyEvent =
  | { phase: 'start'; id: string; agentId: string; page: object | null; kind: 'create' | 'get' }
  | {
      phase: 'end';
      id: string;
      agentId: string;
      page: object | null;
      kind: 'create' | 'get';
      ok: boolean;
    };

export interface LoginEvent {
  agentId: string;
  origin: string;
  host: string;
}

interface Authorized {
  approval: SignerAuthorization;
  used: CoreGrant | null;
  offered: CoreGrant | null;
  keep: { agentId: string; site: string } | null;
}

const GRANT_USE_TTL_MS = 60_000;

export const HANDOFF_SIGNIN_GRANT_MS = HANDOFF_GRANT_MAX_MS;

export interface HandoffSignInOffer {
  kind: 'webauthn.get' | 'fill';
  verifiedOrigin: string;
  host: string;
  rpId: string;
  credentialId: string;
  rowId: string;
  fields: FillField[];
  credentialType: ApprovalRequest['display']['credentialType'];
}

export type HandoffSignInCheck =
  | { ok: true; offer: HandoffSignInOffer }
  | { ok: false; reason: string };

export type HandoffSignInResult =
  | { ok: true; deviceId: string; grantId: string }
  | { ok: false; reason: string };

const MAX_RECENT_SIGNINS = 1024;

const isAgent = (a: unknown): a is AgentIdentity =>
  typeof a === 'object' &&
  a !== null &&
  typeof (a as AgentIdentity).id === 'string' &&
  (a as AgentIdentity).id.length > 0 &&
  typeof (a as AgentIdentity).name === 'string' &&
  (a as AgentIdentity).name.length > 0;

function toDeny(err: unknown): Deny {
  if (err instanceof Deny) return err;
  if (err instanceof SignerDenied && /^[a-z_]{1,64}$/.test(err.message)) {
    return new Deny(`signer:${err.message}`);
  }
  return new Deny('internal_error');
}

export class Broker {
  readonly audit: AuditLog;
  readonly intents: IntentStore;
  readonly credentials: CredentialRepo;
  readonly requests: RequestRepo;
  readonly policy: PolicyStore;
  readonly grants = new GrantBook();
  private readonly loginListeners = new Set<(e: LoginEvent) => void>();
  private readonly signer: SignerPort;
  private readonly approver: Approver;
  private readonly agents: AgentRegistry;
  private readonly ceremonyListeners = new Set<(e: CeremonyEvent) => void>();
  private readonly now: () => number;
  private readonly approvalTimeoutMs: number;
  private readonly highRisk: readonly string[];
  private readonly keepHooks: KeepSignedInHooks | null;
  private readonly pendingApprovals = new Map<string, number>();
  private handoffOpen: (agentId: string) => boolean = () => false;
  private readonly recentSignIns = new Map<string, string>();

  constructor(opts: BrokerOptions) {
    this.now = opts.now ?? Date.now;
    this.audit = new AuditLog(opts.db, this.now);
    this.intents = new IntentStore(opts.db, {
      now: this.now,
      ...(opts.intentTtlMs ? { ttlMs: opts.intentTtlMs } : {}),
    });
    this.credentials = new CredentialRepo(opts.db);
    this.requests = new RequestRepo(opts.db);
    this.policy = new PolicyStore(opts.db, { now: this.now });
    this.agents = new AgentRegistry(opts.db, { now: this.now });
    this.signer = opts.signer;
    this.approver = opts.approver;
    this.approvalTimeoutMs = opts.approvalTimeoutMs ?? 90_000;
    this.highRisk = opts.highRiskDomains ?? [];
    this.keepHooks = opts.keepSignedIn ?? null;
  }

  setHandoffCheck(isOpen: (agentId: string) => boolean): void {
    this.handoffOpen = isOpen;
  }

  approvalPending(agentId: string): boolean {
    return (this.pendingApprovals.get(agentId) ?? 0) > 0;
  }

  private checkAgent(agent: AgentIdentity): void {
    let active = false;
    try {
      active = this.agents.byId(agent.id) !== null;
    } catch {
      active = false;
    }
    if (!active) {
      this.grants.dropAgent(agent.id);
      throw new Deny('agent_revoked');
    }
  }

  private checkHandoff(agent: AgentIdentity): void {
    let open = true;
    try {
      open = this.handoffOpen(agent.id) !== false;
    } catch {
      open = true;
    }
    if (open) throw new Deny('handoff_open');
  }

  onCeremony(listener: (e: CeremonyEvent) => void): () => void {
    this.ceremonyListeners.add(listener);
    return () => this.ceremonyListeners.delete(listener);
  }

  onLogin(listener: (e: LoginEvent) => void): () => void {
    this.loginListeners.add(listener);
    return () => this.loginListeners.delete(listener);
  }

  private emitLogin(e: LoginEvent): void {
    for (const l of this.loginListeners) {
      try {
        l(e);
      } catch {}
    }
  }

  private emit(e: CeremonyEvent): void {
    for (const l of this.ceremonyListeners) {
      try {
        l(e);
      } catch {}
    }
  }

  handleWebAuthn = async (
    req: ShimWebAuthnRequest,
    agent: AgentIdentity,
    source: { page?: object } = {},
  ): Promise<ShimWebAuthnResult> => {
    try {
      if (!isAgent(agent)) return { ok: false, name: 'NotAllowedError' };
      const reqKind: 'create' | 'get' = req.kind === 'create' ? 'create' : 'get';
      const id = randomUUID();
      const page = source.page ?? null;
      const ceremony = req.frame?.isMainFrame === true;
      if (ceremony) this.emit({ phase: 'start', id, agentId: agent.id, page, kind: reqKind });
      let result: ShimWebAuthnResult = { ok: false, name: 'NotAllowedError' };
      try {
        result = await this.run(id, req, agent);
      } finally {
        if (ceremony) {
          this.emit({ phase: 'end', id, agentId: agent.id, page, kind: reqKind, ok: result.ok });
        }
      }
      return result;
    } catch {
      return { ok: false, name: 'NotAllowedError' };
    }
  };

  private async run(
    requestId: string,
    req: ShimWebAuthnRequest,
    agent: AgentIdentity,
  ): Promise<ShimWebAuthnResult> {
    const origin = verifiedOriginFromFrame(req.frame);
    const verifiedOrigin = origin.ok ? origin.origin : null;
    const kind = req.kind === 'create' ? 'passkey.create' : 'passkey.get';
    this.requests.insert({
      id: requestId,
      agentId: agent.id,
      verifiedOrigin,
      kind,
      now: this.now(),
    });
    this.audit.append('request', { requestId, agentId: agent.id, kind, verifiedOrigin });
    try {
      if (!origin.ok) throw new Deny(origin.reason);
      if (req.kind !== 'create' && req.kind !== 'get') throw new Deny('bad_kind');
      const pol = this.checkPolicy(requestId, agent, origin);
      this.checkHandoff(agent);
      return req.kind === 'create'
        ? await this.create(requestId, agent, origin.origin, origin.host, req.options, pol)
        : await this.get(requestId, agent, origin.origin, origin.host, req.options, pol);
    } catch (err) {
      const deny = toDeny(err);
      this.requests.update(requestId, { status: 'denied', now: this.now() });
      this.audit.append('denied', {
        requestId,
        agentId: agent.id,
        kind,
        verifiedOrigin,
        reason: deny.reason,
      });
      return { ok: false, name: deny.name_ };
    }
  }

  fill = async (agent: AgentIdentity, target: FillTarget): Promise<FillOutcome> => {
    try {
      if (!isAgent(agent)) return 'denied';
      return await this.runFill(randomUUID(), agent, target);
    } catch {
      return 'denied';
    }
  };

  refuseFill(agent: AgentIdentity, verifiedOrigin: string, reason: string): void {
    const requestId = randomUUID();
    const kind = 'password.fill';
    this.requests.insert({
      id: requestId,
      agentId: agent.id,
      verifiedOrigin,
      kind,
      now: this.now(),
    });
    this.audit.append('request', { requestId, agentId: agent.id, kind, verifiedOrigin });
    this.requests.update(requestId, { status: 'denied', now: this.now() });
    this.audit.append('denied', { requestId, agentId: agent.id, kind, verifiedOrigin, reason });
  }

  private async runFill(
    requestId: string,
    agent: AgentIdentity,
    target: FillTarget,
  ): Promise<FillOutcome> {
    const verifiedOrigin = target.origin.origin;
    const kind = 'password.fill';
    this.requests.insert({
      id: requestId,
      agentId: agent.id,
      verifiedOrigin,
      kind,
      now: this.now(),
    });
    this.audit.append('request', { requestId, agentId: agent.id, kind, verifiedOrigin });
    try {
      const o = checkOriginUrl(verifiedOrigin);
      if (!o.ok || o.origin !== verifiedOrigin || o.host !== target.origin.host) {
        throw new Deny(o.ok ? 'origin_mismatch' : o.reason);
      }
      const pol = this.checkPolicy(requestId, agent, o);
      this.checkHandoff(agent);
      const domain = registrableDomain(o.host);
      if (!domain) throw new Deny('no_registrable_domain');
      const items = this.credentials.passwordsForDomain(domain);
      if (items.length === 0) throw new Deny('no_matching_credential');
      if (items.length > 1) throw new Deny('ambiguous_credential');
      const item = items[0] as PasswordRow;

      let fields: FillField[];
      if (target.first === 'otp') {
        if (!item.has_totp) throw new Deny('no_totp');
        fields = ['totp'];
      } else {
        if (target.first === 'identifier' && !item.username) throw new Deny('no_username');
        fields = item.has_totp ? ['password', 'totp'] : ['password'];
      }

      const intent = this.requireIntent(agent);
      const auth = await this.authorize(
        agent,
        pol,
        {
          display: {
            intentText: intent.text,
            intentAt: intent.createdAt,
            verifiedOrigin,
            agentName: agent.name,
            credentialType:
              fields.length === 2 ? 'password+totp' : (fields[0] as 'password' | 'totp'),
            action: 'sign-in',
          },
          binding: {
            requestId,
            kind: 'fill',
            rpId: domain,
            credentialId: item.signer_ref,
            intentHash: intentHash(intent),
            clientDataHash: sha256B64url(fillScope(fields)),
          },
        },
        fields,
      );
      this.requests.update(requestId, {
        status: 'approved',
        credentialId: item.id,
        intentId: intent.id,
        now: this.now(),
      });

      const released = new Set<FillField>();
      const performed = await target.perform({
        item,
        release: async (field) => {
          if (!fields.includes(field) || released.has(field)) throw new Deny('field_not_approved');
          released.add(field);
          const { value } = await this.withGrantFallback(requestId, agent, auth, () =>
            this.signer.releaseSecret({ itemId: item.signer_ref, field, approval: auth.approval }),
          );
          if (typeof value !== 'string' || value.length === 0) throw new Deny('bad_secret');
          this.audit.append('fill.released', { requestId, itemId: item.id, field });
          return value;
        },
      });
      const outcome = performed.outcome;
      if (outcome !== 'success' && outcome !== 'failed' && outcome !== 'challenge') {
        throw new Deny('internal_error');
      }
      this.requests.update(requestId, { status: 'completed', now: this.now() });
      this.audit.append('fill.completed', {
        requestId,
        agentId: agent.id,
        verifiedOrigin,
        itemId: item.id,
        outcome,
        fields: [...released],
        ...(performed.outcome === 'challenge' ? { humanCheck: performed.humanCheck } : {}),
      });
      if (outcome === 'success')
        this.emitLogin({ agentId: agent.id, origin: o.origin, host: o.host });
      if (outcome === 'success' || outcome === 'challenge')
        this.noteSignIn(agent.id, o.host, intent);
      return outcome;
    } catch (err) {
      const deny = toDeny(err);
      this.requests.update(requestId, { status: 'denied', now: this.now() });
      this.audit.append('denied', {
        requestId,
        agentId: agent.id,
        kind,
        verifiedOrigin,
        reason: deny.reason,
      });
      return 'denied';
    }
  }

  private resolveRpId(requested: string | undefined, host: string): string {
    const rpId = requested ?? host;
    if (!rpIdAllowedForHost(rpId, host))
      throw new Deny('rp_id_not_allowed_for_origin', 'SecurityError');
    return rpId;
  }

  private requireIntent(agent: AgentIdentity): Intent {
    const intent = this.intents.latestLive(agent.id);
    if (!intent) throw new Deny('no_live_intent');
    return intent;
  }

  private checkPolicy(
    requestId: string,
    agent: AgentIdentity,
    o: { origin: string; host: string },
  ): EffectivePolicy {
    this.checkAgent(agent);
    const pol = this.policy.resolve(agent.id, o);
    if (pol.matched.length > 0) {
      this.audit.append('policy', {
        requestId,
        agentId: agent.id,
        verifiedOrigin: o.origin,
        mode: pol.mode,
        ...(pol.allowForMs !== null ? { allowForMs: pol.allowForMs } : {}),
        rules: pol.matched,
      });
    }
    if (pol.mode === 'deny') throw new Deny('policy_deny');
    return pol;
  }

  private async authorize(
    agent: AgentIdentity,
    pol: EffectivePolicy,
    r: Omit<ApprovalRequest, 'policy'>,
    fields: readonly FillField[],
  ): Promise<Authorized> {
    const b = r.binding;
    const strong =
      pol.mode === 'ask-strong' ||
      isHighRisk(b.rpId, this.highRisk) ||
      isHighRiskOrigin(r.display.verifiedOrigin, this.highRisk);
    const allowForMs =
      !strong &&
      pol.mode === 'allow-for' &&
      pol.allowForMs !== null &&
      (b.kind === 'webauthn.get' || b.kind === 'fill') &&
      b.credentialId !== null
        ? pol.allowForMs
        : null;
    const kind = b.kind as CoreGrant['kind'];
    const credentialId = b.credentialId as string;
    const now = this.now();
    const keepSite = this.keepOffer(agent, r, strong);
    if (allowForMs !== null) {
      const g = this.grants.find(
        {
          agentId: agent.id,
          kind,
          verifiedOrigin: r.display.verifiedOrigin,
          rpId: b.rpId,
          credentialId,
          fields,
        },
        now,
        allowForMs,
      );
      if (g) {
        const statement: ApprovalStatement = {
          v: 1,
          requestId: b.requestId,
          kind: b.kind,
          verifiedOrigin: r.display.verifiedOrigin,
          rpId: b.rpId,
          credentialId: b.credentialId,
          intentHash: b.intentHash,
          clientDataHash: b.clientDataHash,
          userVerified: false,
          issuedAt: now,
          expiresAt: now + GRANT_USE_TTL_MS,
        };
        this.audit.append('grant.used', {
          requestId: b.requestId,
          grantId: g.grantId,
          agentId: agent.id,
          verifiedOrigin: r.display.verifiedOrigin,
        });
        return {
          approval: { statement, grantId: g.grantId, agentId: agent.id },
          used: g,
          offered: null,
          keep: null,
        };
      }
    }
    if (
      !strong &&
      (pol.mode === 'ask' || pol.mode === 'allow-for') &&
      (b.kind === 'webauthn.get' || b.kind === 'fill') &&
      b.credentialId !== null
    ) {
      const g = this.grants.takeHandoff(
        {
          agentId: agent.id,
          kind,
          verifiedOrigin: r.display.verifiedOrigin,
          rpId: b.rpId,
          credentialId,
          fields,
        },
        now,
      );
      if (g) {
        const statement: ApprovalStatement = {
          v: 1,
          requestId: b.requestId,
          kind: b.kind,
          verifiedOrigin: r.display.verifiedOrigin,
          rpId: b.rpId,
          credentialId: b.credentialId,
          intentHash: b.intentHash,
          clientDataHash: b.clientDataHash,
          userVerified: false,
          issuedAt: now,
          expiresAt: now + GRANT_USE_TTL_MS,
        };
        this.audit.append('grant.used', {
          requestId: b.requestId,
          grantId: g.grantId,
          agentId: agent.id,
          verifiedOrigin: r.display.verifiedOrigin,
          singleUse: true,
          ...(g.handoffId ? { handoffId: g.handoffId } : {}),
        });
        return {
          approval: { statement, grantId: g.grantId, agentId: agent.id },
          used: g,
          offered: null,
          keep: null,
        };
      }
    }
    const req: ApprovalRequest =
      allowForMs !== null
        ? {
            display: { ...r.display, allowForMs },
            binding: { ...b, grant: { agentId: agent.id, durationMs: allowForMs } },
            policy: { tier: 'ask' },
          }
        : {
            display: keepSite !== null ? { ...r.display, keepSignedInSite: keepSite } : r.display,
            binding: r.binding,
            policy: { tier: strong ? 'ask-strong' : 'ask' },
          };
    let approval: SignedApproval;
    if ((this.pendingApprovals.get(agent.id) ?? 0) > 0) throw new Deny('approval_pending');
    this.pendingApprovals.set(agent.id, (this.pendingApprovals.get(agent.id) ?? 0) + 1);
    try {
      approval = await this.approve(req, strong);
    } finally {
      const n = (this.pendingApprovals.get(agent.id) ?? 1) - 1;
      if (n > 0) this.pendingApprovals.set(agent.id, n);
      else this.pendingApprovals.delete(agent.id);
    }
    const s = approval.statement;
    if (strong && s.strong !== true) throw new Deny('strong_not_signed');
    let keep: Authorized['keep'] = null;
    if (s.keepSignedIn !== undefined) {
      if (keepSite === null || s.keepSignedIn?.site !== keepSite) throw new Deny('unexpected_keep');
      keep = { agentId: agent.id, site: keepSite };
    }
    let offered: CoreGrant | null = null;
    if (s.grant !== undefined) {
      const g = s.grant;
      if (
        allowForMs === null ||
        g.agentId !== agent.id ||
        g.until <= s.issuedAt ||
        g.until > s.issuedAt + allowForMs
      ) {
        throw new Deny('unexpected_grant');
      }
      offered = {
        grantId: s.requestId,
        agentId: agent.id,
        kind,
        verifiedOrigin: s.verifiedOrigin,
        rpId: s.rpId,
        credentialId,
        scope: [...fields],
        createdAt: s.issuedAt,
        until: g.until,
      };
    }
    return { approval, used: null, offered, keep };
  }

  private keepOffer(
    agent: AgentIdentity,
    r: Omit<ApprovalRequest, 'policy'>,
    strong: boolean,
  ): string | null {
    const hooks = this.keepHooks;
    const b = r.binding;
    if (!hooks || (b.kind !== 'webauthn.get' && b.kind !== 'fill')) return null;
    let host: string;
    try {
      host = new URL(r.display.verifiedOrigin).hostname;
    } catch {
      return null;
    }
    if (!strong) return null;
    const site = registrableDomain(host);
    if (!site) return null;
    try {
      return hooks.offer(agent.id, site) ? site : null;
    } catch {
      return null;
    }
  }

  private async withGrantFallback<T>(
    requestId: string,
    agent: AgentIdentity,
    auth: Authorized,
    op: () => Promise<T>,
  ): Promise<T> {
    this.checkAgent(agent);
    let result: T;
    try {
      result = await op();
    } catch (err) {
      if (auth.used) {
        this.grants.drop(auth.used.grantId);
        this.audit.append('grant.dropped', {
          requestId,
          grantId: auth.used.grantId,
          reason: err instanceof Error ? err.message.slice(0, 64) : 'error',
        });
        throw new Deny('grant_refused');
      }
      throw err;
    }
    const k = auth.keep;
    if (k) {
      auth.keep = null;
      try {
        this.keepHooks?.record(k.agentId, k.site);
      } catch {
        this.audit.append('session.keep_failed', { requestId, agentId: k.agentId, site: k.site });
      }
    }
    const g = auth.offered;
    if (g) {
      auth.offered = null;
      this.grants.add(g);
      this.audit.append('grant.created', {
        requestId,
        grantId: g.grantId,
        agentId: g.agentId,
        verifiedOrigin: g.verifiedOrigin,
        until: g.until,
      });
    }
    return result;
  }

  private async approve(req: ApprovalRequest, strong: boolean): Promise<SignedApproval> {
    return (await this.decide(req, strong)).approval;
  }

  private async decide(
    req: ApprovalRequest,
    strong: boolean,
    external?: AbortSignal,
  ): Promise<{ approval: SignedApproval; deviceId: string | null }> {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), this.approvalTimeoutMs);
    let gone: Deny = new Deny('approval_timeout');
    const onExternal = () => {
      gone = new Deny('handoff_ended');
      ctl.abort();
    };
    if (external?.aborted) onExternal();
    else external?.addEventListener('abort', onExternal);
    try {
      const decision = await Promise.race([
        this.approver.request(req, { signal: ctl.signal }),
        new Promise<never>((_, reject) => {
          if (ctl.signal.aborted) reject(gone);
          else ctl.signal.addEventListener('abort', () => reject(gone));
        }),
      ]);
      this.audit.append('approval', {
        requestId: req.binding.requestId,
        approved: decision.approved,
        reason: decision.approved ? undefined : decision.reason,
      });
      if (!decision.approved) throw new Deny(`approval_${decision.reason}`);
      if (
        strong &&
        decision.approval.webauthn === undefined &&
        decision.approval.native === undefined
      ) {
        throw new Deny('user_verification_required');
      }
      const deviceId = typeof decision.deviceId === 'string' ? decision.deviceId : null;
      return { approval: decision.approval, deviceId };
    } finally {
      clearTimeout(timer);
      external?.removeEventListener('abort', onExternal);
    }
  }

  private noteSignIn(agentId: string, host: string, intent: Intent): void {
    const key = `${agentId}\n${registrableDomain(host) ?? host}`;
    this.recentSignIns.delete(key);
    this.recentSignIns.set(key, intent.id);
    while (this.recentSignIns.size > MAX_RECENT_SIGNINS) {
      this.recentSignIns.delete(this.recentSignIns.keys().next().value as string);
    }
  }

  handoffSignInOffer(
    agent: AgentIdentity,
    at: { origin: string; host: string },
  ): HandoffSignInCheck {
    const no = (reason: string): HandoffSignInCheck => ({ ok: false, reason });
    try {
      if (!isAgent(agent)) return no('bad_agent');
      if (this.agents.byId(agent.id) === null) return no('agent_revoked');
      if (!this.signer.acceptHandoffGrant || !this.signer.dropGrant) return no('unsupported');
      const o = checkOriginUrl(at.origin);
      if (!o.ok || o.origin !== at.origin || o.host !== at.host) return no('not_eligible');
      const mode = this.policy.resolve(agent.id, o).mode;
      if (mode !== 'ask' && mode !== 'allow-for') {
        return no(mode === 'ask-strong' ? 'policy_ask_strong' : 'policy_deny');
      }
      if (isHighRiskOrigin(o.origin, this.highRisk)) return no('high_risk');
      const intent = this.intents.latestLive(agent.id);
      if (!intent) return no('no_live_intent');
      if (this.approvalPending(agent.id)) return no('approval_pending');
      const site = registrableDomain(o.host);
      if (this.recentSignIns.get(`${agent.id}\n${site ?? o.host}`) === intent.id) {
        return no('signed_in_for_intent');
      }
      if (site) {
        const items = this.credentials.passwordsForDomain(site);
        if (items.length > 1) return no('ambiguous_credential');
        const item = items[0];
        if (item) {
          if (isHighRisk(site, this.highRisk)) return no('high_risk');
          const fields: FillField[] = item.has_totp ? ['password', 'totp'] : ['password'];
          return {
            ok: true,
            offer: {
              kind: 'fill',
              verifiedOrigin: o.origin,
              host: o.host,
              rpId: site,
              credentialId: item.signer_ref,
              rowId: item.id,
              fields,
              credentialType: fields.length === 2 ? 'password+totp' : 'password',
            },
          };
        }
      }
      const passkeys = this.credentials
        .allPasskeyRpIds()
        .filter((c) => rpIdAllowedForHost(c.rp_id, o.host));
      if (passkeys.length > 1) return no('ambiguous_credential');
      const pk = passkeys[0];
      if (!pk) return no('no_credential');
      if (isHighRisk(pk.rp_id, this.highRisk)) return no('high_risk');
      return {
        ok: true,
        offer: {
          kind: 'webauthn.get',
          verifiedOrigin: o.origin,
          host: o.host,
          rpId: pk.rp_id,
          credentialId: pk.id,
          rowId: pk.id,
          fields: [],
          credentialType: 'passkey',
        },
      };
    } catch {
      return no('internal_error');
    }
  }

  async approveHandoffSignIn(
    agent: AgentIdentity,
    offer: HandoffSignInOffer,
    handoff: { id: string; signal?: AbortSignal },
  ): Promise<HandoffSignInResult> {
    const requestId = randomUUID();
    const kind = 'handoff.sign-in';
    const verifiedOrigin = offer.verifiedOrigin;
    const agentId = isAgent(agent) ? agent.id : '';
    try {
      this.requests.insert({ id: requestId, agentId, verifiedOrigin, kind, now: this.now() });
      this.audit.append('request', {
        requestId,
        agentId,
        kind,
        verifiedOrigin,
        handoffId: handoff.id,
      });
    } catch {
      return { ok: false, reason: 'internal_error' };
    }
    try {
      if (!isAgent(agent)) throw new Deny('bad_agent');
      const o = checkOriginUrl(verifiedOrigin);
      if (!o.ok || o.origin !== verifiedOrigin) throw new Deny('not_eligible');
      this.checkPolicy(requestId, agent, o);
      const fresh = this.handoffSignInOffer(agent, o);
      if (!fresh.ok) throw new Deny(fresh.reason);
      const f = fresh.offer;
      if (
        f.kind !== offer.kind ||
        f.rpId !== offer.rpId ||
        f.credentialId !== offer.credentialId ||
        f.fields.join(',') !== offer.fields.join(',')
      ) {
        throw new Deny('credential_changed');
      }
      const intent = this.requireIntent(agent);
      const clientDataHash =
        f.kind === 'fill'
          ? sha256B64url(fillScope(f.fields))
          : handoffSignInClientDataHash(handoff.id);
      const req: ApprovalRequest = {
        display: {
          intentText: intent.text,
          intentAt: intent.createdAt,
          verifiedOrigin,
          agentName: agent.name,
          credentialType: f.credentialType,
          action: 'sign-in',
          handoffSignIn: { withinMs: HANDOFF_SIGNIN_GRANT_MS },
        },
        binding: {
          requestId,
          kind: f.kind,
          rpId: f.rpId,
          credentialId: f.credentialId,
          intentHash: intentHash(intent),
          clientDataHash,
          grant: { agentId: agent.id, durationMs: HANDOFF_SIGNIN_GRANT_MS, uses: 1 },
          handoff: { id: handoff.id },
        },
        policy: { tier: 'ask' },
      };
      let decided: { approval: SignedApproval; deviceId: string | null };
      this.pendingApprovals.set(agent.id, (this.pendingApprovals.get(agent.id) ?? 0) + 1);
      try {
        decided = await this.decide(req, false, handoff.signal);
      } finally {
        const n = (this.pendingApprovals.get(agent.id) ?? 1) - 1;
        if (n > 0) this.pendingApprovals.set(agent.id, n);
        else this.pendingApprovals.delete(agent.id);
      }
      const approval = decided.approval;
      if (approval.webauthn === undefined) throw new Deny('user_verification_required');
      if (decided.deviceId === null || decided.deviceId.length === 0) throw new Deny('no_device');
      const s = approval.statement;
      const g = s.grant;
      if (
        s.requestId !== requestId ||
        s.kind !== f.kind ||
        s.verifiedOrigin !== verifiedOrigin ||
        s.rpId !== f.rpId ||
        s.credentialId !== f.credentialId ||
        s.intentHash !== req.binding.intentHash ||
        s.clientDataHash !== clientDataHash ||
        s.handoff?.id !== handoff.id ||
        s.strong !== undefined ||
        s.keepSignedIn !== undefined ||
        g === undefined ||
        g.uses !== 1 ||
        g.agentId !== agent.id ||
        g.until <= s.issuedAt ||
        g.until > s.issuedAt + HANDOFF_SIGNIN_GRANT_MS
      ) {
        throw new Deny('unexpected_grant');
      }
      if (handoff.signal?.aborted) throw new Deny('handoff_ended');
      this.checkAgent(agent);
      try {
        const r = await this.signer.acceptHandoffGrant?.(approval);
        if (!r || r.grantId !== s.requestId) throw new Error('refused');
      } catch {
        throw new Deny('grant_refused');
      }
      this.grants.add({
        grantId: s.requestId,
        agentId: agent.id,
        kind: f.kind,
        verifiedOrigin,
        rpId: f.rpId,
        credentialId: f.credentialId,
        scope: [...f.fields],
        createdAt: s.issuedAt,
        until: g.until,
        singleUse: true,
        handoffId: handoff.id,
        armed: false,
      });
      this.requests.update(requestId, {
        status: 'approved',
        credentialId: f.rowId,
        intentId: intent.id,
        now: this.now(),
      });
      this.audit.append('grant.created', {
        requestId,
        grantId: s.requestId,
        agentId: agent.id,
        verifiedOrigin,
        until: g.until,
        singleUse: true,
        handoffId: handoff.id,
      });
      return { ok: true, deviceId: decided.deviceId, grantId: s.requestId };
    } catch (err) {
      const deny = toDeny(err);
      try {
        this.requests.update(requestId, { status: 'denied', now: this.now() });
        this.audit.append('denied', {
          requestId,
          agentId,
          kind,
          verifiedOrigin,
          reason: deny.reason,
        });
      } catch {}
      return { ok: false, reason: deny.reason };
    }
  }

  handoffEnded(handoffId: string, outcome: string): void {
    try {
      if (outcome === 'done') {
        const g = this.grants.arm(handoffId);
        if (g) this.audit.append('grant.armed', { grantId: g.grantId, handoffId });
        return;
      }
      const g = this.grants.dropHandoff(handoffId);
      if (!g) return;
      this.audit.append('grant.dropped', {
        grantId: g.grantId,
        handoffId,
        reason: `handoff_${outcome}`,
      });
      void Promise.resolve(this.signer.dropGrant?.(g.grantId)).catch(() => {
        try {
          this.audit.append('grant.drop_failed', { grantId: g.grantId, handoffId });
        } catch {}
      });
    } catch {}
  }

  private async get(
    requestId: string,
    agent: AgentIdentity,
    verifiedOrigin: string,
    host: string,
    rawOptions: unknown,
    pol: EffectivePolicy,
  ): Promise<ShimWebAuthnResult> {
    const opts = parseGetOptions(rawOptions);
    const rpId = this.resolveRpId(opts.rpId, host);

    let candidates = this.credentials.passkeysForRp(rpId);
    if (opts.allowCredentials.length > 0) {
      const allowed = new Set(opts.allowCredentials.map(b64url.encode));
      candidates = candidates.filter((c) => allowed.has(c.id));
    }
    if (candidates.length === 0) throw new Deny('no_matching_credential');
    if (candidates.length > 1) throw new Deny('ambiguous_credential');
    const cred = candidates[0] as (typeof candidates)[number];

    const intent = this.requireIntent(agent);
    const clientDataJSON = buildClientDataJSON(
      'webauthn.get',
      b64url.encode(opts.challenge),
      verifiedOrigin,
    );
    const auth = await this.authorize(
      agent,
      pol,
      {
        display: {
          intentText: intent.text,
          intentAt: intent.createdAt,
          verifiedOrigin,
          agentName: agent.name,
          credentialType: 'passkey',
          action: 'sign-in',
        },
        binding: {
          requestId,
          kind: 'webauthn.get',
          rpId,
          credentialId: cred.id,
          intentHash: intentHash(intent),
          clientDataHash: sha256B64url(clientDataJSON),
        },
      },
      [],
    );
    this.requests.update(requestId, {
      status: 'approved',
      credentialId: cred.id,
      intentId: intent.id,
      now: this.now(),
    });

    const flags = FLAG_UP | (auth.approval.statement.userVerified ? FLAG_UV : 0);
    const authData = buildAuthenticatorData({ rpId, flags, signCount: 0 });
    const { signature } = await this.withGrantFallback(requestId, agent, auth, () =>
      this.signer.sign({
        credentialId: cred.id,
        authenticatorData: b64url.encode(authData),
        clientDataJSON: b64url.encode(clientDataJSON),
        approval: auth.approval,
      }),
    );

    this.requests.update(requestId, { status: 'completed', now: this.now() });
    this.audit.append('passkey.signed', {
      requestId,
      agentId: agent.id,
      verifiedOrigin,
      rpId,
      credentialId: cred.id,
    });
    this.emitLogin({ agentId: agent.id, origin: verifiedOrigin, host });
    this.noteSignIn(agent.id, host, intent);
    return {
      ok: true,
      credential: {
        id: cred.id,
        type: 'public-key',
        authenticatorAttachment: 'platform',
        response: {
          clientDataJSON: b64url.encode(clientDataJSON),
          authenticatorData: b64url.encode(authData),
          signature,
          userHandle: cred.user_handle,
        },
        clientExtensionResults: {},
      },
    };
  }

  private async create(
    requestId: string,
    agent: AgentIdentity,
    verifiedOrigin: string,
    host: string,
    rawOptions: unknown,
    pol: EffectivePolicy,
  ): Promise<ShimWebAuthnResult> {
    const opts = parseCreateOptions(rawOptions);
    const rpId = this.resolveRpId(opts.rpId, host);

    if (opts.excludeCredentials.length > 0) {
      const ours = new Set(this.credentials.passkeysForRp(rpId).map((c) => c.id));
      if (opts.excludeCredentials.some((id) => ours.has(b64url.encode(id)))) {
        throw new Deny('excluded_credential_present', 'InvalidStateError');
      }
    }

    const intent = this.requireIntent(agent);
    const clientDataJSON = buildClientDataJSON(
      'webauthn.create',
      b64url.encode(opts.challenge),
      verifiedOrigin,
    );
    const userHandle = b64url.encode(opts.userId);
    const auth = await this.authorize(
      agent,
      pol,
      {
        display: {
          intentText: intent.text,
          intentAt: intent.createdAt,
          verifiedOrigin,
          agentName: agent.name,
          credentialType: 'passkey',
          action: 'register',
        },
        binding: {
          requestId,
          kind: 'webauthn.create',
          rpId,
          credentialId: null,
          intentHash: intentHash(intent),
          clientDataHash: sha256B64url(clientDataJSON),
        },
      },
      [],
    );
    if (auth.used || isGrantedApproval(auth.approval)) throw new Deny('internal_error');
    const approval: SignedApproval = auth.approval;
    this.requests.update(requestId, { status: 'approved', intentId: intent.id, now: this.now() });

    this.checkAgent(agent);
    const created = await this.signer.createCredential({
      rpId,
      userHandle,
      clientDataJSON: b64url.encode(clientDataJSON),
      approval,
    });
    const credentialId = b64url.decode(created.credentialId);
    const x = b64url.decode(created.publicKey.x);
    const y = b64url.decode(created.publicKey.y);
    const cose = coseEs256PublicKey(x, y);
    const flags = FLAG_UP | FLAG_AT | (approval.statement.userVerified ? FLAG_UV : 0);
    const authData = buildAuthenticatorData({
      rpId,
      flags,
      signCount: 0,
      attested: { aaguid: AAGUID_NONE, credentialId, cosePublicKey: cose },
    });

    this.credentials.insertPasskey({
      id: created.credentialId,
      rpId,
      registrableDomain: registrableDomain(host),
      userHandle,
      username: opts.userName ?? null,
      publicKey: b64url.encode(cose),
      now: this.now(),
    });
    this.requests.update(requestId, {
      status: 'completed',
      credentialId: created.credentialId,
      now: this.now(),
    });
    this.audit.append('passkey.created', {
      requestId,
      agentId: agent.id,
      verifiedOrigin,
      rpId,
      credentialId: created.credentialId,
    });

    return {
      ok: true,
      credential: {
        id: created.credentialId,
        type: 'public-key',
        authenticatorAttachment: 'platform',
        response: {
          clientDataJSON: b64url.encode(clientDataJSON),
          authenticatorData: b64url.encode(authData),
          attestationObject: b64url.encode(buildNoneAttestationObject(authData)),
          publicKey: b64url.encode(spkiP256(x, y)),
          publicKeyAlgorithm: COSE_ALG_ES256,
          transports: ['internal'],
        },
        clientExtensionResults: opts.credProps ? { credProps: { rk: true } } : {},
      },
    };
  }
}
