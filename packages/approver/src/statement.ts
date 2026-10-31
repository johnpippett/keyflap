import {
  type ApprovalStatement,
  HANDOFF_GRANT_MAX_MS,
  keepSignedInOk,
  MAX_GRANT_MS,
} from '@aab/signer/approval';
import type { ApprovalRequest } from './types.ts';

export const APPROVAL_TTL_MS = 60_000;

export function requestProblem(req: ApprovalRequest): string | null {
  if (keepProblem(req)) return 'inconsistent_request';
  const combined = handoffProblem(req);
  if (combined !== undefined) return combined;
  const shown = req.display?.allowForMs;
  const grant = req.binding?.grant;
  if (shown === undefined && grant === undefined) return null;
  if (
    grant === undefined ||
    shown !== grant.durationMs ||
    typeof shown !== 'number' ||
    !Number.isInteger(shown) ||
    shown <= 0 ||
    shown > MAX_GRANT_MS ||
    typeof grant.agentId !== 'string' ||
    grant.agentId.length === 0
  ) {
    return 'inconsistent_request';
  }
  if (req.policy?.tier !== 'ask') return 'inconsistent_request';
  return null;
}

function handoffProblem(req: ApprovalRequest): string | null | undefined {
  const shown = req.display?.handoffSignIn;
  const h = req.binding?.handoff;
  const g = req.binding?.grant;
  if (shown === undefined && h === undefined && g?.uses === undefined) return undefined;
  if (
    shown === undefined ||
    h === undefined ||
    g === undefined ||
    g.uses !== 1 ||
    typeof h.id !== 'string' ||
    !/^[A-Za-z0-9-]{1,64}$/.test(h.id) ||
    typeof shown.withinMs !== 'number' ||
    !Number.isInteger(shown.withinMs) ||
    shown.withinMs <= 0 ||
    shown.withinMs > HANDOFF_GRANT_MAX_MS ||
    shown.withinMs !== g.durationMs ||
    typeof g.agentId !== 'string' ||
    g.agentId.length === 0 ||
    req.display.allowForMs !== undefined ||
    req.display.keepSignedInSite !== undefined ||
    req.display.action !== 'sign-in' ||
    req.policy?.tier !== 'ask' ||
    (req.binding.kind !== 'webauthn.get' && req.binding.kind !== 'fill') ||
    typeof req.binding.credentialId !== 'string'
  ) {
    return 'inconsistent_request';
  }
  return null;
}

function keepProblem(req: ApprovalRequest): boolean {
  const site = req.display?.keepSignedInSite;
  if (site === undefined) return false;
  if (!keepSignedInOk({ site })) return true;
  if (req.policy?.tier !== 'ask-strong' || req.binding?.grant !== undefined) return true;
  if (req.binding?.kind !== 'webauthn.get' && req.binding?.kind !== 'fill') return true;
  let host: string;
  try {
    host = new URL(req.display.verifiedOrigin).hostname;
  } catch {
    return true;
  }
  return host !== site && !host.endsWith(`.${site}`);
}

export function buildStatement(
  req: ApprovalRequest,
  opts: { userVerified: boolean; now?: number; ttlMs?: number; keepSignedIn?: boolean },
): ApprovalStatement {
  const problem = requestProblem(req);
  if (problem) throw new Error(problem);
  const keepSite = req.display.keepSignedInSite;
  if (opts.keepSignedIn === true && keepSite === undefined) throw new Error('keep_not_offered');
  const issuedAt = opts.now ?? Date.now();
  const grant = req.binding.grant;
  return {
    v: 1,
    requestId: req.binding.requestId,
    kind: req.binding.kind,
    verifiedOrigin: req.display.verifiedOrigin,
    rpId: req.binding.rpId,
    credentialId: req.binding.credentialId,
    intentHash: req.binding.intentHash,
    clientDataHash: req.binding.clientDataHash,
    userVerified: opts.userVerified,
    issuedAt,
    expiresAt: issuedAt + (opts.ttlMs ?? APPROVAL_TTL_MS),
    ...(req.policy?.tier === 'ask-strong' ? { strong: true as const } : {}),
    ...(grant
      ? {
          grant: {
            agentId: grant.agentId,
            until: issuedAt + grant.durationMs,
            ...(grant.uses === 1 ? { uses: 1 as const } : {}),
          },
        }
      : {}),
    ...(req.binding.handoff ? { handoff: { id: req.binding.handoff.id } } : {}),
    ...(opts.keepSignedIn === true && keepSite !== undefined
      ? { keepSignedIn: { site: keepSite } }
      : {}),
  };
}
