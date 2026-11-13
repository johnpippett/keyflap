import type { FillField } from '@aab/signer/approval';

export interface GrantBase {
  grantId: string;
  agentId: string;
  kind: 'webauthn.get' | 'fill';
  verifiedOrigin: string;
  rpId: string;
  credentialId: string;
  scope: FillField[];
  createdAt: number;
  until: number;
}

export type CoreGrant = GrantBase &
  ({ use: 'window' } | { use: 'single'; handoffId: string; phase: 'held' | 'armed' });

export type WindowGrant = Extract<CoreGrant, { use: 'window' }>;
export type SingleUseGrant = Extract<CoreGrant, { use: 'single' }>;

export interface GrantQuery {
  agentId: string;
  kind: CoreGrant['kind'];
  verifiedOrigin: string;
  rpId: string;
  credentialId: string;
  fields: readonly FillField[];
}

function matches(g: CoreGrant, q: GrantQuery): boolean {
  return (
    g.agentId === q.agentId &&
    g.kind === q.kind &&
    g.verifiedOrigin === q.verifiedOrigin &&
    g.rpId === q.rpId &&
    g.credentialId === q.credentialId &&
    q.fields.every((f) => g.scope.includes(f))
  );
}

const MAX_GRANTS = 256;

export class GrantBook {
  private readonly grants = new Map<string, CoreGrant>();

  add(g: CoreGrant): void {
    this.grants.delete(g.grantId);
    while (this.grants.size >= MAX_GRANTS) {
      this.grants.delete(this.grants.keys().next().value as string);
    }
    this.grants.set(g.grantId, { ...g, scope: [...g.scope] });
  }

  find(q: GrantQuery, now: number, windowMs: number): WindowGrant | null {
    let best: WindowGrant | null = null;
    for (const [id, g] of this.grants) {
      if (g.until < now) {
        this.grants.delete(id);
        continue;
      }
      if (g.use !== 'window' || !matches(g, q) || Math.min(g.until, g.createdAt + windowMs) < now) {
        continue;
      }
      if (!best || g.until > best.until) best = g;
    }
    return best;
  }

  takeHandoff(q: GrantQuery, now: number): SingleUseGrant | null {
    for (const [id, g] of this.grants) {
      if (g.until < now) {
        this.grants.delete(id);
        continue;
      }
      if (g.use === 'single' && g.phase === 'armed' && matches(g, q)) {
        this.grants.delete(id);
        return g;
      }
    }
    return null;
  }

  arm(handoffId: string): SingleUseGrant | null {
    for (const g of this.grants.values()) {
      if (g.use === 'single' && g.handoffId === handoffId) {
        g.phase = 'armed';
        return g;
      }
    }
    return null;
  }

  dropHandoff(handoffId: string): SingleUseGrant | null {
    for (const [id, g] of this.grants) {
      if (g.use === 'single' && g.handoffId === handoffId) {
        this.grants.delete(id);
        return g;
      }
    }
    return null;
  }

  drop(grantId: string): void {
    this.grants.delete(grantId);
  }

  dropAgent(agentId: string): void {
    for (const [id, g] of this.grants) if (g.agentId === agentId) this.grants.delete(id);
  }

  size(): number {
    return this.grants.size;
  }
}
