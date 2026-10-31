import { AdminError, type AdminOps } from '@aab/signer/admin-wire';
import { siteOfHost } from './browser-state.ts';
import type { Daemon } from './daemon.ts';
import { ALL_AGENTS_OPTIN, CredentialRepo } from './db.ts';
import { addPasswordItem, parseTotpInput, removePasswordItem } from './passwords.ts';
import { normalizePattern } from './policy.ts';

function siteParam(p: Record<string, unknown>): string {
  const raw = str(p, 'site') as string;
  const pattern = normalizePattern(raw);
  return siteOfHost(pattern.includes('://') ? new URL(pattern).hostname : pattern);
}

export interface CoreAdminInfo {
  intentSocketPath: string;
  passwordSource: string | null;
}

function str(params: Record<string, unknown>, key: string, opts: { optional?: boolean } = {}) {
  const v = params[key];
  if (v === undefined || v === null) {
    if (opts.optional) return null;
    throw new AdminError(`missing ${key}`);
  }
  if (typeof v !== 'string' || v.length === 0 || v.length > 4096) {
    throw new AdminError(`bad ${key}`);
  }
  return v;
}

async function asAdmin<T>(fn: () => T | Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (err) {
    if (err instanceof AdminError) throw err;
    throw new AdminError(err instanceof Error ? err.message : 'failed');
  }
}

export function registerCoreAdminOps(ops: AdminOps, daemon: Daemon, info: CoreAdminInfo): void {
  const audit = (event: string, fields: Record<string, unknown>) =>
    daemon.broker.audit.append(event, fields);

  ops.register('status', async () => {
    const agents = daemon.registry.list().filter((a) => a.revokedAt === null).length;
    const passwords = new CredentialRepo(daemon.db).allPasswords().length;
    let signer = 'ok';
    try {
      await daemon.signer.client.ping();
    } catch {
      signer = 'unreachable';
    }
    return {
      mode: 'service',
      mcpUrl: daemon.mcpUrl,
      intentSocket: info.intentSocketPath,
      agents,
      passwords,
      passwordSource: info.passwordSource,
      signer,
    };
  });

  ops.register('agent.add', (p) =>
    asAdmin(() => {
      const a = daemon.registry.add(str(p, 'name') as string);
      audit('agent.added', { agentId: a.id, name: a.name, via: 'admin' });
      return { id: a.id, name: a.name, token: a.token };
    }),
  );
  ops.register('agent.list', () => ({ agents: daemon.registry.list() }));
  ops.register('agent.revoke', (p) =>
    asAdmin(() => {
      const id = str(p, 'id') as string;
      const revoked = daemon.registry.revoke(id);
      if (revoked) audit('agent.revoked', { agentId: id, via: 'admin' });
      return { revoked };
    }),
  );

  ops.register('password.add', (p) =>
    asAdmin(async () => {
      const totpRaw = str(p, 'totp', { optional: true });
      const added = await addPasswordItem(
        { signer: daemon.signer.client, db: daemon.db },
        {
          site: str(p, 'site') as string,
          username: str(p, 'username', { optional: true }),
          password: str(p, 'password') as string,
          ...(totpRaw !== null ? { totp: parseTotpInput(totpRaw) } : {}),
        },
      );
      return added;
    }),
  );
  ops.register('password.list', () => ({
    passwords: new CredentialRepo(daemon.db).allPasswords(),
  }));
  ops.register('password.remove', (p) =>
    asAdmin(async () => {
      const removed = await removePasswordItem(
        { signer: daemon.signer.client, db: daemon.db },
        str(p, 'id') as string,
      );
      return { removed };
    }),
  );

  ops.register('sessions.clear', (p) =>
    asAdmin(async () => {
      const all = p.all === true;
      const agent = str(p, 'agent', { optional: true });
      if (all === (agent !== null)) throw new AdminError('give exactly one of agent / all');
      const site = p.site === undefined || p.site === null ? null : siteParam(p);
      const agents = all
        ? daemon.registry
            .list()
            .filter((a) => a.revokedAt === null)
            .map((a) => a.id)
        : [agent as string];
      if (!all && !daemon.registry.byId(agent))
        throw new AdminError('no active agent with that id');
      audit('session.clear_requested', {
        agentId: all ? '*' : agent,
        ...(site !== null ? { site } : {}),
        via: 'admin',
      });
      let cookies = 0;
      let pages = 0;
      for (const id of agents) {
        const r =
          site === null
            ? await daemon.sessions.clearAgent(id, 'admin')
            : await daemon.sessions.clearSite(id, site, 'admin');
        cookies += r.cookies;
        pages += r.pages;
      }
      return { agents: agents.length, site, cookies, pages };
    }),
  );
  const optinAgent = (p: Record<string, unknown>) => {
    const agent = str(p, 'agent', { optional: true });
    if (agent !== null && !daemon.registry.byId(agent)) {
      throw new AdminError('no active agent with that id');
    }
    return agent ?? ALL_AGENTS_OPTIN;
  };
  ops.register('sessions.keep', (p) =>
    asAdmin(() => {
      const site = siteParam(p);
      const added = daemon.optins.add(optinAgent(p), site, 'admin');
      return { site, added };
    }),
  );
  ops.register('sessions.unkeep', (p) =>
    asAdmin(async () => {
      const site = siteParam(p);
      const agent = optinAgent(p);
      const removed = daemon.optins.remove(agent, site, 'admin');
      if (removed) {
        const ids =
          agent === ALL_AGENTS_OPTIN
            ? daemon.registry
                .list()
                .filter((a) => a.revokedAt === null)
                .map((a) => a.id)
            : [agent];
        for (const id of ids) await daemon.sessions.refilter(id);
      }
      return { site, removed };
    }),
  );
}
