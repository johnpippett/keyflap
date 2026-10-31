import { mkdirSync, unlinkSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, relative, sep } from 'node:path';
import {
  type AgentListing,
  AgentRegistry,
  AuditLog,
  isAgentId,
  openDb,
  PersistOptins,
  SessionStateRepo,
} from '@aab/core';
import { type AgentHost, defaultDataDir } from './args.ts';

type Out = (text: string) => void;

function withRegistry<T>(
  dataDir: string,
  fn: (r: AgentRegistry, audit: AuditLog, db: ReturnType<typeof openDb>) => T,
): T {
  mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  const db = openDb(join(dataDir, 'broker.sqlite'));
  try {
    return fn(new AgentRegistry(db), new AuditLog(db), db);
  } finally {
    db.close();
  }
}

export function shellQuote(s: string): string {
  return /^[A-Za-z0-9_@%+=:,./-]+$/.test(s) ? s : `'${s.replaceAll("'", `'\\''`)}'`;
}

export function homeRelative(path: string): string {
  const rel = relative(homedir(), path);
  if (rel === '') return '~';
  if (!rel.startsWith('..') && !rel.startsWith(sep) && !rel.includes(`..${sep}`)) {
    return `~/${rel.split(sep).join('/')}`;
  }
  return path;
}

export function hookCommand(agentId: string, dataDir: string): string {
  const parts = [process.execPath, join(import.meta.dirname, 'main.ts'), 'hook', 'claude-code'];
  parts.push('--agent', agentId);
  if (dataDir !== defaultDataDir()) parts.push('--data-dir', dataDir);
  return parts.map(shellQuote).join(' ');
}

export function headersCommand(agentId: string, dataDir: string): string {
  const parts = [process.execPath, join(import.meta.dirname, 'main.ts'), 'mcp-headers'];
  parts.push('--agent', agentId);
  if (dataDir !== defaultDataDir()) parts.push('--data-dir', dataDir);
  return parts.map(shellQuote).join(' ');
}

export function claudeCodePaths(dataDir: string): { sandbox: string; rule: string } {
  const p = homeRelative(dataDir);
  return { sandbox: `${p}/**`, rule: p.startsWith('~') ? `${p}/**` : `/${p}/**` };
}

export function claudeCodeSnippet(
  agent: { id: string },
  dataDir: string,
  mcpPort: number,
  service?: { hookCommand: string },
) {
  const mcp = {
    mcpServers: {
      keyflap: {
        type: 'http',
        url: `http://127.0.0.1:${mcpPort}/mcp`,
        // biome-ignore lint/suspicious/noTemplateCurlyInString: Claude Code expands it, not JS
        headers: { Authorization: 'Bearer ${KEYFLAP_AGENT_TOKEN}' },
      },
    },
  };
  const paths = claudeCodePaths(dataDir);
  const settings = {
    hooks: {
      UserPromptSubmit: [
        {
          hooks: [
            { type: 'command', command: service?.hookCommand ?? hookCommand(agent.id, dataDir) },
          ],
        },
      ],
    },
    sandbox: {
      enabled: true,
      failIfUnavailable: true,
      allowUnsandboxedCommands: false,
      filesystem: { denyRead: [paths.sandbox], denyWrite: [paths.sandbox] },
    },
    permissions: { deny: [`Read(${paths.rule})`, `Edit(${paths.rule})`] },
  };
  return { mcp, settings };
}

export function createAgent(
  dataDir: string,
  name: string,
  via?: string,
): { id: string; name: string; token: string } {
  return withRegistry(dataDir, (registry, audit) => {
    const a = registry.add(name);
    appendAudit(audit, 'agent.added', { agentId: a.id, name: a.name, ...(via ? { via } : {}) });
    return a;
  });
}

export function listAgents(dataDir: string): AgentListing[] {
  return withRegistry(dataDir, (r) => r.list());
}

export function agentAddedText(agent: { id: string; name: string; token: string }): string[] {
  return [
    `Added agent "${agent.name}" (id ${agent.id}).`,
    '',
    'Agent token (shown once; the broker keeps only its hash):',
    '',
    `  ${agent.token}`,
    '',
    "The token is the agent's own identity for the MCP endpoint. It is NOT the host token,",
    'and it is fine for the agent to know it. Keep it out of committed files.',
    '',
  ];
}

const DEV_WARNING = [
  'WARNING: the broker currently runs as your OS user (`keyflap daemon --unprotected`). The',
  'settings above only cover this agent host; any other agent with shell access as you can',
  "read the broker's key files, memory and code. Development only (docs/ISOLATION_PLAN.md).",
  '',
];

export async function agentAdd(
  opts: { dataDir: string; name: string; mcpPort: number; host?: AgentHost; owners?: string[] },
  out: Out,
): Promise<{ id: string }> {
  const host = opts.host ?? 'claude-code';
  if (host !== 'claude-code') {
    const { codexText, hermesText } = await import('./host-config.ts');
    const agent = createAgent(opts.dataDir, opts.name);
    const body =
      host === 'hermes'
        ? hermesText({
            agent,
            dataDir: opts.dataDir,
            mcpPort: opts.mcpPort,
            owners: opts.owners ?? [],
          })
        : codexText({ agent, dataDir: opts.dataDir, mcpPort: opts.mcpPort });
    out([...agentAddedText(agent), body, ...DEV_WARNING].join('\n'));
    return { id: agent.id };
  }
  const agent = createAgent(opts.dataDir, opts.name);
  const { mcp, settings } = claudeCodeSnippet(agent, opts.dataDir, opts.mcpPort);
  out(
    [
      `Added agent "${agent.name}" (id ${agent.id}).`,
      '',
      'Agent token (shown once; the broker keeps only its hash):',
      '',
      `  ${agent.token}`,
      '',
      "The token is the agent's own identity for the MCP endpoint. It is NOT the host token,",
      'and it is fine for the agent to know it. Keep it out of committed files:',
      '',
      `  export KEYFLAP_AGENT_TOKEN=${shellQuote(agent.token)}`,
      '',
      '── Claude Code ── (details and the security requirements: docs/integrations/claude-code.md)',
      '',
      '.mcp.json (project root):',
      JSON.stringify(mcp, null, 2),
      '',
      '.claude/settings.json (merge into your existing settings). The sandbox and deny rules keep',
      'the model from reading the host token; without them a prompt-injected agent can forge intents:',
      JSON.stringify(settings, null, 2),
      '',
      'WARNING: the broker currently runs as your OS user (`keyflap daemon --unprotected`). The',
      'settings above only cover Claude Code; any other agent with shell access as you can read',
      "the broker's key files, memory and code. Development only (docs/ISOLATION_PLAN.md).",
      '',
    ].join('\n'),
  );
  return { id: agent.id };
}

const iso = (ms: number | null) => (ms === null ? '-' : new Date(ms).toISOString());

export function agentList(opts: { dataDir: string; json: boolean }, out: Out): AgentListing[] {
  const agents = withRegistry(opts.dataDir, (r) => r.list());
  out(formatAgents(agents, opts.json));
  return agents;
}

export function formatAgents(agents: AgentListing[], json: boolean): string {
  if (json) return `${JSON.stringify(agents, null, 2)}\n`;
  if (agents.length === 0) return 'No agents. Add one with: keyflap agent add <name>\n';
  const rows = [
    ['ID', 'NAME', 'CREATED', 'REVOKED'],
    ...agents.map((a) => [a.id, a.name, iso(a.createdAt), iso(a.revokedAt)]),
  ];
  const widths = [0, 1, 2].map((i) => Math.max(...rows.map((r) => (r[i] as string).length)));
  return `${rows
    .map((r) =>
      r
        .map((c, i) => (i < 3 ? c.padEnd(widths[i] as number) : c))
        .join('  ')
        .trimEnd(),
    )
    .join('\n')}\n`;
}

export function agentRevoke(opts: { dataDir: string; id: string }, out: Out): boolean {
  const revoked = withRegistry(opts.dataDir, (registry, audit, db) => {
    const ok = registry.revoke(opts.id);
    if (ok) {
      appendAudit(audit, 'agent.revoked', { agentId: opts.id });
      let had = false;
      if (isAgentId(opts.id)) {
        try {
          unlinkSync(join(opts.dataDir, 'browser-state', `${opts.id}.state`));
          had = true;
        } catch {}
      }
      new SessionStateRepo(db).forgetAgent(opts.id);
      new PersistOptins(db).forgetAgent(opts.id);
      if (had) {
        appendAudit(audit, 'browser_state.deleted', { agentId: opts.id, reason: 'revoked' });
      }
    }
    return ok;
  });
  if (revoked) out(`Revoked agent ${opts.id}. Its token stops working on its next request.\n`);
  return revoked;
}

function appendAudit(audit: AuditLog, type: string, payload: Record<string, unknown>): void {
  let lastErr: unknown;
  for (let i = 0; i < 5; i++) {
    try {
      audit.append(type, payload);
      return;
    } catch (err) {
      lastErr = err;
    }
  }
  throw lastErr;
}
