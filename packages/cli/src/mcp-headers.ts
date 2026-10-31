import { lstatSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const AGENT_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const TOKEN_RE = /^aab_agent_[A-Za-z0-9_-]{43}$/;

export class HeadersError extends Error {
  override name = 'HeadersError';
}

export function isAgentIdShape(id: string): boolean {
  return AGENT_ID_RE.test(id);
}

export function devAgentTokenPath(dataDir: string, agentId: string): string {
  if (!isAgentIdShape(agentId)) throw new HeadersError('not an agent id');
  return join(dataDir, 'agents', `${agentId}.token`);
}

export function serviceAgentTokenPath(hookDir: string, agentId: string): string {
  if (!isAgentIdShape(agentId)) throw new HeadersError('not an agent id');
  return join(hookDir, `agent-${agentId}.token`);
}

export function readAgentToken(path: string, uid: number | null = process.getuid?.() ?? null) {
  let st: ReturnType<typeof lstatSync>;
  try {
    st = lstatSync(path);
  } catch (err) {
    throw new HeadersError(
      `cannot read the agent token (${(err as NodeJS.ErrnoException).code ?? 'error'}); re-run keyflap setup`,
    );
  }
  if (!st.isFile()) throw new HeadersError('the agent token is not a regular file');
  if ((st.mode & 0o077) !== 0) throw new HeadersError('the agent token is accessible to others');
  if (uid !== null && st.uid !== uid)
    throw new HeadersError('the agent token is owned by another user');
  const token = readFileSync(path, 'utf8').trim();
  if (!TOKEN_RE.test(token)) throw new HeadersError('the agent token file is malformed');
  return token;
}

export function mcpHeadersJson(token: string): string {
  return `${JSON.stringify({ Authorization: `Bearer ${token}` })}\n`;
}
