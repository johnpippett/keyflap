import { randomUUID } from 'node:crypto';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import {
  CallToolRequestSchema,
  type CallToolResult,
  ErrorCode,
  isInitializeRequest,
  ListToolsRequestSchema,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';
import type { z } from 'zod';
import type { AgentBrowserPort, AgentResolver, ToolCallObserver } from './port.ts';
import { ToolError } from './port.ts';
import { findTool, inputJsonSchema, TOOLS } from './tools.ts';

export interface McpHttpServerOptions {
  host?: string;
  port?: number;
  resolve: AgentResolver;
  onToolCall?: ToolCallObserver;
}

export interface McpHttpServer {
  url: string;
  close(): Promise<void>;
}

const MCP_PATH = '/mcp';
const MAX_BODY_BYTES = 1024 * 1024;
const MAX_SESSIONS_PER_AGENT = 16;
const LOOPBACK_HOSTS = new Set(['127.0.0.1', '::1']);
export const UNKNOWN_TOOL = '(unknown)';

interface Binding {
  agentId: string;
  port: AgentBrowserPort;
}

interface Session {
  binding: Binding;
  transport: StreamableHTTPServerTransport;
  server: Server;
}

export async function startMcpHttpServer(opts: McpHttpServerOptions): Promise<McpHttpServer> {
  const host = opts.host ?? '127.0.0.1';
  if (!LOOPBACK_HOSTS.has(host)) {
    throw new Error(`MCP server must bind to a loopback address (127.0.0.1 or ::1), got ${host}`);
  }
  const resolve = opts.resolve;
  const observe = opts.onToolCall;
  const sessions = new Map<string, Session>();
  let allowedHosts = new Set<string>();
  let closing = false;

  const notify = (agentId: string, tool: string, ok: boolean): void => {
    if (!observe) return;
    try {
      const r: unknown = observe({ agentId, tool, ok });
      if (r instanceof Promise) r.catch(() => {});
    } catch {}
  };

  const buildServer = (session: Binding): Server => {
    const server = new Server(
      { name: 'keyflap', version: '0.0.0' },
      {
        capabilities: { tools: {} },
        instructions:
          'Drive a broker-managed browser with the browser_* tools. When a site needs you to sign in, ' +
          'click its passkey / sign-in button and call auth_login: the broker asks the user to approve on their own device ' +
          'and signs in for you. You never see or handle credentials. If a site answers with a human check ' +
          '(CAPTCHA), never try to solve it: call browser_handoff so the user completes it on their phone.',
      },
    );
    server.setRequestHandler(ListToolsRequestSchema, () => ({
      tools: TOOLS.map((t) => ({
        name: t.name,
        title: t.title,
        description: t.description,
        inputSchema: inputJsonSchema(t),
      })),
    }));
    server.setRequestHandler(CallToolRequestSchema, async (request): Promise<CallToolResult> => {
      const def = findTool(request.params.name);
      if (!def) {
        notify(session.agentId, UNKNOWN_TOOL, false);
        throw new McpError(ErrorCode.InvalidParams, 'unknown tool');
      }
      const result = await runTool(def, session.port, request.params.arguments ?? {});
      notify(session.agentId, def.name, result.isError !== true);
      return result;
    });
    return server;
  };

  const handle = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    if (closing) return reject(res, 503, 'server closing');
    const path = (req.url ?? '').split('?')[0];
    if (path !== MCP_PATH) return reject(res, 404, 'not found');
    if (req.headers.origin !== undefined) return reject(res, 403, 'forbidden');
    const hostHeader = req.headers.host?.toLowerCase();
    if (hostHeader === undefined || !allowedHosts.has(hostHeader)) {
      return reject(res, 403, 'forbidden');
    }
    const token = bearerToken(req.headers.authorization);
    let agent: ReturnType<AgentResolver> = null;
    if (token !== null) {
      try {
        agent = resolve(token);
      } catch {
        agent = null;
      }
    }
    if (!agent) {
      res.setHeader('WWW-Authenticate', 'Bearer');
      return reject(res, 401, 'unauthorized');
    }

    const sessionHeader = req.headers['mcp-session-id'];
    if (Array.isArray(sessionHeader)) return reject(res, 400, 'bad request');

    let body: unknown;
    if (req.method === 'POST') {
      const read = await readJsonBody(req);
      if (read.error === 'too_large') return reject(res, 413, 'payload too large', true);
      if (read.error === 'invalid') return reject(res, 400, 'parse error', false, -32700);
      body = read.value;
    }

    if (sessionHeader !== undefined) {
      const session = sessions.get(sessionHeader);
      if (!session) return reject(res, 404, 'session not found');
      if (session.binding.agentId !== agent.agentId) return reject(res, 403, 'forbidden');
      session.binding.port = agent.port;
      await session.transport.handleRequest(req, res, body);
      return;
    }

    if (req.method !== 'POST' || !isInitializeRequest(body)) {
      return reject(res, 400, 'bad request: no valid session id');
    }

    const agentId = agent.agentId;
    const binding: Binding = { agentId, port: agent.port };
    const server = buildServer(binding);
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      onsessioninitialized: (id) => {
        sessions.set(id, { binding, transport, server });
        evictOldSessions(agentId);
      },
    });
    transport.onclose = () => {
      const id = transport.sessionId;
      if (id !== undefined && sessions.get(id)?.transport === transport) sessions.delete(id);
    };
    await server.connect(transport);
    await transport.handleRequest(req, res, body);
    if (transport.sessionId === undefined) {
      await server.close().catch(() => {});
    }
  };

  const evictOldSessions = (agentId: string): void => {
    const mine = [...sessions.entries()].filter(([, s]) => s.binding.agentId === agentId);
    for (const [id, s] of mine.slice(0, Math.max(0, mine.length - MAX_SESSIONS_PER_AGENT))) {
      sessions.delete(id);
      void s.server.close().catch(() => {});
    }
  };

  const http = createServer((req, res) => {
    handle(req, res).catch(() => {
      if (!res.headersSent) reject(res, 500, 'internal error');
      else res.destroy();
    });
  });
  http.requestTimeout = 5 * 60_000;

  await new Promise<void>((ok, fail) => {
    http.once('error', fail);
    http.listen(opts.port ?? 0, host, () => {
      http.off('error', fail);
      ok();
    });
  });
  const boundPort = (http.address() as AddressInfo).port;
  allowedHosts = new Set([
    `127.0.0.1:${boundPort}`,
    `localhost:${boundPort}`,
    `[::1]:${boundPort}`,
  ]);
  const urlHost = host === '::1' ? '[::1]' : host;

  return {
    url: `http://${urlHost}:${boundPort}${MCP_PATH}`,
    close: async () => {
      if (closing) return;
      closing = true;
      const all = [...sessions.values()];
      sessions.clear();
      await Promise.all(all.map((s) => s.server.close().catch(() => {})));
      await new Promise<void>((ok) => {
        http.close(() => ok());
        http.closeAllConnections();
      });
    },
  };
}

async function runTool(
  def: NonNullable<ReturnType<typeof findTool>>,
  port: AgentBrowserPort,
  rawArgs: unknown,
): Promise<CallToolResult> {
  const parsed = def.schema.safeParse(rawArgs);
  if (!parsed.success) {
    return errorResult(`invalid arguments: ${describeIssues(parsed.error)}`);
  }
  try {
    const value = await def.run(port, parsed.data);
    const structured =
      value !== null && typeof value === 'object' && !Array.isArray(value)
        ? (value as Record<string, unknown>)
        : undefined;
    return {
      content: [{ type: 'text', text: JSON.stringify(value) }],
      ...(structured ? { structuredContent: structured } : {}),
    };
  } catch (err) {
    if (err instanceof ToolError) return errorResult(err.message);
    return errorResult('internal error');
  }
}

function errorResult(text: string): CallToolResult {
  return { content: [{ type: 'text', text }], isError: true };
}

function describeIssues(error: z.ZodError): string {
  return error.issues
    .slice(0, 5)
    .map((i) => (i.path.length ? `${i.path.join('.')}: ${i.message}` : i.message))
    .join('; ');
}

function bearerToken(header: string | undefined): string | null {
  if (header === undefined) return null;
  const m = /^Bearer ([^\s]+)$/i.exec(header.trim());
  return m?.[1] ?? null;
}

type BodyRead =
  | { error: 'too_large' | 'invalid'; value?: undefined }
  | { error?: undefined; value: unknown };

function readJsonBody(req: IncomingMessage): Promise<BodyRead> {
  const declared = Number(req.headers['content-length']);
  if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) {
    req.resume();
    return Promise.resolve({ error: 'too_large' });
  }
  return new Promise((done) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let finished = false;
    const finish = (r: BodyRead) => {
      if (finished) return;
      finished = true;
      done(r);
    };
    req.on('data', (chunk: Buffer) => {
      if (finished) return;
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        chunks.length = 0;
        finish({ error: 'too_large' });
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      try {
        finish({ value: JSON.parse(Buffer.concat(chunks).toString('utf8')) });
      } catch {
        finish({ error: 'invalid' });
      }
    });
    req.on('error', () => finish({ error: 'invalid' }));
  });
}

function reject(
  res: ServerResponse,
  status: number,
  message: string,
  closeConnection = false,
  code = -32000,
): void {
  if (res.headersSent) {
    res.destroy();
    return;
  }
  if (closeConnection) res.setHeader('Connection', 'close');
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify({ jsonrpc: '2.0', error: { code, message }, id: null }));
}
