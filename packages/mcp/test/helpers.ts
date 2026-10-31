import { request } from 'node:http';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import type { AgentBrowserPort, AuthenticatedAgent, Locator } from '../src/index.ts';

export interface Call {
  method: string;
  args: unknown[];
}

export function fakePort(
  overrides: Partial<AgentBrowserPort> = {},
): AgentBrowserPort & { calls: Call[] } {
  const calls: Call[] = [];
  const rec = (method: string, args: unknown[]) => calls.push({ method, args });
  const page = { url: 'https://rp.localhost/login', title: 'Login' };
  const base: AgentBrowserPort = {
    open: async (url: string) => {
      rec('open', [url]);
      return { url, title: 'Opened' };
    },
    click: async (target: Locator) => {
      rec('click', [target]);
      return page;
    },
    type: async (...args: unknown[]) => {
      rec('type', args);
      return page;
    },
    snapshot: async () => {
      rec('snapshot', []);
      return { ...page, snapshot: '- button "Sign in"', humanCheck: false };
    },
    authStatus: async () => {
      rec('authStatus', []);
      return {
        origin: 'https://rp.localhost',
        credentials: [{ type: 'passkey' as const }],
        humanCheck: false,
      };
    },
    authLogin: async (...args: unknown[]) => {
      rec('authLogin', args);
      return { status: 'success' as const };
    },
    authEnrollPasskey: async (...args: unknown[]) => {
      rec('authEnrollPasskey', args);
      return { status: 'denied' as const };
    },
    handoff: async (...args: unknown[]) => {
      rec('handoff', args);
      return { status: 'done' as const };
    },
  };
  const wrapped: AgentBrowserPort = { ...base };
  for (const [k, fn] of Object.entries(overrides)) {
    const key = k as keyof AgentBrowserPort;
    (wrapped as unknown as Record<string, unknown>)[key] = async (...args: unknown[]) => {
      rec(key, args);
      return (fn as (...a: unknown[]) => unknown)(...args);
    };
  }
  return Object.assign(wrapped, { calls });
}

export function resolverFor(agents: Record<string, AuthenticatedAgent>) {
  return (token: string): AuthenticatedAgent | null =>
    Object.hasOwn(agents, token) ? (agents[token] ?? null) : null;
}

export async function connect(
  url: string,
  token: string,
): Promise<{
  client: Client;
  transport: StreamableHTTPClientTransport;
}> {
  const transport = new StreamableHTTPClientTransport(new URL(url), {
    requestInit: { headers: { Authorization: `Bearer ${token}` } },
  });
  const client = new Client({ name: 'test-agent', version: '1.0.0' });
  await client.connect(transport);
  return { client, transport };
}

export const INIT_BODY = {
  jsonrpc: '2.0',
  id: 1,
  method: 'initialize',
  params: {
    protocolVersion: '2025-06-18',
    capabilities: {},
    clientInfo: { name: 'raw', version: '1' },
  },
};

export interface RawResponse {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

export function rawRequest(
  url: string,
  opts: { method?: string; headers?: Record<string, string>; body?: string | Buffer } = {},
): Promise<RawResponse> {
  const u = new URL(url);
  return new Promise((resolve, reject) => {
    const req = request(
      {
        host: u.hostname.replace(/^\[|\]$/g, ''),
        port: u.port,
        path: u.pathname,
        method: opts.method ?? 'POST',
        headers: {
          'content-type': 'application/json',
          accept: 'application/json, text/event-stream',
          ...opts.headers,
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () =>
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            body: Buffer.concat(chunks).toString('utf8'),
          }),
        );
        res.on('error', reject);
      },
    );
    req.on('error', reject);
    if (opts.body !== undefined) req.write(opts.body);
    req.end();
  });
}
