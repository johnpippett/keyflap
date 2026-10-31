import { rmSync } from 'node:fs';
import { request } from 'node:http';
import { join } from 'node:path';
import {
  type ApprovalDecision,
  type ApprovalRequest,
  type Approver,
  ApproverKey,
  ScriptedApprover,
} from '@aab/approver';
import { startMcpHttpServer } from '@aab/mcp';
import type { SignedApproval } from '@aab/signer/approval';
import { startTestRp, type TestRp, type TestRpOptions } from '@aab/test-rp';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import type { CallToolResult, Tool } from '@modelcontextprotocol/sdk/types.js';
import type { BrowserContext, Page } from 'playwright';
import type { NewAgent } from '../src/agents.ts';
import { type Daemon, type DaemonOptions, startDaemon } from '../src/daemon.ts';
import { tmpDir } from './harness.ts';

export const PASSPHRASE = 'test-passphrase';

export class CapturingApprover implements Approver {
  readonly inner: ScriptedApprover;
  readonly signed: SignedApproval[] = [];
  decide: (req: ApprovalRequest) => boolean | Promise<boolean> = () => true;

  constructor(key: ApproverKey) {
    this.inner = new ScriptedApprover(key, (req) => this.decide(req));
  }

  get seen(): ApprovalRequest[] {
    return this.inner.seen;
  }

  async request(req: ApprovalRequest): Promise<ApprovalDecision> {
    const d = await this.inner.request(req);
    if (d.approved) this.signed.push(d.approval);
    return d;
  }
}

export interface IntentResponse {
  status: number;
  body: Record<string, unknown>;
}

export function postIntent(
  socketPath: string,
  body: unknown,
  opts: { token?: string | null; authorization?: string } = {},
): Promise<IntentResponse> {
  return new Promise((resolve, reject) => {
    const json = typeof body === 'string' ? body : JSON.stringify(body);
    const headers: Record<string, string | number> = {
      'content-type': 'application/json',
      'content-length': Buffer.byteLength(json),
    };
    if (opts.authorization !== undefined) headers.authorization = opts.authorization;
    else if (opts.token) headers.authorization = `Bearer ${opts.token}`;
    const req = request({ socketPath, path: '/v1/intents', method: 'POST', headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let parsed: Record<string, unknown> = {};
        try {
          parsed = JSON.parse(text) as Record<string, unknown>;
        } catch {}
        resolve({ status: res.statusCode ?? 0, body: parsed });
      });
    });
    req.on('error', reject);
    req.end(json);
  });
}

export interface McpAgent {
  agent: NewAgent;
  client: Client;
  raw: string[];
  results: unknown[];
  calls: number;
  listTools(): Promise<Tool[]>;
  call(
    name: string,
    args?: Record<string, unknown>,
    meta?: Record<string, unknown>,
  ): Promise<CallToolResult>;
  ok<T = Record<string, unknown>>(name: string, args?: Record<string, unknown>): Promise<T>;
  err(name: string, args?: Record<string, unknown>): Promise<string>;
  drain(): Promise<void>;
  everything(): Promise<string>;
  close(): Promise<void>;
}

const textOf = (r: CallToolResult): string =>
  r.content.map((c) => (c.type === 'text' ? c.text : JSON.stringify(c))).join('\n');

export async function connectAgent(
  url: string,
  agent: NewAgent,
  clientInfo: { name: string; version: string; title?: string } = {
    name: 'test-mcp-client',
    version: '1.0.0',
  },
): Promise<McpAgent> {
  const bodies: { text: string }[] = [];
  const pending: Promise<void>[] = [];
  const recordingFetch = async (input: string | URL | Request, init?: RequestInit) => {
    const res = await fetch(input, init);
    const entry = { text: '' };
    bodies.push(entry);
    const reader = res.clone().body?.getReader();
    if (reader) {
      const dec = new TextDecoder();
      pending.push(
        (async () => {
          try {
            for (;;) {
              const { done, value } = await reader.read();
              if (done) break;
              entry.text += dec.decode(value, { stream: true });
            }
          } catch {}
        })(),
      );
    }
    return res;
  };
  const transport = new StreamableHTTPClientTransport(new URL(url), {
    requestInit: { headers: { Authorization: `Bearer ${agent.token}` } },
    fetch: recordingFetch,
  });
  const client = new Client(clientInfo);
  await client.connect(transport);
  const results: unknown[] = [
    client.getServerVersion(),
    client.getServerCapabilities(),
    client.getInstructions(),
  ];
  const self: McpAgent = {
    agent,
    client,
    get raw() {
      return bodies.map((b) => b.text);
    },
    results,
    calls: 0,
    async listTools() {
      const r = await client.listTools();
      results.push(r);
      return r.tools;
    },
    async call(name, args = {}, meta) {
      self.calls++;
      const r = (await client.callTool({
        name,
        arguments: args,
        ...(meta ? { _meta: meta } : {}),
      })) as CallToolResult;
      results.push(r);
      return r;
    },
    async ok<T>(name: string, args: Record<string, unknown> = {}) {
      const r = await self.call(name, args);
      if (r.isError) throw new Error(`${name} failed: ${textOf(r)}`);
      return JSON.parse(textOf(r)) as T;
    },
    async err(name, args = {}) {
      const r = await self.call(name, args);
      if (!r.isError) throw new Error(`${name} unexpectedly succeeded: ${textOf(r)}`);
      return textOf(r);
    },
    async drain() {
      await Promise.race([Promise.all(pending), new Promise((r) => setTimeout(r, 200))]);
    },
    async everything() {
      await self.drain();
      return [...self.raw, JSON.stringify(results)].join('\n');
    },
    async close() {
      await client.close().catch(() => {});
      await self.drain();
    },
  };
  return self;
}

export interface McpHarness {
  rp: TestRp;
  daemon: Daemon;
  dataDir: string;
  approver: CapturingApprover;
  approverKey: ApproverKey;
  agent: NewAgent;
  mcp: McpAgent;
  mcpUrl: string;
  addAgent(name: string, clientInfo?: { name: string; version: string }): Promise<McpAgent>;
  intent(text: string, agentId?: string): Promise<{ intentId: string; expiresAt: number }>;
  post(
    body: unknown,
    opts?: { token?: string | null; authorization?: string },
  ): Promise<IntentResponse>;
  context(agent?: NewAgent): Promise<BrowserContext>;
  page(agent?: NewAgent): Page;
  auditEvents(): { seq: number; type: string; payload: Record<string, unknown> }[];
  close(): Promise<void>;
}

export async function startMcpHarness(
  opts: {
    agentName?: string;
    clientInfo?: { name: string; version: string; title?: string };
    rp?: TestRpOptions;
    daemon?: Partial<DaemonOptions>;
  } = {},
): Promise<McpHarness> {
  const rp = await startTestRp({ host: 'rp.localhost', ...opts.rp });
  const dataDir = tmpDir();
  const approverKey = ApproverKey.generate('test-approver');
  const approver = new CapturingApprover(approverKey);
  let daemon: Daemon;
  try {
    daemon = await startDaemon({
      dataDir,
      passphrase: PASSPHRASE,
      approver,
      trustedApproverKeys: approverKey.trustEntry(),
      approvalTimeoutMs: 10_000,
      actionTimeoutMs: 3_000,
      startMcp: (deps) => startMcpHttpServer(deps),
      ...opts.daemon,
    });
  } catch (err) {
    await rp.close();
    throw err;
  }
  const mcpUrl = daemon.mcpUrl;
  if (!mcpUrl) throw new Error('daemon started without MCP');
  const clients: McpAgent[] = [];
  const agent = daemon.registry.add(opts.agentName ?? 'test-agent');
  const mcp = await connectAgent(mcpUrl, agent, opts.clientInfo);
  clients.push(mcp);

  const post: McpHarness['post'] = (body, o = { token: daemon.hostToken }) =>
    postIntent(daemon.intentSocketPath, body, o);

  return {
    rp,
    daemon,
    dataDir,
    approver,
    approverKey,
    agent,
    mcp,
    mcpUrl,
    async addAgent(name, clientInfo) {
      const a = daemon.registry.add(name);
      const c = await connectAgent(mcpUrl, a, clientInfo);
      clients.push(c);
      return c;
    },
    async intent(text, agentId = agent.id) {
      const r = await post({ agentId, text });
      if (r.status !== 201) throw new Error(`intent socket answered ${r.status}`);
      return r.body as { intentId: string; expiresAt: number };
    },
    post,
    async context(a = agent) {
      return (await daemon.sessions.get(a)).context;
    },
    page(a = agent) {
      const p = daemon.sessions.peek(a.id)?.currentPage();
      if (!p) throw new Error('no page');
      return p;
    },
    auditEvents() {
      return daemon.broker.audit.all().map((r) => ({
        seq: r.seq,
        type: r.event_type,
        payload: JSON.parse(r.payload_json) as Record<string, unknown>,
      }));
    },
    async close() {
      for (const c of clients) await c.close();
      await daemon.stop();
      await rp.close();
      rmSync(dataDir, { recursive: true, force: true });
    },
  };
}

export const keyStorePath = (dataDir: string) => join(dataDir, 'signer', 'keys.enc.json');
export const dbPath = (dataDir: string) => join(dataDir, 'broker.sqlite');

export async function mcpSignUp(h: McpHarness, m: McpAgent, username: string): Promise<void> {
  await m.ok('browser_open', { url: `${h.rp.url}signup` });
  const r = await m.ok<{ url: string }>('browser_type', {
    target: { label: 'Username' },
    text: username,
    submit: true,
  });
  if (r.url !== `${h.rp.url}account`) throw new Error(`sign-up landed on ${r.url}`);
}
