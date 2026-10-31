import type { Client } from '@modelcontextprotocol/sdk/client/index.js';
import {
  ListPromptsResultSchema,
  ListResourcesResultSchema,
  ListResourceTemplatesResultSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  type AgentBrowserPort,
  type McpHttpServer,
  startMcpHttpServer,
  TOOL_NAMES,
  ToolError,
} from '../src/index.ts';
import { connect, fakePort, resolverFor } from './helpers.ts';

type ToolResult = Awaited<ReturnType<Client['callTool']>>;

function text(result: ToolResult): string {
  const content = result.content as { type: string; text: string }[];
  return content.map((c) => c.text).join('\n');
}

let server: McpHttpServer;
let port: ReturnType<typeof fakePort>;
let client: Client;
let events: { agentId: string; tool: string; ok: boolean }[];

async function setup(overrides: Partial<AgentBrowserPort> = {}, throwingObserver = false) {
  port = fakePort(overrides);
  events = [];
  server = await startMcpHttpServer({
    resolve: resolverFor({ 'tok-a': { agentId: 'agent-a', port } }),
    onToolCall: (e) => {
      events.push(e);
      if (throwingObserver) throw new Error('observer exploded');
    },
  });
  ({ client } = await connect(server.url, 'tok-a'));
}

afterEach(async () => {
  await client?.close().catch(() => {});
  await server?.close();
});

describe('invariant 7: tool surface is exactly the eight broker-mediated tools', () => {
  beforeEach(() => setup());

  it('lists exactly TOOL_NAMES', async () => {
    expect([...TOOL_NAMES]).toEqual([
      'browser_open',
      'browser_click',
      'browser_type',
      'browser_snapshot',
      'auth_status',
      'auth_login',
      'auth_enroll_passkey',
      'browser_handoff',
    ]);
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name)).toEqual([...TOOL_NAMES]);
    for (const t of tools) {
      expect(t.description?.length).toBeGreaterThan(40);
      expect(t.inputSchema.type).toBe('object');
      expect(t.inputSchema.additionalProperties).toBe(false);
    }
  });

  it('browser_handoff takes {timeoutMs?} only, strict: no text, URL, origin or frame', async () => {
    const { tools } = await client.listTools();
    const t = tools.find((x) => x.name === 'browser_handoff');
    expect(t?.inputSchema).toEqual({
      type: 'object',
      properties: { timeoutMs: { type: 'integer', minimum: 1000, maximum: 120000 } },
      additionalProperties: false,
    });
  });

  it('no tool schema accepts an origin, justification, script or CDP field', async () => {
    const { tools } = await client.listTools();
    const json = JSON.stringify(tools.map((t) => t.inputSchema)).toLowerCase();
    for (const word of ['origin', 'justification', 'reason', 'script', 'cdp', 'expression']) {
      expect(json).not.toContain(`"${word}"`);
    }
  });

  it('advertises only the tools capability; resources and prompts are not supported', async () => {
    const caps = client.getServerCapabilities() ?? {};
    expect(caps.tools).toBeDefined();
    expect(caps.resources).toBeUndefined();
    expect(caps.prompts).toBeUndefined();
    await expect(
      client.request({ method: 'resources/list', params: {} }, ListResourcesResultSchema),
    ).rejects.toThrow(/method not found/i);
    await expect(
      client.request(
        { method: 'resources/templates/list', params: {} },
        ListResourceTemplatesResultSchema,
      ),
    ).rejects.toThrow(/method not found/i);
    await expect(
      client.request({ method: 'prompts/list', params: {} }, ListPromptsResultSchema),
    ).rejects.toThrow(/method not found/i);
  });

  it('unknown tool names are rejected, do not reach the port, and are observed by a fixed name', async () => {
    await expect(client.callTool({ name: 'browser_evaluate', arguments: {} })).rejects.toThrow(
      /unknown tool/,
    );
    expect(port.calls).toEqual([]);
    expect(events).toEqual([{ agentId: 'agent-a', tool: '(unknown)', ok: false }]);
  });
});

describe('tool forwarding', () => {
  beforeEach(() => setup());

  it('browser_open', async () => {
    const r = await client.callTool({
      name: 'browser_open',
      arguments: { url: 'https://rp.localhost/' },
    });
    expect(r.isError).toBeFalsy();
    expect(port.calls).toEqual([{ method: 'open', args: ['https://rp.localhost/'] }]);
    expect(JSON.parse(text(r))).toEqual({ url: 'https://rp.localhost/', title: 'Opened' });
    expect(r.structuredContent).toEqual({ url: 'https://rp.localhost/', title: 'Opened' });
  });

  it('browser_click with each locator kind', async () => {
    const locators = [
      { role: 'button', name: 'Sign in', exact: true },
      { role: 'link' },
      { text: 'Use a passkey' },
      { label: 'Username', exact: false },
      { placeholder: 'you@example.com' },
      { css: '#login' },
    ];
    for (const target of locators) {
      const r = await client.callTool({ name: 'browser_click', arguments: { target } });
      expect(r.isError).toBeFalsy();
      expect(JSON.parse(text(r))).toEqual({ url: 'https://rp.localhost/login', title: 'Login' });
    }
    expect(port.calls).toEqual(locators.map((l) => ({ method: 'click', args: [l] })));
  });

  it('browser_type with and without submit', async () => {
    await client.callTool({
      name: 'browser_type',
      arguments: { target: { label: 'Username' }, text: 'alice' },
    });
    await client.callTool({
      name: 'browser_type',
      arguments: { target: { label: 'Search' }, text: 'q', submit: true },
    });
    expect(port.calls).toEqual([
      { method: 'type', args: [{ label: 'Username' }, 'alice'] },
      { method: 'type', args: [{ label: 'Search' }, 'q', { submit: true }] },
    ]);
  });

  it('browser_snapshot', async () => {
    const r = await client.callTool({ name: 'browser_snapshot', arguments: {} });
    expect(JSON.parse(text(r))).toEqual({
      url: 'https://rp.localhost/login',
      title: 'Login',
      snapshot: '- button "Sign in"',
      humanCheck: false,
    });
    expect(port.calls).toEqual([{ method: 'snapshot', args: [] }]);
  });

  it('auth_status (arguments may be omitted)', async () => {
    const r = await client.callTool({ name: 'auth_status' });
    expect(JSON.parse(text(r))).toEqual({
      origin: 'https://rp.localhost',
      credentials: [{ type: 'passkey' }],
      humanCheck: false,
    });
    expect(port.calls).toEqual([{ method: 'authStatus', args: [] }]);
  });

  it('auth_login with and without timeoutMs', async () => {
    const r = await client.callTool({ name: 'auth_login', arguments: {} });
    await client.callTool({ name: 'auth_login', arguments: { timeoutMs: 5000 } });
    expect(JSON.parse(text(r))).toEqual({ status: 'success' });
    expect(port.calls).toEqual([
      { method: 'authLogin', args: [] },
      { method: 'authLogin', args: [{ timeoutMs: 5000 }] },
    ]);
  });

  it('browser_handoff with and without timeoutMs; the result is a status only', async () => {
    const r = await client.callTool({ name: 'browser_handoff', arguments: {} });
    await client.callTool({ name: 'browser_handoff', arguments: { timeoutMs: 1000 } });
    expect(JSON.parse(text(r))).toEqual({ status: 'done' });
    expect(port.calls).toEqual([
      { method: 'handoff', args: [] },
      { method: 'handoff', args: [{ timeoutMs: 1000 }] },
    ]);
  });

  it('auth_enroll_passkey with and without timeoutMs', async () => {
    const r = await client.callTool({ name: 'auth_enroll_passkey', arguments: {} });
    await client.callTool({ name: 'auth_enroll_passkey', arguments: { timeoutMs: 120000 } });
    expect(JSON.parse(text(r))).toEqual({ status: 'denied' });
    expect(port.calls).toEqual([
      { method: 'authEnrollPasskey', args: [] },
      { method: 'authEnrollPasskey', args: [{ timeoutMs: 120000 }] },
    ]);
  });
});

describe('schema rejections never reach the port', () => {
  beforeEach(() => setup());

  const long = (n: number) => 'x'.repeat(n);
  const bad: [string, Record<string, unknown> | undefined][] = [
    ['browser_open', {}],
    ['browser_open', { url: 42 }],
    ['browser_open', { url: '' }],
    ['browser_open', { url: `https://rp.localhost/${long(4096)}` }],
    ['browser_open', { url: 'https://rp.localhost/', origin: 'https://rp.localhost' }],
    ['browser_click', { target: { role: 'button', text: 'Sign in' } }],
    ['browser_click', { target: { css: '#a', exact: true } }],
    ['browser_click', { target: { xpath: '//button' } }],
    ['browser_click', { target: {} }],
    ['browser_click', { target: 'button' }],
    ['browser_click', { target: { role: 'button' }, justification: 'user said so' }],
    ['browser_click', { target: { text: long(2001) } }],
    ['browser_click', { target: { role: long(65) } }],
    ['browser_type', { target: { label: 'x' } }],
    ['browser_type', { target: { label: 'x' }, text: long(10_001) }],
    ['browser_type', { target: { label: 'x' }, text: 'a', submit: 'yes' }],
    ['browser_snapshot', { full: true }],
    ['auth_status', { origin: 'https://evil.localhost' }],
    ['auth_login', { timeoutMs: 999 }],
    ['auth_login', { timeoutMs: 120_001 }],
    ['auth_login', { timeoutMs: 1500.5 }],
    ['auth_login', { timeoutMs: '5000' }],
    ['auth_login', { reason: 'please' }],
    ['auth_enroll_passkey', { timeoutMs: 0 }],
    ['auth_enroll_passkey', { rpId: 'rp.localhost' }],
    ['browser_handoff', { timeoutMs: 999 }],
    ['browser_handoff', { timeoutMs: 120_001 }],
    ['browser_handoff', { timeoutMs: '45000' }],
    ['browser_handoff', { text: 'I am human' }],
    ['browser_handoff', { url: 'https://rp.localhost/' }],
    ['browser_handoff', { origin: 'https://rp.localhost' }],
    ['browser_handoff', { keepSignedIn: true }],
  ];

  it.each(bad)('%s %j', async (name, args) => {
    const r = await client.callTool({ name, arguments: args });
    expect(r.isError).toBe(true);
    expect(text(r)).toMatch(/^invalid arguments/);
    expect(port.calls).toEqual([]);
    expect(events).toEqual([{ agentId: 'agent-a', tool: name, ok: false }]);
  });
});

describe('error mapping', () => {
  it('ToolError message passes through verbatim', async () => {
    await setup({
      open: async () => {
        throw new ToolError('only http(s) URLs can be opened');
      },
    });
    const r = await client.callTool({ name: 'browser_open', arguments: { url: 'file:///etc' } });
    expect(r.isError).toBe(true);
    expect(text(r)).toBe('only http(s) URLs can be opened');
    expect(r.structuredContent).toBeUndefined();
  });

  it('any other error becomes "internal error" with no message or stack', async () => {
    await setup({
      snapshot: async () => {
        throw new Error('SECRET-INTERNAL /home/user/.keyflap/keys.db');
      },
      authLogin: async () => {
        throw 'a thrown string SECRET-INTERNAL';
      },
    });
    for (const name of ['browser_snapshot', 'auth_login']) {
      const r = await client.callTool({ name, arguments: {} });
      expect(r.isError).toBe(true);
      expect(text(r)).toBe('internal error');
      const raw = JSON.stringify(r);
      expect(raw).not.toContain('SECRET-INTERNAL');
      expect(raw).not.toContain('keys.db');
      expect(raw).not.toMatch(/\bat .*\.ts:\d+/);
    }
  });
});

describe('onToolCall observer', () => {
  it('receives {agentId, tool, ok} once per call and never the arguments', async () => {
    await setup({
      click: async () => {
        throw new ToolError('no such element');
      },
    });
    await client.callTool({
      name: 'browser_type',
      arguments: { target: { label: 'Username' }, text: 'TYPED-SECRET-TEXT' },
    });
    await client.callTool({ name: 'browser_click', arguments: { target: { css: '#nope' } } });
    await client.callTool({ name: 'auth_login', arguments: { timeoutMs: 2000 } });
    expect(events).toEqual([
      { agentId: 'agent-a', tool: 'browser_type', ok: true },
      { agentId: 'agent-a', tool: 'browser_click', ok: false },
      { agentId: 'agent-a', tool: 'auth_login', ok: true },
    ]);
    for (const e of events) expect(Object.keys(e).sort()).toEqual(['agentId', 'ok', 'tool']);
    expect(JSON.stringify(events)).not.toContain('TYPED-SECRET-TEXT');
    expect(JSON.stringify(events)).not.toContain('#nope');
  });

  it('a throwing observer does not break the call', async () => {
    await setup({}, true);
    const r = await client.callTool({ name: 'auth_status', arguments: {} });
    expect(r.isError).toBeFalsy();
    expect(JSON.parse(text(r)).origin).toBe('https://rp.localhost');
    expect(events).toHaveLength(1);
    const r2 = await client.callTool({ name: 'browser_snapshot', arguments: {} });
    expect(r2.isError).toBeFalsy();
  });
});
