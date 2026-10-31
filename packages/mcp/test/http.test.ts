import { afterEach, describe, expect, it } from 'vitest';
import { type McpHttpServer, startMcpHttpServer } from '../src/index.ts';
import { connect, fakePort, INIT_BODY, rawRequest, resolverFor } from './helpers.ts';

const portA = fakePort();
const portB = fakePort();
const resolve = resolverFor({
  'tok-a': { agentId: 'agent-a', port: portA },
  'tok-b': { agentId: 'agent-b', port: portB },
});

let server: McpHttpServer | undefined;
afterEach(async () => {
  await server?.close();
  server = undefined;
  portA.calls.length = 0;
  portB.calls.length = 0;
});

const init = JSON.stringify(INIT_BODY);

describe('MCP HTTP authentication', () => {
  it('rejects a request without a bearer token (401)', async () => {
    server = await startMcpHttpServer({ resolve });
    const r = await rawRequest(server.url, { body: init });
    expect(r.status).toBe(401);
    expect(r.headers['www-authenticate']).toBe('Bearer');
  });

  it('rejects an unknown or malformed token (401)', async () => {
    server = await startMcpHttpServer({ resolve });
    for (const auth of ['Bearer nope', 'Basic dG9rLWE6', 'Bearer', 'tok-a']) {
      const r = await rawRequest(server.url, { body: init, headers: { authorization: auth } });
      expect(r.status, auth).toBe(401);
    }
  });

  it('a resolver that throws is a denial (401), not a crash', async () => {
    server = await startMcpHttpServer({
      resolve: () => {
        throw new Error('db down');
      },
    });
    const r = await rawRequest(server.url, { body: init, headers: { authorization: 'Bearer x' } });
    expect(r.status).toBe(401);
    expect(r.body).not.toContain('db down');
  });

  it('accepts a valid token (raw initialize succeeds)', async () => {
    server = await startMcpHttpServer({ resolve });
    const r = await rawRequest(server.url, {
      body: init,
      headers: { authorization: 'Bearer tok-a' },
    });
    expect(r.status).toBe(200);
    expect(r.headers['mcp-session-id']).toBeTruthy();
  });

  it('resolves the token on every request: a revoked token is refused mid-session', async () => {
    const tokens = new Map([['tok-a', { agentId: 'agent-a', port: portA }]]);
    server = await startMcpHttpServer({ resolve: (t) => tokens.get(t) ?? null });
    const { client } = await connect(server.url, 'tok-a');
    await client.callTool({ name: 'auth_status', arguments: {} });
    tokens.delete('tok-a');
    await expect(client.callTool({ name: 'auth_status', arguments: {} })).rejects.toThrow();
    expect(portA.calls).toHaveLength(1);
    await client.close();
  });
});

describe('MCP HTTP browser / DNS-rebinding protection', () => {
  it('refuses any request with an Origin header (403), even with a valid token', async () => {
    server = await startMcpHttpServer({ resolve });
    const port = new URL(server.url).port;
    for (const origin of ['https://evil.localhost', `http://127.0.0.1:${port}`, 'null']) {
      const r = await rawRequest(server.url, {
        body: init,
        headers: { authorization: 'Bearer tok-a', origin },
      });
      expect(r.status, origin).toBe(403);
    }
  });

  it('refuses a non-loopback Host header (403)', async () => {
    server = await startMcpHttpServer({ resolve });
    const port = new URL(server.url).port;
    for (const host of [
      `evil.example:${port}`,
      `rebind.attacker.test:${port}`,
      '127.0.0.1',
      `127.0.0.1:${Number(port) + 1}`,
      `192.168.1.10:${port}`,
    ]) {
      const r = await rawRequest(server.url, {
        body: init,
        headers: { authorization: 'Bearer tok-a', host },
      });
      expect(r.status, host).toBe(403);
    }
  });

  it('accepts the loopback Host spellings', async () => {
    server = await startMcpHttpServer({ resolve });
    const port = new URL(server.url).port;
    for (const host of [`127.0.0.1:${port}`, `localhost:${port}`, `[::1]:${port}`]) {
      const r = await rawRequest(server.url, {
        body: init,
        headers: { authorization: 'Bearer tok-a', host },
      });
      expect(r.status, host).toBe(200);
    }
  });

  it('only serves /mcp', async () => {
    server = await startMcpHttpServer({ resolve });
    const r = await rawRequest(server.url.replace(/\/mcp$/, '/other'), {
      body: init,
      headers: { authorization: 'Bearer tok-a' },
    });
    expect(r.status).toBe(404);
  });

  it('caps the request body (413)', async () => {
    server = await startMcpHttpServer({ resolve });
    const big = JSON.stringify({ ...INIT_BODY, pad: 'x'.repeat(1024 * 1024 + 10) });
    const r = await rawRequest(server.url, {
      body: big,
      headers: { authorization: 'Bearer tok-a' },
    });
    expect(r.status).toBe(413);
  });

  it('a non-initialize request without a session is refused (400)', async () => {
    server = await startMcpHttpServer({ resolve });
    const r = await rawRequest(server.url, {
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
      headers: { authorization: 'Bearer tok-a' },
    });
    expect(r.status).toBe(400);
  });
});

describe('MCP sessions are bound to their agent', () => {
  it("agent B's valid token on agent A's session is refused (403)", async () => {
    server = await startMcpHttpServer({ resolve });
    const { client, transport } = await connect(server.url, 'tok-a');
    const sessionId = transport.sessionId;
    expect(sessionId).toBeTruthy();
    const call = JSON.stringify({
      jsonrpc: '2.0',
      id: 7,
      method: 'tools/call',
      params: { name: 'auth_status', arguments: {} },
    });
    const hijack = await rawRequest(server.url, {
      body: call,
      headers: {
        authorization: 'Bearer tok-b',
        'mcp-session-id': sessionId as string,
        'mcp-protocol-version': '2025-06-18',
      },
    });
    expect(hijack.status).toBe(403);
    for (const method of ['GET', 'DELETE']) {
      const r = await rawRequest(server.url, {
        method,
        headers: { authorization: 'Bearer tok-b', 'mcp-session-id': sessionId as string },
      });
      expect(r.status, method).toBe(403);
    }
    expect(portA.calls).toEqual([]);
    expect(portB.calls).toEqual([]);
    const r = await client.callTool({ name: 'auth_status', arguments: {} });
    expect(r.isError).toBeFalsy();
    expect(portA.calls).toHaveLength(1);
    await client.close();
  });

  it('an unknown session id is 404', async () => {
    server = await startMcpHttpServer({ resolve });
    const r = await rawRequest(server.url, {
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
      headers: { authorization: 'Bearer tok-a', 'mcp-session-id': 'not-a-session' },
    });
    expect(r.status).toBe(404);
  });

  it('two agents each reach only their own port', async () => {
    const events: { agentId: string; tool: string; ok: boolean }[] = [];
    server = await startMcpHttpServer({ resolve, onToolCall: (e) => events.push(e) });
    const a = await connect(server.url, 'tok-a');
    const b = await connect(server.url, 'tok-b');
    expect(a.transport.sessionId).not.toBe(b.transport.sessionId);
    await a.client.callTool({ name: 'browser_open', arguments: { url: 'https://a.localhost/' } });
    await b.client.callTool({ name: 'browser_open', arguments: { url: 'https://b.localhost/' } });
    await b.client.callTool({ name: 'auth_login', arguments: {} });
    expect(portA.calls).toEqual([{ method: 'open', args: ['https://a.localhost/'] }]);
    expect(portB.calls).toEqual([
      { method: 'open', args: ['https://b.localhost/'] },
      { method: 'authLogin', args: [] },
    ]);
    expect(events).toEqual([
      { agentId: 'agent-a', tool: 'browser_open', ok: true },
      { agentId: 'agent-b', tool: 'browser_open', ok: true },
      { agentId: 'agent-b', tool: 'auth_login', ok: true },
    ]);
    await a.client.close();
    await b.client.close();
  });
});

describe('startMcpHttpServer lifecycle', () => {
  it('refuses a non-loopback bind host', async () => {
    for (const host of ['0.0.0.0', '::', '192.168.1.10', 'example.com', 'localhost']) {
      await expect(startMcpHttpServer({ host, resolve }), host).rejects.toThrow(/loopback/);
    }
  });

  it('binds 127.0.0.1 by default on a random port and returns the /mcp URL', async () => {
    server = await startMcpHttpServer({ resolve });
    expect(server.url).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/mcp$/);
  });

  it('close() ends open sessions and stops listening', async () => {
    const s = await startMcpHttpServer({ resolve });
    const { client } = await connect(s.url, 'tok-a');
    await client.callTool({ name: 'auth_status', arguments: {} });
    await s.close();
    await s.close();
    await expect(
      rawRequest(s.url, { body: init, headers: { authorization: 'Bearer tok-a' } }),
    ).rejects.toThrow(/ECONNREFUSED/);
    await client.close().catch(() => {});
  });
});
