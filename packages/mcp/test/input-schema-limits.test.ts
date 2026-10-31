import type { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { type McpHttpServer, startMcpHttpServer } from '../src/index.ts';
import { connect, fakePort, resolverFor } from './helpers.ts';

type Schema = Record<string, unknown>;

function strings(node: unknown, path: string, out: { path: string; maxLength: unknown }[]) {
  if (Array.isArray(node)) {
    node.forEach((n, i) => {
      strings(n, `${path}[${i}]`, out);
    });
    return;
  }
  if (typeof node !== 'object' || node === null) return;
  const s = node as Schema;
  if (s.type === 'string' || (Array.isArray(s.type) && s.type.includes('string'))) {
    out.push({ path, maxLength: s.maxLength });
  }
  for (const [k, v] of Object.entries(s)) strings(v, `${path}.${k}`, out);
}

describe('every string an agent can send to a tool has a length cap', () => {
  let server: McpHttpServer;
  let client: Client;

  beforeAll(async () => {
    server = await startMcpHttpServer({
      resolve: resolverFor({ 'tok-a': { agentId: 'agent-a', port: fakePort() } }),
    });
    ({ client } = await connect(server.url, 'tok-a'));
  });

  afterAll(async () => {
    await client?.close().catch(() => {});
    await server?.close();
  });

  it('each string in each tool inputSchema, locator variants included, has maxLength', async () => {
    const { tools } = await client.listTools();
    const found: { path: string; maxLength: unknown }[] = [];
    for (const t of tools) strings(t.inputSchema, t.name, found);
    expect(found.map((f) => f.path)).toEqual(
      expect.arrayContaining([
        'browser_open.properties.url',
        'browser_type.properties.text',
        'browser_click.properties.target.anyOf[0].properties.role',
        'browser_click.properties.target.anyOf[0].properties.name',
        'browser_click.properties.target.anyOf[4].properties.css',
      ]),
    );
    expect(found.length).toBeGreaterThanOrEqual(9);
    const uncapped = found.filter((f) => typeof f.maxLength !== 'number' || f.maxLength <= 0);
    expect(uncapped).toEqual([]);
  });

  it('the walk sees a string whichever way the schema nests it', () => {
    const out: { path: string; maxLength: unknown }[] = [];
    strings(
      {
        properties: { a: { type: 'string' }, b: { type: 'string', maxLength: 5 } },
        anyOf: [{ properties: { c: { type: ['string', 'null'] } } }],
        items: { type: 'string' },
      },
      'x',
      out,
    );
    expect(out).toEqual([
      { path: 'x.properties.a', maxLength: undefined },
      { path: 'x.properties.b', maxLength: 5 },
      { path: 'x.anyOf[0].properties.c', maxLength: undefined },
      { path: 'x.items', maxLength: undefined },
    ]);
  });
});
