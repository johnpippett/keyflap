import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';

const args = JSON.parse(process.argv[2] ?? '{}') as { mcpUrl: string; token: string; rp: string };
const client = new Client({ name: 'isolation-probe', version: '1.0.0' });
await client.connect(
  new StreamableHTTPClientTransport(new URL(args.mcpUrl), {
    requestInit: { headers: { Authorization: `Bearer ${args.token}` } },
  }),
);
const text = (r: CallToolResult) =>
  r.content.map((c) => (c.type === 'text' ? c.text : '')).join('\n');
async function ok<T>(name: string, a: Record<string, unknown> = {}): Promise<T> {
  const r = (await client.callTool({ name, arguments: a })) as CallToolResult;
  if (r.isError) throw new Error(`${name}: ${text(r)}`);
  return JSON.parse(text(r)) as T;
}
const opened = await ok<{ url: string }>('browser_open', { url: `${args.rp}account` });
const snap = await ok<{ snapshot: string }>('browser_snapshot');
await client.close();
process.stdout.write(
  `${JSON.stringify({ url: opened.url, signedInAs: /Signed in as ([\w-]+)/.exec(snap.snapshot)?.[1] ?? null })}\n`,
);
