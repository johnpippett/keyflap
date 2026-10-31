import { spawnSync } from 'node:child_process';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';

const args = JSON.parse(process.argv[2] ?? '{}') as {
  mcpUrl: string;
  token: string;
  agentId: string;
  rp: string;
  user: string;
  action: 'enroll' | 'login';
};

const transport = new StreamableHTTPClientTransport(new URL(args.mcpUrl), {
  requestInit: { headers: { Authorization: `Bearer ${args.token}` } },
});
const client = new Client({ name: 'isolation-address-probe', version: '1.0.0' });
await client.connect(transport);

const text = (r: CallToolResult) =>
  r.content.map((c) => (c.type === 'text' ? c.text : '')).join('\n');
async function ok<T = Record<string, unknown>>(name: string, a: Record<string, unknown> = {}) {
  const r = (await client.callTool({ name, arguments: a })) as CallToolResult;
  if (r.isError) throw new Error(`${name}: ${text(r)}`);
  return JSON.parse(text(r)) as T;
}

function say(prompt: string): { status: number | null; stdout: string; stderr: string } {
  const r = spawnSync(
    '/usr/local/bin/keyflap',
    ['hook', 'claude-code', '--agent', args.agentId, '--service'],
    {
      input: JSON.stringify({ hook_event_name: 'UserPromptSubmit', prompt }),
      encoding: 'utf8',
      timeout: 15_000,
    },
  );
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

const out: Record<string, unknown> = {};
if (args.action === 'enroll') {
  await ok('browser_open', { url: `${args.rp}signup` });
  const signedUp = await ok<{ url: string }>('browser_type', {
    target: { label: 'Username' },
    text: args.user,
    submit: true,
  });
  out.signup = signedUp.url;
  out.hook = say('add a passkey for the test site');
  await ok('browser_click', { target: { role: 'button', name: 'Add a passkey' } });
  out.result = await ok('auth_enroll_passkey');
  await ok('browser_click', { target: { role: 'button', name: 'Log out' } });
} else {
  out.hook = say('sign me in to the test site');
  await ok('browser_open', { url: `${args.rp}login` });
  await ok('browser_click', { target: { role: 'button', name: 'Sign in with a passkey' } });
  out.result = await ok<{ status: string }>('auth_login');
  out.signedInAs = null;
  const tries = (out.result as { status: string }).status === 'success' ? 40 : 1;
  for (let i = 0; i < tries && out.signedInAs === null; i++) {
    const snap = await ok<{ snapshot: string; url: string }>('browser_snapshot');
    out.signedInAs = /Signed in as ([\w-]+)/.exec(snap.snapshot)?.[1] ?? null;
    if (out.signedInAs === null) await new Promise((r) => setTimeout(r, 250));
  }
}

await client.close();
process.stdout.write(`${JSON.stringify(out)}\n`);
