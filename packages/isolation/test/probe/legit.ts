import { spawnSync } from 'node:child_process';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';

const args = JSON.parse(process.argv[2] ?? '{}') as {
  mcpUrl: string;
  token: string;
  agentId: string;
  rp: string;
};

const transport = new StreamableHTTPClientTransport(new URL(args.mcpUrl), {
  requestInit: { headers: { Authorization: `Bearer ${args.token}` } },
});
const client = new Client({ name: 'isolation-probe', version: '1.0.0' });
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

const enroll = async () => {
  await ok('browser_click', { target: { role: 'button', name: 'Add a passkey' } });
  return ok('auth_enroll_passkey');
};
const login = async () => {
  await ok('browser_open', { url: `${args.rp}login` });
  await ok('browser_click', { target: { role: 'button', name: 'Sign in with a passkey' } });
  return ok('auth_login');
};

const out: Record<string, unknown> = {};
await ok('browser_open', { url: `${args.rp}signup` });
const signedUp = await ok<{ url: string }>('browser_type', {
  target: { label: 'Username' },
  text: 'isolation-user',
  submit: true,
});
out.signup = signedUp.url;
out.enrollWithoutIntent = await enroll();
out.hookRegister = say('add a passkey for the test site');
out.enrollApproved = await enroll();
out.hookDeny = say('sign in to the test site, but DENY this one');
out.loginDenied = await login();
out.hookLogin = say('sign me in to the test site');
out.loginApproved = await login();
out.signedInAs = null;
for (let i = 0; i < 40 && out.signedInAs === null; i++) {
  const snap = await ok<{ snapshot: string; url: string }>('browser_snapshot');
  out.finalUrl = snap.url;
  out.signedInAs = /Signed in as ([\w-]+)/.exec(snap.snapshot)?.[1] ?? null;
  if (out.signedInAs === null) await new Promise((r) => setTimeout(r, 250));
}

await client.close();
process.stdout.write(`${JSON.stringify(out)}\n`);
