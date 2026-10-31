#!/usr/bin/env node
import { appendFileSync, existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

export interface FakeItem {
  id: string;
  title: string;
  state?: 'Active' | 'Trashed';
  item_type?: string;
  modify_time?: string;
  login?: {
    username?: string;
    email?: string;
    password?: string;
    urls?: string[];
    totp_uri?: string;
  };
}

export interface FakeVaultFile {
  loggedIn: boolean;
  vaults: { name: string; share_id: string; vault_id: string; items: FakeItem[] }[];
}

const dir = process.env.PROTON_PASS_SESSION_DIR ?? '';
const argv = process.argv.slice(2);

function fail(msg: string, code = 1): never {
  process.stderr.write(`Error: ${msg}\n`);
  process.exit(code);
}

appendFileSync(
  join(dir, 'calls.jsonl'),
  `${JSON.stringify({
    argv,
    reason: process.env.PROTON_PASS_AGENT_REASON ?? null,
    env: Object.keys(process.env).sort(),
  })}\n`,
);
if (existsSync(join(dir, 'hang'))) setInterval(() => {}, 1_000);
else main();

function main(): void {
  const data = JSON.parse(readFileSync(join(dir, 'vault.json'), 'utf8')) as FakeVaultFile;
  if (!data.loggedIn) fail("This operation requires a logged in session. Run 'pass-cli login'");

  const opts = new Map<string, string>();
  const pos: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i] as string;
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      if (eq > 0) {
        opts.set(a.slice(2, eq), a.slice(eq + 1));
        continue;
      }
      const v = argv[i + 1];
      if (v === undefined) fail(`a value is required for '${a}'`, 2);
      if (v.startsWith('-')) {
        fail(
          `unexpected argument '${v}' found\n\n  tip: to pass '${v}' as a value, use '-- ${v}'`,
          2,
        );
      }
      opts.set(a.slice(2), v);
      i++;
    } else {
      pos.push(a);
    }
  }
  if (opts.get('output') !== 'json') fail('this fake only speaks --output json', 2);
  const out = (v: unknown): never => {
    process.stdout.write(`${JSON.stringify(v, null, 2)}\n`);
    process.exit(0);
  };
  const vaultOf = (shareId: string | undefined, name: string | undefined) => {
    const v = data.vaults.find((x) => x.share_id === shareId || (name && x.name === name));
    if (!v) fail(`Error finding vault\n\nCaused by:\n    Could not find vault ${name ?? shareId}`);
    return v;
  };

  const [group, cmd] = pos;
  if (group === 'vault' && cmd === 'list') {
    out({
      vaults: data.vaults.map((v) => ({
        name: v.name,
        vault_id: v.vault_id,
        share_id: v.share_id,
      })),
    });
  }
  if (group === 'item' && cmd === 'list') {
    const v = vaultOf(opts.get('share-id'), pos[2] ?? opts.get('vault-name'));
    const type = opts.get('filter-type');
    const state = opts.get('filter-state');
    out({
      items: v.items
        .filter((it) => !type || (it.item_type ?? 'login') === type)
        .filter((it) => !state || (it.state ?? 'Active').toLowerCase() === state)
        .map((it) => ({
          id: it.id,
          share_id: v.share_id,
          vault_id: v.vault_id,
          state: it.state ?? 'Active',
          flags: [],
          create_time: '2026-10-01T00:00:00',
          modify_time: it.modify_time ?? '2026-10-01T00:00:00',
          title: it.title,
          item_type: it.item_type ?? 'login',
        })),
    });
  }
  if (group === 'item' && cmd === 'view') {
    if (!process.env.PROTON_PASS_AGENT_REASON) {
      fail('agent sessions must set PROTON_PASS_AGENT_REASON');
    }
    const v = vaultOf(opts.get('share-id'), opts.get('vault-name'));
    const it = v.items.find((x) => x.id === opts.get('item-id'));
    if (!it) fail('Item not found');
    const content =
      (it.item_type ?? 'login') === 'login'
        ? {
            Login: {
              email: it.login?.email ?? '',
              username: it.login?.username ?? '',
              password: it.login?.password ?? '',
              urls: it.login?.urls ?? [],
              totp_uri: it.login?.totp_uri ?? '',
              passkeys: [],
            },
          }
        : { Note: {} };
    out({
      item: {
        id: it.id,
        share_id: v.share_id,
        vault_id: v.vault_id,
        content: { title: it.title, note: '', item_uuid: 'uuid', content },
        state: it.state ?? 'Active',
        flags: [],
        create_time: '2026-10-01T00:00:00',
        modify_time: it.modify_time ?? '2026-10-01T00:00:00',
      },
    });
  }
  fail(`unsupported command: ${pos.join(' ')}`, 2);
}
