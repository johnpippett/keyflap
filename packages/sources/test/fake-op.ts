#!/usr/bin/env node
import { appendFileSync, existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

export interface FakeOpItem {
  id: string;
  title: string;
  category?: string;
  archived?: boolean;
  version?: number;
  updated_at?: string;
  username?: string;
  password?: string;
  urls?: string[];
  otp?: string[];
}

export interface FakeOpAccount {
  token: string;
  vaults: { id: string; name: string; items: FakeOpItem[] }[];
}

const dir = process.env.KEYFLAP_FAKE_OP_DIR ?? '';
const argv = process.argv.slice(2);

function fail(msg: string, code = 1): never {
  process.stderr.write(`[ERROR] 2026/10/22 12:00:00 ${msg}\n`);
  process.exit(code);
}

appendFileSync(
  join(dir, 'calls.jsonl'),
  `${JSON.stringify({ argv, env: Object.keys(process.env).sort() })}\n`,
);
if (existsSync(join(dir, 'hang'))) setInterval(() => {}, 1_000);
else main();

function main(): void {
  if (existsSync(join(dir, 'garbage'))) {
    process.stdout.write('this is not json\n');
    process.exit(0);
  }
  if (existsSync(join(dir, 'ratelimit'))) {
    fail('Too many requests. Your client has been rate limited. (429)');
  }
  if (existsSync(join(dir, 'undecodable'))) {
    fail("failed to DecodeSACredentials: invalid character 'd' looking for beginning of value");
  }
  const data = JSON.parse(readFileSync(join(dir, 'account.json'), 'utf8')) as FakeOpAccount;
  if (
    !process.env.OP_SERVICE_ACCOUNT_TOKEN ||
    process.env.OP_SERVICE_ACCOUNT_TOKEN !== data.token
  ) {
    fail('You are not currently signed in. Please run `op signin --help` for instructions');
  }

  const opts = new Map<string, string | true>();
  const pos: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i] as string;
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      if (eq > 0) opts.set(a.slice(2, eq), a.slice(eq + 1));
      else if (a === '--reveal') opts.set('reveal', true);
      else {
        const v = argv[i + 1];
        if (v === undefined) fail(`flag needs an argument: ${a}`, 2);
        opts.set(a.slice(2), v);
        i++;
      }
    } else {
      pos.push(a);
    }
  }
  if (opts.get('format') !== 'json') fail('this fake only speaks --format=json', 2);
  const out = (v: unknown): never => {
    process.stdout.write(`${JSON.stringify(v, null, 2)}\n`);
    process.exit(0);
  };
  const vaultOf = () => {
    const ref = opts.get('vault');
    if (typeof ref !== 'string') {
      fail('a vault must be specified with --vault when using a service account');
    }
    const v = data.vaults.find((x) => x.id === ref || x.name === ref);
    if (!v) fail(`"${ref}" isn't a vault in this account. Specify the vault with its ID or name.`);
    return v;
  };
  const stamp = (it: FakeOpItem) => ({
    version: it.version ?? 1,
    created_at: '2026-10-01T00:00:00Z',
    updated_at: it.updated_at ?? '2026-10-01T00:00:00Z',
    last_edited_by: 'SERVICEACCOUNTXXXXXXXXXXXX',
  });
  const urlsOf = (it: FakeOpItem) =>
    (it.urls ?? []).map((href, i) => ({
      label: 'website',
      ...(i === 0 ? { primary: true } : {}),
      href,
    }));

  const [group, cmd] = pos;
  if (group === 'vault' && cmd === 'list') {
    out(
      data.vaults.map((v) => ({
        id: v.id,
        name: v.name,
        content_version: 1,
        created_at: '2026-10-01T00:00:00Z',
        updated_at: '2026-10-01T00:00:00Z',
        items: v.items.length,
      })),
    );
  }
  if (group === 'item' && cmd === 'list') {
    const v = vaultOf();
    const cats = opts.get('categories');
    out(
      v.items
        .filter((it) => !it.archived)
        .filter(
          (it) =>
            typeof cats !== 'string' ||
            cats
              .toUpperCase()
              .split(',')
              .includes(it.category ?? 'LOGIN'),
        )
        .map((it) => ({
          id: it.id,
          title: it.title,
          ...stamp(it),
          vault: { id: v.id, name: v.name },
          category: it.category ?? 'LOGIN',
          additional_information: it.username ?? '',
          ...(it.urls?.length ? { urls: urlsOf(it) } : {}),
        })),
    );
  }
  if (group === 'item' && cmd === 'get') {
    const v = vaultOf();
    const ref = pos[2];
    const it = v.items.find((x) => x.id === ref || x.title === ref);
    if (!it) {
      fail(
        `"${ref}" isn't an item in the "${v.name}" vault. Specify the item with its UUID, name, or domain.`,
      );
    }
    const reveal = opts.get('reveal') === true;
    const hidden = (s: string) => (reveal ? s : `[use 'op item get ${it.id} --reveal' to reveal]`);
    const fields: Record<string, unknown>[] = [];
    if ((it.category ?? 'LOGIN') === 'LOGIN') {
      fields.push(
        {
          id: 'username',
          type: 'STRING',
          purpose: 'USERNAME',
          label: 'username',
          value: it.username ?? '',
          reference: `op://${v.name}/${it.title}/username`,
        },
        {
          id: 'password',
          type: 'CONCEALED',
          purpose: 'PASSWORD',
          label: 'password',
          value: hidden(it.password ?? ''),
          entropy: 100,
          reference: `op://${v.name}/${it.title}/password`,
          password_details: { strength: 'FANTASTIC' },
        },
        {
          id: 'notesPlain',
          type: 'STRING',
          purpose: 'NOTES',
          label: 'notesPlain',
          reference: `op://${v.name}/${it.title}/notesPlain`,
        },
      );
    }
    (it.otp ?? []).forEach((uri, i) => {
      fields.push({
        id: `TOTP_${i}`,
        section: { id: 'add more' },
        type: 'OTP',
        label: 'one-time password',
        value: hidden(uri),
        totp: '123456',
        reference: `op://${v.name}/${it.title}/one-time password?attribute=otp`,
      });
    });
    out({
      id: it.id,
      title: it.title,
      ...stamp(it),
      vault: { id: v.id, name: v.name },
      category: it.category ?? 'LOGIN',
      ...(it.archived ? { state: 'ARCHIVED' } : {}),
      additional_information: it.username ?? '',
      ...(it.urls?.length ? { urls: urlsOf(it) } : {}),
      sections: [{ id: 'add more' }],
      fields,
    });
  }
  fail(`unknown command "${pos.join(' ')}" for "op"`, 2);
}
