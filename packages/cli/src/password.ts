import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import {
  addPasswordItem,
  CredentialRepo,
  openDb,
  type PasswordRow,
  parseTotpInput,
  printable,
  removePasswordItem,
  withItemSigner,
} from '@aab/core';
import { getPassphrase } from './daemon.ts';
import { type HiddenInput, readHiddenLine, type Unlock } from './passphrase.ts';
import {
  formatPreview,
  type ImportOptions,
  planImport,
  readExport,
  runImport,
} from './password-import.ts';

type Out = (text: string) => void;

export class PasswordCliError extends Error {}

export function secretReader(): (prompt: string) => Promise<string> {
  const input = process.stdin as HiddenInput;
  if (input.isTTY) return (prompt) => readHiddenLine(prompt, input, process.stderr);
  const rl = createInterface({ input: process.stdin, terminal: false });
  const lines: string[] = [];
  const waiting: ((l: string | null) => void)[] = [];
  let closed = false;
  rl.on('line', (l) => {
    const w = waiting.shift();
    if (w) w(l);
    else lines.push(l);
  });
  rl.on('close', () => {
    closed = true;
    for (const w of waiting.splice(0)) w(null);
  });
  return async () => {
    const next =
      lines.length > 0
        ? (lines.shift() as string)
        : closed
          ? null
          : await new Promise<string | null>((r) => waiting.push(r));
    if (next === null) throw new PasswordCliError('stdin ended before all secrets were read');
    return next;
  };
}

function withDb<T>(dataDir: string, fn: (db: ReturnType<typeof openDb>) => T): T {
  mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  const db = openDb(join(dataDir, 'broker.sqlite'));
  let result: T;
  try {
    result = fn(db);
  } catch (err) {
    db.close();
    throw err;
  }
  if (result instanceof Promise) {
    return result.finally(() => db.close()) as T;
  }
  db.close();
  return result;
}

export async function passwordAdd(
  opts: { dataDir: string; site: string; username: string | null; totp: boolean },
  out: Out,
): Promise<{ id: string; domain: string }> {
  const read = secretReader();
  const passphrase = await getPassphrase(opts.dataDir);
  const password = await read('Password: ');
  if (password.length === 0) throw new PasswordCliError('empty password');
  const totp = opts.totp
    ? parseTotpInput(await read('TOTP secret or otpauth:// URI: '))
    : undefined;
  const added = await storePassword(opts.dataDir, passphrase, {
    site: opts.site,
    username: opts.username,
    password,
    totp: totp ?? null,
  });
  out(
    `Added a password${totp ? ' + TOTP' : ''} for ${added.domain}` +
      `${opts.username ? ` (username ${opts.username})` : ''}, id ${added.id}.\n` +
      'It is offered on every page of that registrable domain. Start the daemon to use it.\n',
  );
  return added;
}

export function storePassword(
  dataDir: string,
  passphrase: string,
  item: {
    site: string;
    username: string | null;
    password: string;
    totp: ReturnType<typeof parseTotpInput> | null;
  },
): Promise<{ id: string; domain: string }> {
  return withItemSigner(dataDir, passphrase, (signer) =>
    withDb(dataDir, (db) =>
      addPasswordItem(
        { signer, db },
        {
          site: item.site,
          username: item.username,
          password: item.password,
          ...(item.totp ? { totp: item.totp } : {}),
        },
      ),
    ),
  );
}

export async function passwordImport(
  opts: ImportOptions & { dataDir: string },
  out: Out,
): Promise<{ stored: number; failed: number }> {
  const parsed = readExport(opts.file);
  const existing = listPasswords(opts.dataDir)
    .filter((r) => r.source === 'signer')
    .map((r) => ({ domain: r.registrable_domain, username: r.username }));
  const plan = planImport(parsed, opts, existing);
  if (plan.preview) {
    out(formatPreview(plan, opts.file));
    return { stored: 0, failed: 0 };
  }
  if (plan.toStore.length === 0)
    return runImport(plan, async () => ({ id: '', domain: '' }), out, opts.file);
  const passphrase = await getPassphrase(opts.dataDir);
  const result = await withItemSigner(opts.dataDir, passphrase, (signer) =>
    withDb(opts.dataDir, (db) =>
      runImport(
        plan,
        (l) =>
          addPasswordItem(
            { signer, db },
            {
              site: l.url,
              username: l.username,
              password: l.password,
              ...(l.totp ? { totp: l.totp } : {}),
            },
          ),
        out,
        opts.file,
      ),
    ),
  );
  if (result.stored > 0) out('Start the daemon to use them.\n');
  return result;
}

export function listPasswords(dataDir: string): PasswordRow[] {
  return withDb(dataDir, (db) => new CredentialRepo(db).allPasswords());
}

export function passwordList(opts: { dataDir: string; json: boolean }, out: Out): PasswordRow[] {
  const rows = withDb(opts.dataDir, (db) => new CredentialRepo(db).allPasswords());
  out(formatPasswords(rows, opts.json));
  return rows;
}

export function formatPasswords(rows: PasswordRow[], json: boolean): string {
  const items = rows.map((r) => ({
    id: r.id,
    domain: r.registrable_domain,
    username: r.username,
    totp: r.has_totp === 1,
    source: r.source === 'signer' ? 'native' : r.source,
    createdAt: r.created_at,
  }));
  if (json) return `${JSON.stringify(items, null, 2)}\n`;
  if (items.length === 0) return 'No passwords. Add one with: keyflap password add <site>\n';
  const table = [
    ['ID', 'DOMAIN', 'USERNAME', 'TOTP', 'SOURCE'],
    ...items.map((i) => [
      i.id,
      i.domain,
      i.username === null ? '-' : printable(i.username),
      i.totp ? 'yes' : 'no',
      i.source,
    ]),
  ];
  const widths = [0, 1, 2, 3].map((c) => Math.max(...table.map((r) => (r[c] as string).length)));
  return `${table.map((r) => r.map((c, i) => (i < 4 ? c.padEnd(widths[i] as number) : c)).join('  ')).join('\n')}\n`;
}

export async function passwordRemove(
  opts: { dataDir: string; id: string; unlock?: Unlock },
  out: Out,
) {
  const row = withDb(opts.dataDir, (db) =>
    new CredentialRepo(db).allPasswords().find((r) => r.id === opts.id),
  );
  if (!row) throw new PasswordCliError(`no password with id ${opts.id}`);
  if (row.source !== 'signer') {
    throw new PasswordCliError(
      `${opts.id} is a ${row.source} login: remove it (or its URL) in ${row.source}; ` +
        'the daemon drops it on its next sync',
    );
  }
  const passphrase = await (opts.unlock ?? (() => getPassphrase(opts.dataDir)))();
  await withItemSigner(opts.dataDir, passphrase, (signer) =>
    withDb(opts.dataDir, (db) => removePasswordItem({ signer, db }, opts.id)),
  );
  out(`Removed password ${opts.id}.\n`);
}
