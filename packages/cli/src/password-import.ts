import { createHash } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import { hasUnsafeText, parseTotpInput, printable, siteDomain, type TotpInput } from '@aab/core';

type Out = (text: string) => void;

export class ImportError extends Error {}

const MAX_FILE_BYTES = 32 * 1024 * 1024;

export type ExportFormat = 'apple' | 'chrome' | 'firefox' | '1password' | 'bitwarden' | 'csv';

export interface ImportLogin {
  line: number;
  url: string;
  domain: string;
  username: string | null;
  password: string;
  totp: TotpInput | null;
  totpText: string | null;
}

export interface SkippedRow {
  line: number;
  domain: string | null;
  username: string | null;
  reason: string;
}

export interface ParsedExport {
  format: ExportFormat;
  fingerprint: string;
  logins: ImportLogin[];
  skipped: SkippedRow[];
}

export function parseCsv(text: string): { fields: string[]; line: number }[] {
  const rows: { fields: string[]; line: number }[] = [];
  let fields: string[] = [];
  let field = '';
  let quoted = false;
  let line = 1;
  let rowLine = 1;
  let i = text.charCodeAt(0) === 0xfeff ? 1 : 0;
  const endRow = () => {
    fields.push(field);
    if (fields.length > 1 || fields[0] !== '') rows.push({ fields, line: rowLine });
    fields = [];
    field = '';
  };
  for (; i < text.length; i++) {
    const c = text[i];
    if (quoted) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i++;
        } else quoted = false;
      } else {
        if (c === '\n') line++;
        field += c;
      }
    } else if (c === '"' && field.length === 0) {
      quoted = true;
    } else if (c === ',') {
      fields.push(field);
      field = '';
    } else if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') i++;
      endRow();
      line++;
      rowLine = line;
    } else {
      field += c;
    }
  }
  if (quoted) throw new ImportError(`unterminated quoted field starting on line ${rowLine}`);
  if (field.length > 0 || fields.length > 0) endRow();
  return rows;
}

const COLUMNS = {
  url: ['url', 'login_uri', 'website', 'web site', 'origin'],
  username: ['username', 'login_username', 'user name', 'login', 'email'],
  password: ['password', 'login_password'],
  totp: ['otpauth', 'login_totp', 'totp', 'one-time password', 'otp', 'otpsecret', 'otp secret'],
} as const;

const OTP_LIKE = /otp|2fa|mfa|one[- ]?time|authenticator/;

function detectFormat(header: string[]): ExportFormat {
  const h = header.join(',');
  if (h === 'title,url,username,password,notes,otpauth') return 'apple';
  if (h === 'name,url,username,password,note' || h === 'name,url,username,password') {
    return 'chrome';
  }
  if (h.startsWith('url,username,password,httprealm')) return 'firefox';
  if (h.includes('login_uri') && h.includes('login_password')) return 'bitwarden';
  if (h.startsWith('title,url,username,password,otpauth')) return '1password';
  return 'csv';
}

export function readExport(path: string): ParsedExport {
  let size: number;
  try {
    size = statSync(path).size;
  } catch {
    throw new ImportError(`can't read ${path}`);
  }
  if (size > MAX_FILE_BYTES) throw new ImportError(`${path} is larger than 32 MB`);
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch {
    throw new ImportError(`can't read ${path}`);
  }
  return parseExport(text);
}

export function parseExport(text: string): ParsedExport {
  const rows = parseCsv(text);
  const head = rows.shift();
  if (!head) throw new ImportError('the file is empty');
  const header = head.fields.map((f) => f.trim().toLowerCase());
  const col = (names: readonly string[]) => {
    for (const n of names) {
      const i = header.indexOf(n);
      if (i >= 0) return i;
    }
    return -1;
  };
  const urlCol = col(COLUMNS.url);
  const userCol = col(COLUMNS.username);
  const passCol = col(COLUMNS.password);
  const totpCol = col(COLUMNS.totp);
  if (urlCol < 0 || passCol < 0) {
    throw new ImportError(
      'not a password export: the first line needs a URL column and a password column ' +
        '(Apple Passwords, Google Password Manager / Chrome, Firefox, 1Password and Bitwarden CSV exports have them)',
    );
  }
  const unknownOtp = header.find((h, i) => i !== totpCol && OTP_LIKE.test(h));
  if (unknownOtp !== undefined) {
    throw new ImportError(
      `the column "${unknownOtp}" looks like one-time codes, but import doesn't read it, so ` +
        'its logins would be stored without their TOTP. Add those logins with keyflap password add --totp',
    );
  }
  const format = detectFormat(header);
  const logins: ImportLogin[] = [];
  const skipped: SkippedRow[] = [];
  for (const { fields, line } of rows) {
    const url = (fields[urlCol] ?? '').split(',')[0]?.trim() ?? '';
    const rawUser = userCol >= 0 ? (fields[userCol] ?? '').trim() : '';
    const username = rawUser.length > 0 ? rawUser : null;
    const password = fields[passCol] ?? '';
    const rawTotp = totpCol >= 0 ? (fields[totpCol] ?? '').trim() : '';
    const domain =
      /^https?:\/\//i.test(url) || !/^[a-z][a-z0-9+.-]*:/i.test(url) ? siteDomain(url) : null;
    const skip = (reason: string) => skipped.push({ line, domain, username, reason });
    if (!domain) {
      skip('no website address');
      continue;
    }
    if (password.length === 0) {
      skip('no password');
      continue;
    }
    if (password.length < 4 || password.length > 1024 || password.includes('\u0000')) {
      skip('password shorter than 4 or longer than 1024 characters');
      continue;
    }
    if (username !== null && (username.length > 256 || hasUnsafeText(username))) {
      skip('username longer than 256 characters or not printable');
      continue;
    }
    let totp: TotpInput | null = null;
    if (rawTotp.length > 0) {
      try {
        totp = parseTotpInput(rawTotp);
      } catch {
        skip('one-time code setup not understood (add it with keyflap password add --totp)');
        continue;
      }
    }
    logins.push({ line, url, domain, username, password, totp, totpText: totp ? rawTotp : null });
  }
  const fingerprint = createHash('sha256').update(text).digest('hex').slice(0, 16);
  return { format, fingerprint, logins, skipped };
}

function sameTotp(a: TotpInput | null, b: TotpInput | null): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

export function dedupe(logins: ImportLogin[]): { logins: ImportLogin[]; skipped: SkippedRow[] } {
  const groups = new Map<string, ImportLogin[]>();
  for (const l of logins) {
    const key = `${l.domain}\u0000${l.username ?? ''}`;
    const g = groups.get(key);
    if (g) g.push(l);
    else groups.set(key, [l]);
  }
  const out: ImportLogin[] = [];
  const skipped: SkippedRow[] = [];
  for (const g of groups.values()) {
    const first = g[0] as ImportLogin;
    if (g.every((l) => l.password === first.password && sameTotp(l.totp, first.totp))) {
      out.push(first);
    } else {
      for (const l of g) {
        skipped.push({
          line: l.line,
          domain: l.domain,
          username: l.username,
          reason: 'other rows for this site and username have a different password or TOTP',
        });
      }
    }
  }
  return { logins: out, skipped };
}

export interface ImportOptions {
  file: string;
  sites: string[];
  all: boolean;
  expect?: string | null;
}

export interface ImportPlan {
  format: ExportFormat;
  fingerprint: string;
  available: ImportLogin[];
  toStore: ImportLogin[];
  alreadyStored: ImportLogin[];
  skipped: SkippedRow[];
  preview: boolean;
}

export function planImport(
  parsed: ParsedExport,
  opts: Pick<ImportOptions, 'sites' | 'all' | 'expect'>,
  existing: { domain: string; username: string | null }[],
): ImportPlan {
  if (opts.expect != null && opts.expect.toLowerCase() !== parsed.fingerprint) {
    throw new ImportError(
      'the file changed since the preview (its fingerprint no longer matches --expect). ' +
        'Run the import without --site or --all to see what it holds now',
    );
  }
  const { logins: available, skipped: conflicts } = dedupe(parsed.logins);
  const skipped = [...parsed.skipped, ...conflicts].sort((a, b) => a.line - b.line);
  const preview = !opts.all && opts.sites.length === 0;
  let selected = available;
  if (!opts.all) {
    const wanted = new Map<string, string>();
    for (const s of opts.sites) {
      const d = siteDomain(s);
      if (!d) throw new ImportError(`--site "${s}" has no registrable domain`);
      wanted.set(d, s);
    }
    const missing = [...wanted].filter(
      ([d]) => !available.some((l) => l.domain === d) && !skipped.some((r) => r.domain === d),
    );
    if (missing.length > 0) {
      throw new ImportError(
        `no login for ${missing.map(([, s]) => s).join(', ')} in the file ` +
          '(run without --site to see what it has)',
      );
    }
    selected = available.filter((l) => wanted.has(l.domain));
  }
  const have = new Set(existing.map((e) => `${e.domain}\u0000${e.username ?? ''}`));
  const isStored = (l: ImportLogin) => have.has(`${l.domain}\u0000${l.username ?? ''}`);
  return {
    format: parsed.format,
    fingerprint: parsed.fingerprint,
    available,
    toStore: preview ? [] : selected.filter((l) => !isStored(l)),
    alreadyStored: selected.filter(isStored),
    skipped:
      opts.all || preview
        ? skipped
        : skipped.filter(
            (r) => r.domain !== null && opts.sites.some((s) => siteDomain(s) === r.domain),
          ),
    preview,
  };
}

const FORMAT_NAMES: Record<ExportFormat, string> = {
  apple: 'Apple Passwords',
  chrome: 'Google Password Manager / Chrome',
  firefox: 'Firefox',
  '1password': '1Password',
  bitwarden: 'Bitwarden',
  csv: 'CSV',
};

function who(l: { domain: string | null; username: string | null }): string {
  return `${l.domain ?? '(no site)'}${l.username ? ` (${printable(l.username)})` : ''}`;
}

export function formatLogins(plan: ImportPlan): string[] {
  const lines = [
    `${FORMAT_NAMES[plan.format]} export, ${plan.available.length} usable login${plan.available.length === 1 ? '' : 's'}:`,
  ];
  const table = plan.available.map((l) => [
    l.domain,
    l.username === null ? '-' : printable(l.username),
    l.totp ? 'yes' : 'no',
  ]);
  if (table.length > 0) {
    const rows = [['DOMAIN', 'USERNAME', 'TOTP'], ...table];
    const w = [0, 1].map((c) => Math.max(...rows.map((r) => (r[c] as string).length)));
    for (const r of rows) {
      lines.push(
        `  ${(r[0] as string).padEnd(w[0] as number)}  ${(r[1] as string).padEnd(w[1] as number)}  ${r[2]}`,
      );
    }
  }
  if (plan.skipped.length > 0) lines.push('', formatSkipped(plan.skipped));
  return lines;
}

export function formatPreview(plan: ImportPlan, file: string): string {
  const shown = printable(file);
  const fp = plan.fingerprint;
  const lines = formatLogins(plan);
  lines.push(
    '',
    `Nothing stored. File fingerprint ${fp}. Import only the sites your agents need:`,
    `  keyflap password import ${shown} --expect ${fp} --site example.com [--site …]`,
    `  keyflap password import ${shown} --expect ${fp} --all`,
    'With --expect, the import refuses the file if it changed after this preview.',
    '',
  );
  return lines.join('\n');
}

function formatSkipped(skipped: SkippedRow[]): string {
  return [
    `Skipped ${skipped.length} row${skipped.length === 1 ? '' : 's'}:`,
    ...skipped.map((r) => `  line ${r.line}: ${who(r)}: ${r.reason}`),
  ].join('\n');
}

export async function runImport(
  plan: ImportPlan,
  store: (l: ImportLogin) => Promise<{ id: string; domain: string }>,
  out: Out,
  file: string,
): Promise<{ stored: number; failed: number }> {
  let stored = 0;
  let failed = 0;
  const lines: string[] = [];
  for (const l of plan.toStore) {
    try {
      const added = await store(l);
      stored++;
      lines.push(`  ${added.id}  ${who(l)}${l.totp ? ' + TOTP' : ''}`);
    } catch {
      failed++;
      lines.push(`  line ${l.line}: ${who(l)}: the signer refused it, not stored`);
    }
  }
  const report = [
    `Imported ${stored} login${stored === 1 ? '' : 's'} from the ${FORMAT_NAMES[plan.format]} export${stored > 0 || failed > 0 ? ':' : '.'}`,
    ...lines,
  ];
  if (plan.alreadyStored.length > 0) {
    report.push(
      `Already stored (same site and username), left as they are: ${plan.alreadyStored.map(who).join(', ')}.`,
      '  To replace one: keyflap password remove <id>, then import it again.',
    );
  }
  if (plan.skipped.length > 0) report.push(formatSkipped(plan.skipped));
  report.push(
    `${printable(file)} still holds every password in plaintext. Delete it (and empty the trash) now.`,
    '',
  );
  out(report.join('\n'));
  return { stored, failed };
}
