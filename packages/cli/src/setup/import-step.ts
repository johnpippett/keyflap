import { join } from 'node:path';
import { printable } from '@aab/core';
import {
  formatLogins,
  type ImportPlan,
  type ParsedExport,
  parseExport,
  planImport,
  runImport,
} from '../password-import.ts';
import { confirm } from './prompt.ts';
import { type SetupContext, waitForDaemonStopped } from './steps.ts';

const LOGINS_ON_SCREEN = 9;

export function typedPath(raw: string, home: string): string {
  let p = raw.trim();
  const quoted = p.length > 1 && (p[0] === "'" || p[0] === '"') && p.at(-1) === p[0];
  p = quoted ? p.slice(1, -1) : p.replace(/\\(.)/g, '$1');
  if (p === '~') return home;
  return p.startsWith('~/') ? join(home, p.slice(2)) : p;
}

async function readExportFile(
  ctx: SetupContext,
): Promise<{ parsed: ParsedExport; path: string } | null> {
  for (;;) {
    const raw = await ctx.prompt.ask('Export file (drag it into this window; blank to skip)');
    if (raw.trim() === '') return null;
    const path = typedPath(raw, ctx.backend.user.home);
    try {
      const text = ctx.sys.readUserFile(path, ctx.backend.fileOwner);
      if (text === null) {
        ctx.out(`  ${printable(path)} does not exist.\n`);
        continue;
      }
      return { parsed: parseExport(text), path };
    } catch (err) {
      ctx.out(`  ✗ ${(err as Error).message}\n`);
    }
  }
}

export async function importExport(ctx: SetupContext): Promise<boolean> {
  if (!(await waitForDaemonStopped(ctx, 'importing passwords'))) return false;
  ctx.ui.brief(
    [
      'First export your passwords to a CSV file.',
      '',
      '  Mac: the Passwords app, File > Export All Passwords.',
      '  Chrome, Firefox, 1Password and Bitwarden exports work too.',
      '',
      'Setup shows each site and username from it, never a password.',
    ].join('\n'),
    '  Export your passwords to a CSV file first. Mac: the Passwords app, File > Export All\n' +
      '  Passwords. Chrome, Firefox, 1Password and Bitwarden exports work too. Setup reads the file\n' +
      '  as you and shows each site and username, never a password.\n',
  );
  const file = await readExportFile(ctx);
  if (!file) return false;
  const indented = (t: string) => t.replace(/^(?=.)/gm, '  ');
  const existing = (await ctx.backend.storedLogins()).filter((l) => l.native);
  const everything = planImport(file.parsed, { sites: [], all: true }, existing);
  const table = formatLogins(everything);
  ctx.ui.brief(
    table.length <= LOGINS_ON_SCREEN ? table.join('\n') : `${table[0]}\nTab lists them all.`,
    indented(`${table.join('\n')}\n`),
    { log: false },
  );
  if (everything.available.length === 0) return false;
  let plan: ImportPlan;
  for (;;) {
    const a = (
      await ctx.prompt.ask(
        'Sites your agents need (blank: all of them; or a list such as github.com, example.com)',
      )
    ).trim();
    try {
      const sites = a.split(/[\s,]+/).filter(Boolean);
      plan =
        sites.length === 0 ? everything : planImport(file.parsed, { sites, all: false }, existing);
      break;
    } catch (err) {
      ctx.out(`  ${(err as Error).message}\n`);
    }
  }
  const n = plan.toStore.length;
  if (
    n > 0 &&
    !(await confirm(ctx.prompt, `Store ${n} login${n === 1 ? '' : 's'} in Keyflap?`, false))
  ) {
    ctx.out(`  Nothing stored. ${printable(file.path)} still holds every password: delete it.\n`);
    return false;
  }
  let report = '';
  const r = await ctx.ui.wait('Storing them in the signer', () =>
    runImport(
      plan,
      (l) =>
        ctx.backend.addPassword({
          site: l.url,
          username: l.username,
          password: l.password,
          totp: l.totpText,
        }),
      (t) => {
        report += indented(t);
      },
      file.path,
    ),
  );
  ctx.ui.brief(
    [
      `✓ Stored ${r.stored} login${r.stored === 1 ? '' : 's'}${r.failed > 0 ? `; ${r.failed} refused` : ''}.`,
      '',
      `${printable(file.path)} still holds every password in plaintext. Delete it now, and empty the trash.`,
    ].join('\n'),
    report,
    { log: false },
  );
  return r.stored > 0;
}
