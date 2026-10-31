import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { codePointLabel, findBidi } from './lib/bidi.ts';

const files = execFileSync(
  'git',
  ['ls-files', '--cached', '--others', '--exclude-standard', '*.ts', '*.js', '*.mjs'],
  { encoding: 'utf8' },
)
  .split('\n')
  .filter(Boolean);

const found: string[] = [];
for (const f of files) {
  for (const hit of findBidi(readFileSync(f, 'utf8'))) {
    found.push(`${f}:${hit.line}: ${codePointLabel(hit.codePoint)}`);
  }
}

if (found.length > 0) {
  process.stderr.write(
    `${found.length} invisible direction or line-separator characters in source. They change how\n` +
      'code reads without changing what it does. Write them as escapes in a string or regex.\n\n' +
      `${found.join('\n')}\n`,
  );
  process.exit(1);
}
