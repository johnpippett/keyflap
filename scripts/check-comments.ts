import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { isDirective, scanComments } from './lib/comments.ts';

const files = execFileSync(
  'git',
  ['ls-files', '--cached', '--others', '--exclude-standard', '*.ts', '*.js', '*.mjs'],
  { encoding: 'utf8' },
)
  .split('\n')
  .filter(Boolean);

const found: string[] = [];
for (const f of files) {
  const src = readFileSync(f, 'utf8');
  for (const c of scanComments(src)) {
    if (isDirective(c)) continue;
    const line = src.slice(0, c.start).split('\n').length;
    found.push(`${f}:${line}: ${c.text.split('\n')[0]?.slice(0, 80)}`);
  }
}

if (found.length > 0) {
  process.stderr.write(
    `${found.length} code comments. This repo has none: put the meaning in a name, a type, a test or\n` +
      'a lint rule. Only lint and type suppression directives that give a reason are allowed.\n\n' +
      `${found.join('\n')}\n`,
  );
  process.exit(1);
}
