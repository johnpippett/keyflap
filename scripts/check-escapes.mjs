import { execFileSync } from 'node:child_process';

const CEILING = 15;
const PATTERN = 'biome-ignore|@ts-ignore|@ts-expect-error|@ts-nocheck|eslint-disable';
const SELF = [':!scripts/check-escapes.mjs', ':!scripts/lib/'];

function suppressions() {
  try {
    const out = execFileSync(
      'git',
      ['grep', '--untracked', '-nE', PATTERN, '--', '*.ts', '*.js', '*.mjs', ...SELF],
      { encoding: 'utf8' },
    );
    return out.split('\n').filter(Boolean);
  } catch (e) {
    if (e.status === 1) return [];
    throw e;
  }
}

const found = suppressions();
if (found.length > CEILING) {
  process.stderr.write(
    `${found.length} lint or type suppressions; the ceiling is ${CEILING}.\n` +
      'Fix the code instead of silencing the rule. A new suppression needs the owner to agree: raise CEILING in this\n' +
      'script and say why in the pull request.\n\n' +
      `${found.join('\n')}\n`,
  );
  process.exit(1);
}
if (found.length < CEILING) {
  process.stdout.write(
    `${found.length} suppressions, below the ceiling of ${CEILING}: lower CEILING.\n`,
  );
}
