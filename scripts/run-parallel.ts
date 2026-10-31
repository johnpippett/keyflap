import { packageScriptTask, runAllInParallel, type TaskResult } from './lib/parallel.ts';

const scripts = process.argv.slice(2);
if (scripts.length === 0) {
  process.stderr.write('usage: node scripts/run-parallel.ts <package script>...\n');
  process.exit(2);
}

const inActions = process.env.GITHUB_ACTIONS === 'true';

function report({ name, ok, output, seconds }: TaskResult) {
  const title = `${ok ? 'ok  ' : 'FAIL'} ${name} (${seconds.toFixed(1)} s)`;
  const body = output.trimEnd();
  if (inActions && ok) {
    process.stdout.write(`::group::${title}\n${body}\n::endgroup::\n`);
  } else if (inActions) {
    process.stdout.write(`::error::${name} failed\n${title}\n${body}\n`);
  } else {
    process.stdout.write(`${title}\n${ok || body === '' ? '' : `${body}\n`}`);
  }
}

const ok = await runAllInParallel(
  scripts.map((s) => packageScriptTask(s, process.env.npm_execpath)),
  report,
);
process.exit(ok ? 0 : 1);
