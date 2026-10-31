const SOURCES = '/opt/keyflap/app/packages/sources/src/index.ts';
const { checkTool, PASS_CLI_TOOL } = (await import(
  SOURCES
)) as typeof import('../../../sources/src/index.ts');

const paths = JSON.parse(process.argv[2] ?? '[]') as string[];
const out: Record<string, string> = {};
for (const p of paths) {
  const r = checkTool(p, PASS_CLI_TOOL);
  out[p] = r.ok ? 'ok' : `${r.problem}: ${r.detail}`;
}
process.stdout.write(`${JSON.stringify(out)}\n`);
