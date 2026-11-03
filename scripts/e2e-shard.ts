import { fileURLToPath } from 'node:url';
import { readPlans, shardFiles } from './lib/e2e-shards.ts';

const [indexArg, countArg] = process.argv.slice(2);
const index = Number(indexArg);
const count = Number(countArg);
if (!Number.isInteger(index) || !Number.isInteger(count)) {
  process.stderr.write('usage: node scripts/e2e-shard.ts <index> <count>\n');
  process.exit(1);
}
try {
  const plans = readPlans(fileURLToPath(new URL('./e2e-durations.json', import.meta.url)));
  const files = shardFiles(process.cwd(), plans, index, count);
  process.stdout.write(`${files.join('\n')}\n`);
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
}
