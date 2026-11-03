import { globSync, readFileSync } from 'node:fs';

const E2E_GLOB = 'packages/*/test/**/*.e2e.test.ts';
const E2E_EXCLUDE = ['packages/isolation/**'];

export type E2eDurations = {
  source: string;
  defaultSeconds?: number;
  seconds: Record<string, number>;
};

export function e2eFiles(root: string): string[] {
  return globSync(E2E_GLOB, { cwd: root, exclude: E2E_EXCLUDE }).sort();
}

export function readDurations(file: string): E2eDurations {
  return JSON.parse(readFileSync(file, 'utf8')) as E2eDurations;
}

function meanOf(seconds: Record<string, number>): number {
  const values = Object.values(seconds);
  if (values.length === 0) return 0;
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

export function secondsOf(file: string, durations: E2eDurations): number {
  return durations.seconds[file] ?? durations.defaultSeconds ?? meanOf(durations.seconds);
}

export function totalSeconds(files: string[], durations: E2eDurations): number {
  return files.reduce((sum, file) => sum + secondsOf(file, durations), 0);
}

export function assignShards(files: string[], durations: E2eDurations, count: number): string[][] {
  if (!Number.isInteger(count) || count < 1) {
    throw new Error(`shard count must be a positive integer, got ${count}`);
  }
  if (count > files.length) {
    throw new Error(`shard count ${count} is more than the ${files.length} test files`);
  }
  if (new Set(files).size !== files.length) {
    throw new Error('the test file list has a duplicate');
  }
  const ordered = [...files].sort((a, b) => {
    const bySeconds = secondsOf(b, durations) - secondsOf(a, durations);
    return bySeconds === 0 ? a.localeCompare(b) : bySeconds;
  });
  const shards: string[][] = Array.from({ length: count }, () => []);
  const totals: number[] = Array.from({ length: count }, () => 0);
  for (const file of ordered) {
    let target = 0;
    for (let i = 1; i < count; i += 1) {
      if ((totals[i] ?? 0) < (totals[target] ?? 0)) target = i;
    }
    shards[target]?.push(file);
    totals[target] = (totals[target] ?? 0) + secondsOf(file, durations);
  }
  return shards;
}

export function shardFiles(
  root: string,
  durations: E2eDurations,
  index: number,
  count: number,
): string[] {
  if (!Number.isInteger(index) || index < 1 || index > count) {
    throw new Error(`shard index must be 1..${count}, got ${index}`);
  }
  const shard = assignShards(e2eFiles(root), durations, count)[index - 1];
  if (!shard) throw new Error(`no shard ${index} of ${count}`);
  return shard;
}
