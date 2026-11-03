import { globSync, readFileSync } from 'node:fs';
import { E2E_EXCLUDE, E2E_INCLUDE } from './e2e-files.ts';

export type E2eDurations = {
  source: string;
  seconds: Record<string, number>;
};

export type E2ePlans = {
  linux: E2eDurations;
  darwin: E2eDurations;
};

export function e2eFiles(root: string): string[] {
  return globSync(E2E_INCLUDE, { cwd: root, exclude: E2E_EXCLUDE }).sort();
}

export function readPlans(file: string): E2ePlans {
  return JSON.parse(readFileSync(file, 'utf8')) as E2ePlans;
}

export function planFor(
  plans: E2ePlans,
  platform: NodeJS.Platform = process.platform,
): E2eDurations {
  return platform === 'darwin' ? plans.darwin : plans.linux;
}

function meanOf(seconds: Record<string, number>): number {
  const values = Object.values(seconds);
  if (values.length === 0) return 0;
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

export function secondsOf(file: string, durations: E2eDurations): number {
  return durations.seconds[file] ?? meanOf(durations.seconds);
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
  plans: E2ePlans,
  index: number,
  count: number,
  platform: NodeJS.Platform = process.platform,
): string[] {
  if (!Number.isInteger(index) || index < 1 || index > count) {
    throw new Error(`shard index must be 1..${count}, got ${index}`);
  }
  const shard = assignShards(e2eFiles(root), planFor(plans, platform), count)[index - 1];
  if (!shard) throw new Error(`no shard ${index} of ${count}`);
  return shard;
}
