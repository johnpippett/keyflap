import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { assignShards, e2eFiles, readDurations, totalSeconds } from './e2e-shards.ts';

const root = fileURLToPath(new URL('../..', import.meta.url));
const durations = readDurations(fileURLToPath(new URL('../e2e-durations.json', import.meta.url)));
const files = e2eFiles(root);

describe('e2e shard plan', () => {
  it('assigns every e2e file exactly once', () => {
    for (const count of [1, 2, 4, 6, 8]) {
      const shards = assignShards(files, durations, count);
      expect(shards).toHaveLength(count);
      expect(shards.flat().sort()).toEqual(files);
      for (const shard of shards) expect(shard.length).toBeGreaterThan(0);
    }
  });

  it('is deterministic', () => {
    expect(assignShards(files, durations, 6)).toEqual(assignShards(files, durations, 6));
  });

  it('keeps six shards within 15% of an even load', () => {
    const shards = assignShards(files, durations, 6);
    const loads = shards.map((shard) => totalSeconds(shard, durations));
    const mean = totalSeconds(files, durations) / shards.length;
    expect(Math.max(...loads)).toBeLessThanOrEqual(mean * 1.15);
  });

  it('has a measured time for every e2e file', () => {
    expect(files.filter((file) => durations.seconds[file] === undefined)).toEqual([]);
  });

  it('has no measured file that no longer exists', () => {
    expect(Object.keys(durations.seconds).filter((file) => !files.includes(file))).toEqual([]);
  });

  it('never lets one planned file filter another', () => {
    const collisions = files.filter((file) =>
      files.some((other) => other !== file && other.includes(file)),
    );
    expect(collisions).toEqual([]);
  });

  it('rejects impossible shard counts', () => {
    expect(() => assignShards(files, durations, 0)).toThrow();
    expect(() => assignShards(files, durations, -1)).toThrow();
    expect(() => assignShards(files, durations, 2.5)).toThrow();
    expect(() => assignShards(files, durations, files.length + 1)).toThrow();
  });

  it('rejects a duplicate file', () => {
    const first = files[0] ?? '';
    expect(() => assignShards([...files, first], durations, 2)).toThrow();
  });
});
