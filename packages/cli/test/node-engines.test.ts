import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { MIN_NODE, nodeIsSupported } from '../src/doctor.ts';

type Version = readonly [number, number, number];

const engines = (
  JSON.parse(readFileSync(new URL('../../../package.json', import.meta.url), 'utf8')) as {
    engines: { node: string };
  }
).engines.node;

function parse(v: string): Version {
  const m = /^(\d+)\.(\d+)\.(\d+)$/.exec(v);
  if (!m) throw new Error(`not a plain version: ${v}`);
  return [Number(m[1]), Number(m[2]), Number(m[3])];
}

const atLeast = (v: Version, floor: Version) =>
  v[0] !== floor[0] ? v[0] > floor[0] : v[1] !== floor[1] ? v[1] > floor[1] : v[2] >= floor[2];

function satisfies(version: string, range: string): boolean {
  const v = parse(version);
  return range.split('||').some((clause) => {
    const c = clause.trim();
    if (c.startsWith('^')) {
      const floor = parse(c.slice(1));
      return v[0] === floor[0] && atLeast(v, floor);
    }
    if (c.startsWith('>=')) return atLeast(v, parse(c.slice(2)));
    throw new Error(`unsupported engines clause: ${c}`);
  });
}

describe('doctor and package.json engines name the same supported Node versions', () => {
  const probes = [
    ...MIN_NODE.flatMap((line) => {
      const [major, minor, patch] = line;
      return [
        `${major}.${minor}.${patch}`,
        `${major}.${minor}.${patch + 1}`,
        `${major}.${minor + 1}.0`,
        `${major}.${minor}.${Math.max(0, patch - 1)}`,
        `${major}.${Math.max(0, minor - 1)}.99`,
        `${major}.0.0`,
        `${major + 1}.0.0`,
        `${major - 1}.99.99`,
      ];
    }),
    '18.20.0',
    '20.19.0',
    '25.0.0',
    '25.99.99',
    '27.0.0',
    '30.1.2',
  ];

  it.each(probes)('Node %s is supported by both or by neither', (version) => {
    expect(nodeIsSupported(version), `doctor on ${version} vs engines ${engines}`).toBe(
      satisfies(version, engines),
    );
  });

  it('the lowest supported release of each line is exactly what engines names', () => {
    expect(engines.split('||').length).toBe(MIN_NODE.length);
    for (const [major, minor, patch] of MIN_NODE) {
      expect(satisfies(`${major}.${minor}.${patch}`, engines)).toBe(true);
      if (patch > 0) expect(satisfies(`${major}.${minor}.${patch - 1}`, engines)).toBe(false);
    }
  });

  it('the range reader is correct on a small example', () => {
    const range = '^22.23.4 || ^24.22.1 || >=26.12.1';
    expect(
      [
        '22.23.3',
        '22.23.4',
        '22.99.0',
        '23.0.0',
        '24.22.1',
        '25.0.0',
        '26.12.0',
        '26.12.1',
        '40.0.0',
      ].map((v) => satisfies(v, range)),
    ).toEqual([false, true, true, false, true, false, false, true, true]);
  });
});
