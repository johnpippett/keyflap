import { readFileSync } from 'node:fs';
import { MAX_GRANT_MS } from '@aab/signer/approval';
import { describe, expect, it } from 'vitest';

const source = (path: string) => readFileSync(new URL(path, import.meta.url), 'utf8');

const product = (expression: string) =>
  expression
    .split('*')
    .map((factor) => Number(factor.trim().replaceAll('_', '')))
    .reduce((a, b) => a * b, 1);

describe('the allow-for cap is one number in every place that checks it', () => {
  it('the phone page checks the same cap as the signer', () => {
    const page = source('../src/page/approval-check.js');
    const found = /const MAX_GRANT_MS = ([\d_ *]+);/.exec(page);
    expect(found, 'approval-check.js declares MAX_GRANT_MS').not.toBeNull();
    expect(product(found?.[1] ?? '')).toBe(MAX_GRANT_MS);
  });

  it('the iOS approver core checks the same cap as the signer', () => {
    const swift = source(
      '../../../ios/KeyflapApproverCore/Sources/KeyflapApproverCore/Statement.swift',
    );
    const found = /static let maxGrantMs: Int64 = ([\d_ *]+)\n/.exec(swift);
    expect(found, 'Statement.swift declares maxGrantMs').not.toBeNull();
    expect(product(found?.[1] ?? '')).toBe(MAX_GRANT_MS);
  });
});
