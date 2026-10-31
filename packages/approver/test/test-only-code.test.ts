import { describe, expect, it } from 'vitest';
import { callArguments, productionSources } from './source-tree.ts';

const mentioning = (symbol: string, allowedPaths: readonly string[]): string[] =>
  productionSources()
    .filter((f) => !allowedPaths.includes(f.path) && new RegExp(`\\b${symbol}\\b`).test(f.text))
    .map((f) => f.path);

describe('test-only code stays out of production', () => {
  it('ScriptedApprover is defined and exported by the approver package and used by no other production file', () => {
    expect(
      mentioning('ScriptedApprover', [
        'packages/approver/src/scripted.ts',
        'packages/approver/src/index.ts',
      ]),
    ).toEqual([]);
  });

  it('allowInsecurePushEndpoints is named by phone.ts alone, so no daemon or CLI code can set it', () => {
    expect(mentioning('allowInsecurePushEndpoints', ['packages/approver/src/phone.ts'])).toEqual(
      [],
    );
  });

  it('production code never passes encryptPush a fixed ephemeral key or salt', () => {
    const calls = productionSources().flatMap((f) =>
      callArguments(f.text, 'encryptPush').map((args) => ({ path: f.path, args })),
    );
    expect(calls.length).toBeGreaterThan(0);
    for (const call of calls) expect(call.args, call.path).toHaveLength(2);
  });

  it('the call scanner counts a third argument, nested calls and quoted commas', () => {
    expect(callArguments('encryptPush(sub, b, { salt: s })', 'encryptPush')).toEqual([
      ['sub', 'b', '{ salt: s }'],
    ]);
    expect(
      callArguments('encryptPush(sub, opts.p ?? Buffer.from(\'{"t":","}\'))', 'encryptPush'),
    ).toEqual([['sub', 'opts.p ?? Buffer.from(\'{"t":","}\')']]);
    expect(callArguments('export function encryptPush(sub, b, o = {}) {}', 'encryptPush')).toEqual(
      [],
    );
  });
});
