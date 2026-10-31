import { readFileSync } from 'node:fs';
import { MAX_INTENT_TEXT } from '@aab/core';
import { describe, expect, it } from 'vitest';
import { DEFAULT_HOOK_TIMEOUT_MS, MAX_PROMPT } from '../src/hook-core.ts';
import { codexHooksJson } from '../src/host-config.ts';
import { mergeCodexHooks } from '../src/setup/hosts.ts';

const AGENT = '0b9d6c1e-2f4a-4c3b-9e8d-7a6b5c4d3e2f';

function hookHardStopMs(): number {
  const main = readFileSync(new URL('../src/main.ts', import.meta.url), 'utf8');
  const m = /setTimeout\(\s*bail\s*,\s*([\d_]+)\s*\)/.exec(main);
  if (!m) throw new Error('main.ts no longer has a setTimeout(bail, <ms>) hard stop for the hook');
  return Number((m[1] as string).replaceAll('_', ''));
}

interface HooksFile {
  hooks: { UserPromptSubmit: { hooks: { timeout: number }[] }[] };
}

describe('the hook and the intent socket agree on their limits', () => {
  it('the hook records prompts up to the length the intent socket accepts, no more', () => {
    expect(MAX_PROMPT).toBe(MAX_INTENT_TEXT);
  });

  it('the hook gives up on stdin and the socket before its own hard stop', () => {
    expect(DEFAULT_HOOK_TIMEOUT_MS).toBeLessThan(hookHardStopMs());
  });

  it('Codex waits for the hook longer than the hook takes to stop itself', () => {
    const generated = codexHooksJson(AGENT, '/home/u/.keyflap') as HooksFile;
    const merged = mergeCodexHooks(undefined, `/n /m.ts hook codex --agent ${AGENT}`)
      .doc as unknown as HooksFile;
    for (const file of [generated, merged]) {
      const timeoutSeconds = file.hooks.UserPromptSubmit[0]?.hooks[0]?.timeout as number;
      expect(timeoutSeconds * 1000).toBeGreaterThan(hookHardStopMs());
    }
  });
});
