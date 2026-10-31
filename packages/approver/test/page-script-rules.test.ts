import { runInNewContext } from 'node:vm';
import { describe, expect, it } from 'vitest';
import { type ApprovalRequest, renderPrompt } from '../src/index.ts';
import { sourceFiles } from './source-tree.ts';

const pageScripts = sourceFiles('packages/approver/src/page', /\.js$/);
const script = (name: string) => {
  const file = pageScripts.find((f) => f.path.endsWith(`/${name}`));
  if (!file) throw new Error(`no page script ${name}`);
  return file;
};

describe('the approver page scripts', () => {
  it('cover the approvals page, the live view and the service worker', () => {
    expect(pageScripts.map((f) => f.path.split('/').pop())).toEqual(
      expect.arrayContaining(['app.js', 'handoff.js', 'approval-check.js', 'sw.js']),
    );
  });

  it('never turn text into markup: every field a person reads is set as text', () => {
    const sinks = /innerHTML|outerHTML|insertAdjacentHTML|document\.write|createContextualFragment/;
    for (const file of pageScripts) expect(file.text, file.path).not.toMatch(sinks);
  });

  it('navigate only to the fixed paths / and /handoff', () => {
    const calls = pageScripts.flatMap((f) =>
      [...f.text.matchAll(/\blocation\s*\.\s*(?:assign|replace)\s*\(([^)]*)\)/g)].map((m) => ({
        path: f.path,
        argument: (m[1] as string).trim(),
      })),
    );
    expect(calls.map((c) => c.path.split('/').pop())).toEqual(
      expect.arrayContaining(['app.js', 'handoff.js']),
    );
    for (const call of calls) expect(call.argument, call.path).toMatch(/^'(?:\/|\/handoff)'$/);
    const other =
      /\blocation\s*(?:\.\s*(?:href|pathname|search|hash)\s*)?=(?!=)|window\s*\.\s*open\b/;
    for (const file of pageScripts) expect(file.text, file.path).not.toMatch(other);
  });
});

describe('the pages neutralize what the terminal prompt neutralizes', () => {
  const asked = (text: string): ApprovalRequest => ({
    display: {
      intentText: text,
      intentAt: 0,
      verifiedOrigin: 'https://example.com',
      agentName: 'agent',
      credentialType: 'passkey',
      action: 'sign-in',
    },
    policy: { tier: 'ask' },
    binding: {
      requestId: 'r1',
      kind: 'webauthn.get',
      rpId: 'example.com',
      credentialId: 'c1',
      intentHash: 'aA',
      clientDataHash: 'bB',
    },
  });
  const terminalReplaces = (ch: string) => renderPrompt(asked(`a${ch}b`)).includes('a�b');
  const pageClean = (name: string): ((s: string) => string) => {
    const lines = script(name).text.match(/^const (?:UNSAFE|clean) =[^;]*;/gm);
    return runInNewContext(`${(lines ?? []).join('\n')}\nclean`);
  };

  it('control and bidi characters become U+FFFD in app.js and handoff.js exactly as in the prompt', () => {
    const pages = ['app.js', 'handoff.js'].map((name) => ({ name, clean: pageClean(name) }));
    const disagreements: string[] = [];
    let replaced = 0;
    for (let code = 0; code <= 0xffff; code++) {
      if (code === 0xfffd) continue;
      const ch = String.fromCharCode(code);
      const terminal = terminalReplaces(ch);
      if (terminal) replaced++;
      for (const page of pages) {
        if ((page.clean(`a${ch}b`) === 'a�b') !== terminal) {
          disagreements.push(`${page.name} U+${code.toString(16).padStart(4, '0')}`);
        }
      }
    }
    expect(replaced).toBeGreaterThan(50);
    expect(disagreements).toEqual([]);
  });
});
