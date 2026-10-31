import { ToolError } from '@aab/mcp';
import { describe, expect, it } from 'vitest';
import { nodePrefix, parseLocator, REDACTED, redactSnapshot } from '../src/agent-port.ts';

describe('locator validation', () => {
  it('accepts each kind with its own options', () => {
    expect(parseLocator({ role: 'button', name: 'Sign in', exact: true })).toEqual({
      kind: 'role',
      role: 'button',
      name: 'Sign in',
      exact: true,
    });
    expect(parseLocator({ role: 'link' })).toEqual({ kind: 'role', role: 'link' });
    expect(parseLocator({ text: 'Welcome' })).toEqual({ kind: 'text', value: 'Welcome' });
    expect(parseLocator({ label: 'Username', exact: false })).toEqual({
      kind: 'label',
      value: 'Username',
      exact: false,
    });
    expect(parseLocator({ placeholder: 'you@example.com' })).toEqual({
      kind: 'placeholder',
      value: 'you@example.com',
    });
    for (const css of [
      '#signup',
      'button[type="submit"]',
      'form > input[name=username]',
      'a[href^="https://"]',
      'li:nth-child(2) a',
      '[data-test=x]',
    ]) {
      expect(parseLocator({ css })).toEqual({ kind: 'css', css });
    }
  });

  it('refuses anything that is not exactly one well-formed kind', () => {
    for (const bad of [
      null,
      undefined,
      'button',
      42,
      ['css', 'a'],
      {},
      { role: 'button', text: 'x' },
      { css: 'a', text: 'x' },
      { css: 'a', exact: true },
      { text: 'x', name: 'y' },
      { role: 'button', script: 'alert(1)' },
      { role: 'Button' },
      { role: 'button!' },
      { role: '' },
      { role: 'x'.repeat(65) },
      { text: '' },
      { text: 5 },
      { text: { $regex: '.*' } },
      { text: 'x'.repeat(1001) },
      { text: 'nul\u0000byte' },
      { label: 'x', exact: 'yes' },
      { role: 'button', name: 7 },
      Object.create({ css: 'a' }),
      new (class {
        css = 'a';
      })(),
    ]) {
      expect(() => parseLocator(bad), JSON.stringify(bad)).toThrow(ToolError);
    }
  });

  it('css: no selector-engine prefixes, no chains, no XPath or text shorthands', () => {
    for (const css of [
      'xpath=//input',
      'text=Sign in',
      'internal:role=button',
      'internal:attr=[placeholder="x"i]',
      'css=button',
      'id=signup',
      'data-testid=x',
      '_react=App',
      'nth=0',
      '  xpath = //a',
      'button >> text=Sign in',
      'div>>nth=1',
      'a >>> b',
      '//input',
      '..',
      '"Sign in"',
      "'Sign in'",
      '`Sign in`',
    ]) {
      expect(() => parseLocator({ css }), css).toThrow(/plain CSS/);
    }
  });
});

describe('snapshot redaction', () => {
  const raw = [
    '- text: User',
    '- textbox "User": alice',
    '- textbox "Password": hunter2secret',
    '- textbox "pw2": "quoted: value"',
    '- textbox "Code": "123456"',
    '- textbox "Empty"',
    '- textbox "Password" [disabled]: zz',
    '- group:',
    '  - textbox "Password": nested-secret',
    '  - text: after',
    '- paragraph: page echoes hunter2secret here',
  ].join('\n');

  it('nodePrefix keeps role, quoted name and attributes, drops the value', () => {
    expect(nodePrefix('- textbox "Password": hunter2secret')).toBe('- textbox "Password"');
    expect(nodePrefix('  - textbox "a \\" b: c": v')).toBe('- textbox "a \\" b: c"');
    expect(nodePrefix('- textbox "P" [disabled]: x')).toBe('- textbox "P" [disabled]');
    expect(nodePrefix('- textbox: x')).toBe('- textbox');
    expect(nodePrefix('not a node')).toBeNull();
  });

  it('redacts nodes that render like a sensitive field, and the values themselves', () => {
    const out = redactSnapshot(raw, {
      prefixes: new Set(['- textbox "Password"', '- textbox "pw2"', '- textbox "Code"']),
      values: ['hunter2secret', 'quoted: value', '123456'],
    });
    expect(out).toContain('- textbox "User": alice');
    expect(out).toContain(`- textbox "Password": ${REDACTED}`);
    expect(out).toContain(`- textbox "pw2": ${REDACTED}`);
    expect(out).toContain(`- textbox "Code": ${REDACTED}`);
    expect(out).toContain(`  - textbox "Password": ${REDACTED}`);
    expect(out).toContain('- textbox "Empty"');
    expect(out).toContain(`- paragraph: page echoes ${REDACTED} here`);
    for (const secret of ['hunter2secret', 'quoted: value', '123456', 'nested-secret']) {
      expect(out).not.toContain(secret);
    }
    expect(out).toContain('- textbox "Password" [disabled]: zz');
  });

  it('fail-closed mode redacts every text-entry value', () => {
    const out = redactSnapshot(raw, { prefixes: new Set(), values: [] }, true);
    const entries = out.split('\n').filter((l) => l.includes('textbox'));
    expect(entries).toHaveLength(7);
    expect(entries.join('\n')).not.toMatch(/alice|hunter2secret|nested-secret|123456|zz/);
  });
});
