import { describe, expect, it } from 'vitest';
import { AgentRegistry } from '../src/agents.ts';
import { openDb } from '../src/db.ts';
import { hasUnsafeText, printable } from '../src/display-text.ts';
import { addPasswordItem } from '../src/passwords.ts';

const ch = (n: number) => String.fromCharCode(n);

const UNSAFE = [
  'esc\u001b]52;c;cHduZWQ=\u0007',
  'csi\u009b31m',
  'nel\u0085line',
  'del\u007f',
  `rlo${ch(0x202e)}gnp.exe`,
  `lri${ch(0x2066)}x${ch(0x2069)}`,
  `lrm${ch(0x200e)}`,
  `alm${ch(0x061c)}`,
  `ls${ch(0x2028)}ps${ch(0x2029)}`,
];

describe('display text', () => {
  it('flags C0, DEL, C1, bidi controls and line separators; passes ordinary text', () => {
    for (const s of UNSAFE) expect(hasUnsafeText(s), JSON.stringify(s)).toBe(true);
    for (const s of ['alice', 'bob@mail.test', 'Zoë Ångström', '名前', 'emoji 🔑', 'a b']) {
      expect(hasUnsafeText(s)).toBe(false);
    }
  });

  it('printable escapes every unsafe character visibly and leaves the rest', () => {
    for (const s of UNSAFE) expect(hasUnsafeText(printable(s))).toBe(false);
    expect(printable(`a\u001b[2Jb${ch(0x202e)}c`)).toBe('a\\u001b[2Jb\\u202ec');
    expect(printable('Zoë')).toBe('Zoë');
  });

  it('agent names reject C1 and bidi controls too', () => {
    const registry = new AgentRegistry(openDb(':memory:'));
    for (const bad of ['c1\u0085', 'csi\u009b', `bidi${ch(0x2067)}x`]) {
      expect(() => registry.add(bad)).toThrow(/agent name/);
    }
  });

  it('password usernames reject C1 and bidi controls before the signer is asked', async () => {
    const db = openDb(':memory:');
    const signer = {
      storeItem: async () => {
        throw new Error('signer must not be reached');
      },
      deleteItem: async () => {
        throw new Error('signer must not be reached');
      },
    };
    for (const username of ['c1\u009b31m', `bidi${ch(0x202e)}evil`, 'esc\u001b[0m']) {
      await expect(
        addPasswordItem({ signer, db }, { site: 'example.com', username, password: 'pw-123456' }),
      ).rejects.toThrow(/username must be at most 256 printable characters/);
    }
  });
});
