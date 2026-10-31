import { plainStyle, stripStyle } from '@aab/approver';
import { describe, expect, it } from 'vitest';
import { USAGE } from '../src/args.ts';
import { SECTIONS } from '../src/console/menu.ts';
import { ConsoleRefused, consoleCommand } from '../src/console/run.ts';
import { type ConsoleCapture, captureConsole, ESC, type Step, TOUR } from './console-capture.ts';
import { runCli } from './helpers.ts';

const size = { cols: 80, rows: 24 };

async function tour(steps: Step[], o: Partial<Parameters<typeof captureConsole>[1]> = {}) {
  return captureConsole(steps, { size, style: plainStyle, ...o });
}

function screens(c: ConsoleCapture): string[] {
  return c.shots.map((s) => stripStyle(s.painted.lines.join('\n')));
}

function shown(c: ConsoleCapture, caption: RegExp): string {
  const shot = c.shots.find((s) => caption.test(s.caption));
  if (!shot) throw new Error(`no screen captioned ${caption}`);
  return stripStyle(shot.painted.lines.join('\n'));
}

describe('console: sudo keyflap with no command', () => {
  it('runs each change through the real admin operations', async () => {
    const c = await tour(TOUR);
    try {
      const domains = c.world.passwords().map((p) => p.domain);
      expect(domains).toContain('notion.so');
      expect(domains).not.toContain('linear.app');
      expect(c.world.phones).toHaveLength(2);
      const agents = c.world.agents.list().filter((a) => a.revokedAt === null);
      expect(agents.map((a) => a.name).sort()).toEqual(['claude-code', 'codex', 'research']);
      expect(c.world.policies.list().find((r) => r.pattern === 'github.com')).toMatchObject({
        mode: 'allow-for',
        allowForMs: 30 * 60_000,
      });
      expect(c.world.clears).toEqual([
        {
          agent: c.world.agents.list().find((a) => a.name === 'claude-code')?.id,
          site: 'github.com',
        },
      ]);
      expect(shown(c, /^Overview: What do you want to manage/)).toContain('✓ 1 phone paired.');
      const loosen = c.shots.find((s) => /github\.com: skip the prompt/.test(s.caption));
      expect(loosen?.frame.input).toMatchObject({ kind: 'line', hint: 'y/N' });
      expect(c.after.trim()).toBe('');
    } finally {
      await c.world.close();
    }
  });

  it('never shows a password, a TOTP secret or an agent token, not even behind Tab', async () => {
    const c = await tour(TOUR);
    try {
      const everything = [
        ...screens(c),
        ...c.shots.flatMap((s) => s.frame.details),
        ...c.shots.flatMap((s) => s.frame.blocks.map((b) => JSON.stringify(b))),
      ].join('\n');
      expect(c.world.tokens.length).toBeGreaterThan(2);
      for (const secret of [...c.world.secrets, ...c.world.tokens, 'tour-typed-pw']) {
        expect(everything).not.toContain(secret);
      }
    } finally {
      await c.world.close();
    }
  });

  it('asks before a removal, defaults to no, and changes nothing on no', async () => {
    const c = await tour([
      { q: /^What do you want to manage/, a: '4' },
      { q: /^What now/, a: '3' },
      { q: /^Which one/, a: '1' },
      { q: /^Revoke "claude-code"\?/, a: '' },
      { q: /^What now/, a: ESC },
      { q: /^What do you want to manage/, a: ESC },
    ]);
    try {
      expect(shown(c, /Revoke "claude-code"/)).toContain('y/N');
      expect(shown(c, /Press Enter to go back/)).toContain('Nothing changed.');
      expect(c.world.agents.list().every((a) => a.revokedAt === null)).toBe(true);
    } finally {
      await c.world.close();
    }
  });

  it('Esc at any prompt goes back without a change', async () => {
    const c = await tour([
      { q: /^What do you want to manage/, a: '5' },
      { q: /^What now/, a: '2' },
      { q: /^Site/, a: 'x.example' },
      { q: /^For which agent/, a: ESC },
      { q: /^What now/, a: ESC },
      { q: /^What do you want to manage/, a: ESC },
    ]);
    try {
      expect(c.world.policies.list().map((r) => r.pattern)).toEqual(['bank.example']);
    } finally {
      await c.world.close();
    }
  });

  it('narrows a long list by name before it asks which one', async () => {
    const extra = Array.from({ length: 10 }, (_, i) => `site${i}.example`);
    const c = await tour(
      [
        { q: /^What do you want to manage/, a: '1' },
        { q: /^What now/, a: '4' },
        { q: /^13 to choose from/, a: 'linear' },
        { q: /^Which one/, a: '' },
        { q: /^Remove the password for linear\.app/, a: 'y' },
        { q: /^What now/, a: ESC },
        { q: /^What do you want to manage/, a: ESC },
      ],
      { passwords: extra },
    );
    try {
      expect(c.world.passwords().map((p) => p.domain)).not.toContain('linear.app');
      expect(c.world.passwords()).toHaveLength(12);
    } finally {
      await c.world.close();
    }
  });

  it('says when the approval address is wrong, with the fix behind Tab', async () => {
    const c = await tour([{ q: /^What do you want to manage/, a: ESC }], {
      prepare: (w) => {
        w.address.state = { kind: 'latched', at: Date.UTC(2026, 9, 30, 8), seen: 'x proxies to y' };
      },
    });
    try {
      expect(shown(c, /What do you want to manage/)).toContain(
        '✗ The approval address changed, so phones were signed out. Tab shows how.',
      );
      expect(shown(c, /Tab: details/)).toContain('sudo keyflap approver pair');
    } finally {
      await c.world.close();
    }
  });

  it('after a trip, says when the address is right again and only pairing is left', async () => {
    const c = await tour([{ q: /^What do you want to manage/, a: ESC }], {
      prepare: (w) => {
        w.address.state = {
          kind: 'latched',
          at: Date.UTC(2026, 9, 30, 8),
          seen: 'x proxies to y',
          latest: { checkedAt: Date.UTC(2026, 9, 30, 9), verdict: { kind: 'ok' } },
        };
      },
    });
    try {
      expect(shown(c, /What do you want to manage/)).toContain(
        '✗ The address is right again, but phones were signed out: pair one again.',
      );
    } finally {
      await c.world.close();
    }
  });

  it('fails closed when the broker does not answer: it says so and returns to the menu', async () => {
    const down = new Error("the broker service isn't running");
    const c = await tour(
      [
        { q: /^What do you want to manage/, a: '1' },
        { q: /^What now/, a: '4' },
        { q: /^What now/, a: ESC },
        { q: /^What do you want to manage/, a: ESC },
      ],
      {
        dispatch: () => async () => {
          throw down;
        },
      },
    );
    try {
      expect(shown(c, /^Overview: What do you want/)).toContain(`✗ ${down.message}`);
      expect(shown(c, /Remove one: Press Enter/)).toContain(`✗ ${down.message}`);
      expect(c.world.passwords()).toHaveLength(3);
    } finally {
      await c.world.close();
    }
  });
});

describe('console: only commands that print no secret', () => {
  it('refuses the commands that print a token or a pairing link, or read a secret', () => {
    for (const argv of [
      ['agent', 'add', 'x'],
      ['approver', 'pair'],
      ['approver', 'qr'],
      ['password', 'add', 'example.com'],
      ['password', 'import', 'x.csv', '--all'],
      ['setup'],
      ['doctor'],
      ['daemon', '--unprotected'],
      ['mcp-headers', '--agent', 'a', '--service'],
    ]) {
      expect(() => consoleCommand(argv), argv.join(' ')).toThrow(ConsoleRefused);
    }
  });

  it('every command in the menu table parses and is allowed', () => {
    const argvs = SECTIONS.flatMap((s) =>
      s.actions.flatMap((a) =>
        a.kind === 'show' || a.kind === 'list' || a.kind === 'pick' ? [a.argv] : [],
      ),
    );
    expect(argvs.length).toBeGreaterThan(8);
    for (const argv of argvs) expect(() => consoleCommand(argv)).not.toThrow();
  });

  it('without a terminal, keyflap with no command prints its usage as before', async () => {
    const r = await runCli([], { env: { KEYFLAP_MODE: 'service' } });
    expect(r.code).toBe(0);
    expect(r.stdout).toBe(USAGE);
  });
});
