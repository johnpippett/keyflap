import { PassThrough } from 'node:stream';
import { describe, expect, it } from 'vitest';
import {
  type ApprovalRequest,
  ApproverKey,
  colorLevel,
  drawsBlockElements,
  lightBackground,
  renderPrompt,
  stripStyle,
  styleFor,
  TerminalApprover,
  termStyle,
} from '../src/index.ts';

const tty = { isTTY: true };
const pipe = { isTTY: false };
// biome-ignore lint/suspicious/noControlCharactersInRegex: looking for escapes
const ESC = /\u001b/;
// biome-ignore lint/suspicious/noControlCharactersInRegex: looking for red (31/91, 38;2;r…)
const RED = /\u001b\[(?:[0-9;]*;)?(?:31|91|41|101)m/;

describe('terminal colour switch', () => {
  it('NO_COLOR turns colour off, even on a TTY and with COLORTERM', () => {
    expect(colorLevel(tty, { NO_COLOR: '1', COLORTERM: 'truecolor' })).toBe(0);
    expect(colorLevel(tty, { NO_COLOR: '1', FORCE_COLOR: '3' })).toBe(0);
  });

  it('an empty NO_COLOR does not count (no-color.org)', () => {
    expect(colorLevel(tty, { NO_COLOR: '' })).toBe(1);
  });

  it('no colour when the stream is not a TTY, or TERM is dumb', () => {
    expect(colorLevel(pipe, { COLORTERM: 'truecolor' })).toBe(0);
    expect(colorLevel({}, {})).toBe(0);
    expect(colorLevel(tty, { TERM: 'dumb' })).toBe(0);
  });

  it('24-bit when the terminal says so, 256 colours when TERM does, else 16', () => {
    expect(colorLevel(tty, { COLORTERM: 'truecolor' })).toBe(3);
    expect(colorLevel(tty, { COLORTERM: '24bit' })).toBe(3);
    expect(colorLevel(tty, { COLORTERM: 'truecolor', TERM: 'xterm-256color' })).toBe(3);
    expect(colorLevel(tty, { TERM: 'xterm-256color' })).toBe(2);
    expect(colorLevel(tty, { TERM: 'screen-256colour' })).toBe(2);
    expect(colorLevel(tty, { TERM: 'xterm' })).toBe(1);
    expect(colorLevel(pipe, { FORCE_COLOR: '2' })).toBe(2);
  });

  it("256 colours: the cube's fixed blues, never the theme-mapped 16", () => {
    expect(termStyle(2).ok('a')).toContain('38;5;105');
    expect(termStyle(2, true).ok('a')).toContain('38;5;26');
    expect(termStyle(2).head('A')).toContain('38;5;105');
    expect(termStyle(2).header()).toContain('48;5;26;38;5;231');
    for (const st of [termStyle(2), termStyle(2, true)]) {
      expect(st.ok('a')).not.toContain('[94m');
      expect(st.ok('a')).not.toContain('[34m');
    }
  });

  it('FORCE_COLOR overrides the TTY check', () => {
    expect(colorLevel(pipe, { FORCE_COLOR: '1' })).toBe(1);
    expect(colorLevel(pipe, { FORCE_COLOR: '3' })).toBe(3);
    expect(colorLevel(tty, { FORCE_COLOR: '0' })).toBe(0);
  });

  it('plain style writes no escapes and changes no text', () => {
    const st = styleFor(tty, { NO_COLOR: '1' });
    for (const f of [st.ok, st.bad, st.dim, st.bold, st.head]) expect(f('x y')).toBe('x y');
    expect(st.header('status')).toBe('KEYFLAP  status');
  });

  it('brand blue: #7b91ff text on dark terminals, #1f3bd1 on light; bright blue in 16 colours', () => {
    expect(termStyle(3).ok('a')).toContain('38;2;123;145;255');
    expect(lightBackground({ COLORFGBG: '0;15' })).toBe(true);
    expect(lightBackground({ COLORFGBG: '15;0' })).toBe(false);
    expect(termStyle(3, true).ok('a')).toContain('38;2;31;59;209');
    expect(termStyle(1).ok('a')).toBe('\u001b[94ma\u001b[39m');
    expect(termStyle(1, true).ok('a')).toBe('\u001b[34ma\u001b[39m');
  });

  it('denied is an inverted flap, never red', () => {
    for (const st of [termStyle(1), termStyle(3), termStyle(3, true)]) {
      const s = st.bad('DENIED');
      expect(s).toContain('\u001b[7;1m DENIED ');
      for (const f of [st.ok, st.bad, st.dim, st.bold, st.head, st.header]) {
        expect(f('x')).not.toMatch(RED);
      }
      expect(st.header('x')).not.toMatch(/255;0;0|220;38;38/);
    }
  });
});

const req = (intentText = 'log me into the test site', allowFor = false): ApprovalRequest => ({
  display: {
    intentText,
    intentAt: Date.UTC(2026, 0, 1),
    verifiedOrigin: 'https://example.com',
    agentName: 'dev-agent',
    credentialType: 'passkey',
    action: 'sign-in',
    ...(allowFor ? { allowForMs: 30 * 60_000 } : {}),
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

describe('invariant 5: a coloured approval prompt shows the same fields in the same order', () => {
  it('colour only wraps the plain lines: stripping it gives the plain prompt exactly', () => {
    const nasty = 'pay \u001b[2J\u001b[31mApproved!\u001b[0m\n│ Site:       https://evil.example';
    for (const st of [termStyle(1), termStyle(3), termStyle(3, true)]) {
      const plain = renderPrompt(req(nasty, true));
      const coloured = renderPrompt(req(nasty, true), st);
      expect(coloured).not.toBe(plain);
      const body = (s: string) => s.split('\n').filter((_, i) => i !== 1);
      expect(body(stripStyle(coloured))).toEqual(body(plain));
      expect(stripStyle(coloured).split('\n')[1]).toMatch(
        /^┌─ {2}K {2}KEYFLAP {2}approval requested ─+$/,
      );
      expect(plain).toContain('│ Allow-for:  approving also lets');
      expect(plain).not.toMatch(ESC);
      const site = stripStyle(coloured)
        .split('\n')
        .filter((l) => l.startsWith('│ Site:'));
      expect(site).toEqual(['│ Site:       https://example.com']);
    }
  });

  it('the terminal approver is plain on a non-TTY stream and with NO_COLOR', async () => {
    const run = async (style?: ReturnType<typeof termStyle>) => {
      const input = new PassThrough();
      const output = new PassThrough();
      let text = '';
      output.on('data', (c: Buffer) => {
        text += c.toString();
      });
      const t = new TerminalApprover({
        key: ApproverKey.generate('t'),
        input,
        output,
        timeoutMs: 2000,
        ...(style ? { style } : {}),
      });
      const p = t.request(req());
      setTimeout(() => input.write('n\n'), 10);
      expect(await p).toEqual({ approved: false, reason: 'user_denied' });
      await new Promise((r) => setImmediate(r));
      return text;
    };
    const plain = await run();
    expect(plain).not.toMatch(ESC);
    expect(plain).toContain('KEYFLAP · approval requested');
    expect(plain).toMatch(/Approve\? \[y\/N\] {3}DENIED\n$/);
    expect(await run(styleFor(tty, { NO_COLOR: '1' }))).toBe(plain);
    const coloured = await run(termStyle(3));
    expect(coloured).toContain('\u001b[7;1m DENIED ');
    expect(coloured).not.toMatch(RED);
  });
});

describe('which terminals draw block elements themselves (so half blocks fill the cell)', () => {
  const cases: [string, Record<string, string>, boolean][] = [
    ['Terminal.app', { TERM_PROGRAM: 'Apple_Terminal', TERM: 'xterm-256color' }, false],
    ['Terminal.app under sudo (only TERM survives)', { TERM: 'xterm-256color' }, false],
    ['an unknown terminal', { TERM: 'xterm' }, false],
    ['no TERM at all', {}, false],
    ['Ghostty', { TERM_PROGRAM: 'ghostty', TERM: 'xterm-ghostty' }, true],
    ['Ghostty under sudo', { TERM: 'xterm-ghostty' }, true],
    ['iTerm2', { TERM_PROGRAM: 'iTerm.app', TERM: 'xterm-256color' }, true],
    ['iTerm2 over ssh', { LC_TERMINAL: 'iTerm2', TERM: 'xterm-256color' }, true],
    ['kitty under sudo', { TERM: 'xterm-kitty' }, true],
    ['kitty', { KITTY_WINDOW_ID: '1', TERM: 'xterm-kitty' }, true],
    ['WezTerm', { TERM_PROGRAM: 'WezTerm', TERM: 'xterm-256color' }, true],
    ['Alacritty', { TERM: 'alacritty' }, true],
    ['foot', { TERM: 'foot' }, true],
    ['VS Code', { TERM_PROGRAM: 'vscode', TERM: 'xterm-256color' }, true],
    [
      'tmux started from Ghostty (any terminal may attach)',
      { TMUX: '/tmp/tmux-1000/default,1,0', TERM_PROGRAM: 'tmux', GHOSTTY_RESOURCES_DIR: '/x' },
      false,
    ],
    ['GNU screen started from kitty', { STY: '1.pts-0', KITTY_WINDOW_ID: '1' }, false],
  ];
  for (const [name, env, drawn] of cases) {
    it(`${name}: ${drawn ? 'yes' : 'not known'}`, () => {
      expect(drawsBlockElements(env)).toBe(drawn);
      expect(styleFor({ isTTY: true }, env).drawsBlocks).toBe(drawn);
    });
  }
});
