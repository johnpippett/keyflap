import { stripStyle, termStyle } from '@aab/approver';
import { describe, expect, it } from 'vitest';
import { GUTTER, KeyDecoder, reflow, visible, wrap } from '../src/setup/screen.ts';
import { redactForLog, useScreen } from '../src/setup/ui.ts';
import { capture } from './setup-capture.ts';
import { SCENARIOS } from './setup-scenarios.ts';

const size = { cols: 80, rows: 24 };
const style = termStyle(3);
const plain = (lines: string[]) => lines.map(stripStyle);

describe('setup screens (the preview harness, real steps against fakes)', () => {
  for (const name of SCENARIOS) {
    it(`${name}: every screen fits the terminal and the run uses every canned answer`, async () => {
      const c = await capture(name, { size, style });
      expect(c.shots.length).toBeGreaterThan(8);
      for (const s of c.shots) {
        expect(s.painted.lines, s.caption).toHaveLength(size.rows);
        for (const l of s.painted.lines)
          expect(visible(l), `${s.caption}: ${stripStyle(l)}`).toBeLessThanOrEqual(size.cols);
      }
      const steps = new Set(c.shots.map((s) => s.frame.step?.n).filter(Boolean));
      expect([...steps].sort()).toEqual([1, 2, 3, 4, 5, 6]);
    });
  }

  it('mac-fresh shows the pairing code, the import choice and its own instruction screen, and the health check', async () => {
    const c = await capture('mac-fresh', { size, style });
    const captions = c.shots.map((s) => s.caption);
    const qr = c.shots.find((s) => /Scan the code: Waiting for your phone/.test(s.caption));
    expect(qr?.frame.blocks.some((b) => b.kind === 'figure')).toBe(true);
    const menu = captions.findIndex((t) => /Credentials: Add a credential/.test(t));
    const instructions = captions.findIndex((t) => /Import an export: Export file/.test(t));
    expect(menu).toBeGreaterThan(-1);
    expect(instructions).toBeGreaterThan(menu);
    const choice = c.shots[menu] as (typeof c.shots)[number];
    expect(plain(choice.painted.lines).join('\n')).not.toMatch(/Export your passwords/);
    expect(captions.some((t) => /Finish: Running the health check/.test(t))).toBe(true);
    expect(captions.at(-2)).toMatch(/Finish: Press Enter to finish/);
  });

  it('mac-agents: Claude Code then Codex on their own screens; the config.toml to merge sits behind Tab', async () => {
    const c = await capture('mac-agents', { size, style });
    const pages = [...new Set(c.shots.map((s) => s.frame.page).filter(Boolean))];
    expect(pages.filter((p) => / of 2\)/.test(p as string))).toEqual([
      'Claude Code (1 of 2)',
      'Codex (2 of 2)',
    ]);
    const text = (view: 'main' | 'details') =>
      c.shots.filter((s) => s.frame.view === view).map((s) => plain(s.painted.lines));
    for (const lines of text('main')) {
      expect(lines.join('\n')).not.toContain('default_permissions');
    }
    const toml = text('details').find((l) => l.some((x) => x.includes('default_permissions')));
    expect(toml?.some((l) => l.trim() === 'default_permissions = "keyflap-protected"')).toBe(true);
    const finish = c.shots.findLast((s) => s.frame.step?.n === 6 && s.frame.view === 'main');
    const done = plain(finish?.painted.lines ?? []).join('\n');
    expect(done).toContain('✓ Claude Code, all projects (terminal and desktop app)');
    expect(done).toContain('✓ Codex');
  });

  it('puts every prompt on the text column, with the input marker in the gutter and a blank line above', async () => {
    const c = await capture('mac-fresh', { size, style });
    const prompts = c.shots.filter(
      (s) => s.frame.input?.kind === 'line' && s.frame.view === 'main',
    );
    expect(prompts.length).toBeGreaterThan(4);
    for (const s of prompts) {
      const lines = plain(s.painted.lines);
      const row = (s.painted.cursor as { row: number }).row;
      expect(lines[row]?.indexOf('›'), s.caption).toBe(GUTTER - 2);
      const blank = lines.slice(0, row).findLastIndex((l) => l.trim() === '');
      expect(blank, s.caption).toBeGreaterThan(3);
      expect(lines[blank + 1]?.search(/\S/), s.caption).toBe(GUTTER);
    }
  });

  it('keeps the MCP config, file paths and command lines off the main screen, behind Tab', async () => {
    const c = await capture('mac-fresh', { size, style });
    const main = c.shots
      .filter((s) => s.frame.view === 'main')
      .map((s) => plain(s.painted.lines).join('\n'));
    for (const text of main) {
      expect(text).not.toMatch(/mcpServers|headersHelper|UserPromptSubmit|\$ /);
      expect(text).not.toContain('agent-0b9d6c1e');
    }
    const details = c.shots
      .filter((s) => s.frame.view === 'details')
      .map((s) => plain(s.painted.lines).join('\n'));
    expect(details.some((t) => t.includes('mcpServers'))).toBe(true);
  });

  it('never puts a secret in the setup log or on the terminal after it closes', async () => {
    for (const name of SCENARIOS) {
      const c = await capture(name, { size, style });
      expect(c.log).toMatch(/^# keyflap setup/);
      for (const secret of c.run.secrets) {
        expect(c.log, name).not.toContain(secret);
        expect(c.after, name).not.toContain(secret);
      }
      const [pairingCode, ...others] = c.run.secrets;
      for (const s of c.shots) {
        const text = s.painted.lines.join('\n');
        for (const secret of others) expect(text, s.caption).not.toContain(secret);
        if (s.frame.view === 'main') expect(text, s.caption).not.toContain(pairingCode);
      }
    }
  });

  it('writes the log into the data area as the user, 0600', async () => {
    const c = await capture('mac-fresh', { size, style });
    const path = `${c.run.backend.stateDir}/setup.log`;
    expect(c.run.sys.stat(path)).toMatchObject({ uid: 501, mode: 0o600, isFile: true });
    expect(c.run.sys.userAccess).toContainEqual({
      op: 'write',
      path,
      owner: { uid: 501, gid: 20 },
    });
  });

  it('heads each step with the mode and step count over a bar that fills as steps are done', async () => {
    const c = await capture('linux-fresh', { size, style });
    const fills = new Map<number, number>();
    for (const s of c.shots) {
      const n = s.frame.step?.n;
      if (!n) continue;
      const [head = '', bar = ''] = plain(s.painted.lines);
      expect(head, s.caption).toMatch(new RegExp(`KEYFLAP.*STEP ${n} OF 6$`));
      const filled = [...bar].filter((ch) => ch === '━').length;
      const total = filled + [...bar].filter((ch) => ch === '─').length;
      expect(filled, s.caption).toBe(Math.round((total * n) / 6));
      fills.set(n, filled);
    }
    const byStep = [...fills.entries()].sort(([a], [b]) => a - b).map(([, filled]) => filled);
    expect(byStep).toHaveLength(6);
    expect(byStep).toEqual([...byStep].sort((a, b) => a - b));
    expect(new Set(byStep).size).toBe(6);
  });
});

describe('screen pieces', () => {
  it('wraps styled text to the width and carries the style onto the next line', () => {
    const st = termStyle(3);
    const lines = wrap(`${st.ok('one two three four five six')} seven`, 10, 2);
    for (const l of lines) expect(visible(l)).toBeLessThanOrEqual(10);
    expect(lines.map(stripStyle)).toEqual([
      'one two',
      '  three',
      '  four',
      '  five six',
      '  seven',
    ]);
    expect(lines[1]).toContain('\u001b[38;2;');
  });

  it('keeps deeply indented lines (config to copy) on their own lines', () => {
    expect(reflow(['merge this:', '   a = 1', '   b = 2', '', 'then run it', 'twice'])).toEqual([
      'merge this:',
      '   a = 1',
      '   b = 2',
      '',
      'then run it twice',
    ]);
  });

  it('decodes keys, including an escape sequence split across reads', () => {
    const d = new KeyDecoder();
    expect(d.decode('ab\r\n')).toEqual([
      { kind: 'char', ch: 'a' },
      { kind: 'char', ch: 'b' },
      { kind: 'enter' },
    ]);
    expect(d.decode('\u001b[')).toEqual([]);
    expect(d.decode('A\u0003\t\u007f')).toEqual([
      { kind: 'up' },
      { kind: 'interrupt' },
      { kind: 'tab' },
      { kind: 'backspace' },
    ]);
  });

  it('redacts pairing codes and agent tokens from the log', () => {
    expect(
      redactForLog(`open https://a.ts.net:8766/pair#Abc_-123 now aab_agent_${'x'.repeat(43)}`),
    ).toBe('open https://a.ts.net:8766/pair#… now aab_agent_…');
  });

  it('uses the full screen only on a real terminal', () => {
    const tty = { isTTY: true };
    expect(useScreen({ stdin: tty, stdout: tty }, { TERM: 'xterm-256color' })).toBe(true);
    expect(useScreen({ stdin: tty, stdout: tty }, { TERM: 'dumb' })).toBe(false);
    expect(useScreen({ stdin: tty, stdout: tty }, {})).toBe(false);
    expect(useScreen({ stdin: { isTTY: false }, stdout: tty }, { TERM: 'xterm' })).toBe(false);
  });
});
