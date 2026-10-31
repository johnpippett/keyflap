export type ColorLevel = 0 | 1 | 2 | 3;

type Env = Record<string, string | undefined>;

export function colorLevel(stream: { isTTY?: boolean }, env: Env = process.env): ColorLevel {
  if (env.NO_COLOR !== undefined && env.NO_COLOR !== '') return 0;
  const force = env.FORCE_COLOR;
  if (force === '0' || force === 'false') return 0;
  const forced = force !== undefined;
  if (!forced && (stream.isTTY !== true || env.TERM === 'dumb')) return 0;
  if (force === '3' || env.COLORTERM === 'truecolor' || env.COLORTERM === '24bit') return 3;
  if (force === '2' || /256colou?r/.test(env.TERM ?? '')) return 2;
  return 1;
}

export function lightBackground(env: Env = process.env): boolean {
  const bg = env.COLORFGBG?.split(';').at(-1);
  return bg === '7' || bg === '15';
}

const DRAWS_BLOCKS_PROGRAMS = new Set(['ghostty', 'iTerm.app', 'WezTerm', 'vscode']);
const DRAWS_BLOCKS_TERMS = new Set([
  'xterm-ghostty',
  'xterm-kitty',
  'alacritty',
  'foot',
  'foot-extra',
  'wezterm',
]);
const DRAWS_BLOCKS_MARKERS = [
  'GHOSTTY_RESOURCES_DIR',
  'KITTY_WINDOW_ID',
  'WEZTERM_EXECUTABLE',
  'ALACRITTY_WINDOW_ID',
] as const;

export function drawsBlockElements(env: Env = process.env): boolean {
  if (env.TMUX !== undefined || env.STY !== undefined) return false;
  if (env.TERM_PROGRAM === 'Apple_Terminal') return false;
  return (
    DRAWS_BLOCKS_PROGRAMS.has(env.TERM_PROGRAM ?? '') ||
    DRAWS_BLOCKS_TERMS.has(env.TERM ?? '') ||
    env.LC_TERMINAL === 'iTerm2' ||
    DRAWS_BLOCKS_MARKERS.some((k) => (env[k] ?? '') !== '')
  );
}

export interface TermStyle {
  readonly level: ColorLevel;
  readonly drawsBlocks: boolean;
  ok(s: string): string;
  bad(s: string): string;
  dim(s: string): string;
  bold(s: string): string;
  head(s: string): string;
  header(subtitle?: string): string;
  tile(ch: string): string;
}

const ESC = '\u001b[';
const sgr = (on: string, off: string) => (s: string) =>
  s === '' ? s : `${ESC}${on}m${s}${ESC}${off}m`;
const rgb = (hex: string) =>
  [1, 3, 5].map((i) => Number.parseInt(hex.slice(i, i + 2), 16)).join(';');

export function termStyle(level: ColorLevel, light = false, drawsBlocks = false): TermStyle {
  if (level === 0) {
    const id = (s: string) => s;
    return {
      level,
      drawsBlocks,
      ok: id,
      bad: id,
      dim: id,
      bold: id,
      head: id,
      header: (sub) => (sub ? `KEYFLAP  ${sub}` : 'KEYFLAP'),
      tile: (ch) => `[${ch}]`,
    };
  }
  const blueText =
    level === 3
      ? `38;2;${rgb(light ? '#1f3bd1' : '#7b91ff')}`
      : level === 2
        ? `38;5;${light ? 26 : 105}`
        : light
          ? '34'
          : '94';
  const tile =
    level === 3
      ? `48;2;${rgb('#1f3bd1')};38;2;${rgb('#f4f5f7')}`
      : level === 2
        ? '48;5;26;38;5;231'
        : '44;97';
  const ok = sgr(blueText, '39');
  const bold = sgr('1', '22');
  const dim = sgr('2', '22');
  return {
    level,
    drawsBlocks,
    ok,
    bad: (s) => sgr('7;1', '27;22')(` ${s} `),
    dim,
    bold,
    head: (s) => bold(ok(s)),
    header: (sub) =>
      `${sgr(`${tile};1`, '0')(' K ')} ${bold('KEYFLAP')}${sub ? `  ${dim(sub)}` : ''}`,
    tile: (ch) => sgr(`${tile};1`, '0')(` ${ch} `),
  };
}

export function styleFor(stream: { isTTY?: boolean }, env: Env = process.env): TermStyle {
  return termStyle(colorLevel(stream, env), lightBackground(env), drawsBlockElements(env));
}

export const plainStyle: TermStyle = termStyle(0);

export function stripStyle(s: string): string {
  // biome-ignore lint/suspicious/noControlCharactersInRegex: matching our own escapes
  return s.replace(/\u001b\[[0-9;]*m/g, '');
}
