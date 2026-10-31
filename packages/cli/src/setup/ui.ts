import { plainStyle, stripStyle, type TermStyle } from '@aab/approver';
import { styleMarks } from '../format.ts';
import { PromptAborted, type Prompter } from './prompt.ts';
import {
  type App,
  bodyText,
  emptyFrame,
  type Frame,
  type Input,
  type Key,
  maxScroll,
  type Painted,
  type Place,
  paint,
  type Short,
  type Size,
  STEP_COUNT,
} from './screen.ts';

export interface SetupUi {
  readonly out: (text: string) => void;
  readonly prompt: Prompter;
  step(n: number, title: string): Promise<void>;
  page(title: string, previous?: 'keep-until-read' | 'replace'): Promise<void>;
  brief(short: Short, full: string, o?: { log: boolean }): void;
  status(label: string | null): void;
  wait<T>(label: string, work: () => Promise<T>): Promise<T>;
  logTo(path: string, write: (text: string) => void): void;
  finish(): Promise<void>;
  leave(): void;
}

export function plainHeading(st: TermStyle, n: number, title: string): string {
  const rule = '─'.repeat(Math.max(4, 60 - title.length));
  return `\n${st.dim('──')} ${st.dim(`${n}/${STEP_COUNT}`)} ${st.head(title.toUpperCase())} ${st.dim(rule)}\n`;
}

export function plainUi(
  out: (text: string) => void,
  prompt: Prompter,
  st: TermStyle = plainStyle,
): SetupUi {
  return {
    out,
    prompt,
    step: async (n, title) => out(plainHeading(st, n, title)),
    page: async () => {},
    brief: (_short, full) => out(full),
    status: () => {},
    wait: (_label, work) => work(),
    logTo: () => {},
    finish: async () => {},
    leave: () => {},
  };
}

export function redactForLog(text: string): string {
  return text
    .replace(/(\/pair)#[A-Za-z0-9_-]+/g, '$1#…')
    .replace(/aab_agent_[A-Za-z0-9_-]+/g, 'aab_agent_…');
}

export class SetupLog {
  private entries: string[] = [];
  private section = '';
  private write: ((text: string) => void) | null = null;
  readonly started: string;
  path: string | null = null;

  constructor(started: string) {
    this.started = started;
  }

  add(section: string, text: string): void {
    if (section !== this.section) {
      this.section = section;
      this.entries.push(`\n## ${section}\n`);
    }
    const body = redactForLog(stripStyle(text)).replace(/^\n+|\n+$/g, '');
    if (body !== '') this.entries.push(`${body}\n`);
    this.flush();
  }

  to(path: string, write: (text: string) => void): void {
    this.path = path;
    this.write = write;
    this.flush();
  }

  text(): string {
    return `# keyflap setup, ${this.started}\n${this.entries.join('\n')}`;
  }

  private flush(): void {
    if (!this.write) return;
    try {
      this.write(this.text());
    } catch {
      this.write = null;
      this.path = null;
    }
  }
}

export interface Screen {
  size(): Size;
  draw(p: Painted, f: Frame): void;
  enter(onResize: () => void): void;
  restore(): void;
}

export interface Keys {
  open(): void;
  next(f: Frame): Promise<Key>;
  flush(): void;
  close(): void;
}

const YES_NO = /^(.*?)\s*\[(Y\/n|y\/N)\]$/;

export interface ScreenUiOptions {
  screen: Screen;
  keys: Keys;
  style: TermStyle;
  mode: string;
  app?: App;
  alert?: string;
  log: SetupLog;
  afterLeave: (text: string) => void;
  fallbackPrompt: Prompter;
}

export class ScreenUi implements SetupUi {
  readonly frame: Frame;
  readonly prompt: Prompter;
  private readonly o: ScreenUiOptions;
  private unseen = false;
  private left = false;
  private entered = false;
  private ticker: ReturnType<typeof setInterval> | null = null;
  private section = 'Setup';

  constructor(o: ScreenUiOptions) {
    this.o = o;
    this.frame = emptyFrame(o.mode, o.app ?? 'setup', o.alert ?? null);
    this.prompt = {
      ask: (q, def) => (this.left ? o.fallbackPrompt.ask(q, def) : this.ask(q, def)),
      secret: (q) =>
        this.left
          ? o.fallbackPrompt.secret(q)
          : this.line(q.replace(/ \(not shown\)$/, ''), '', true),
      menu: (q, options, def) =>
        this.left
          ? Promise.reject(new Error('no menu after the screen closed'))
          : this.menu(q, options, def),
    };
  }

  readonly out = (text: string): void => {
    if (this.left) {
      this.o.afterLeave(styleMarks(text, this.o.style));
      return;
    }
    if (text.trim() === '') return;
    this.frame.blocks.push({ kind: 'text', text });
    this.unseen = true;
    this.draw();
  };

  brief(short: Short, full: string, o: { log: boolean } = { log: true }): void {
    if (this.left) {
      this.out(full);
      return;
    }
    if (o.log) this.o.log.add(this.section, full);
    const detail =
      typeof short === 'string'
        ? full
        : full.replace('printed' in short ? short.printed : short.art, '');
    if (detail.trim() !== '') this.frame.details.push(detail);
    if (typeof short === 'string' && short.trim() === '') return;
    this.frame.blocks.push(
      typeof short === 'string'
        ? { kind: 'text', text: short }
        : 'qr' in short
          ? { kind: 'figure', qr: short.qr, beside: short.beside }
          : { kind: 'figure', art: short.art, beside: short.beside },
    );
    this.unseen = true;
    this.draw();
  }

  async step(n: number, title: string): Promise<void> {
    if (this.frame.app === 'console') return this.page(title);
    await this.gate();
    this.section = `${n}/${STEP_COUNT} ${title}`;
    this.o.log.add(this.section, '');
    this.reset();
    this.frame.step = { n, title };
    this.frame.page = null;
    this.draw();
  }

  async page(
    title: string,
    previous: 'keep-until-read' | 'replace' = 'keep-until-read',
  ): Promise<void> {
    if (previous === 'keep-until-read') await this.gate();
    this.reset();
    this.frame.page = title;
    this.draw();
  }

  place(section: Place | null): void {
    this.reset();
    this.frame.section = section;
    this.frame.page = null;
    this.draw();
  }

  hold(label: string): Promise<void> {
    return this.gate(label);
  }

  status(label: string | null): void {
    if (this.left) return;
    this.frame.status = label === null ? null : { label, tick: 0 };
    if (label === null) this.stopTicker();
    else this.startTicker();
    this.draw();
  }

  async wait<T>(label: string, work: () => Promise<T>): Promise<T> {
    this.status(label);
    try {
      return await work();
    } finally {
      this.status(null);
    }
  }

  logTo(path: string, write: (text: string) => void): void {
    this.o.log.to(path, write);
    this.frame.footnote = null;
  }

  async finish(): Promise<void> {
    if (this.left) return;
    if (this.o.log.path) {
      this.frame.blocks.push({ kind: 'text', text: `Setup log: ${this.o.log.path}` });
    }
    this.unseen = true;
    await this.gate('Press Enter to finish');
    this.leave();
  }

  leave(): void {
    if (this.left) return;
    this.left = true;
    this.stopTicker();
    this.o.keys.close();
    if (this.entered) this.o.screen.restore();
    const size = this.o.screen.size();
    const body = bodyText({ ...this.frame, view: 'main' }, size, this.o.style);
    if (body.trim() !== '') this.o.afterLeave(`\n${body}\n`);
  }

  private reset(): void {
    this.frame.blocks = [];
    this.frame.details = [];
    this.frame.view = 'main';
    this.frame.scroll = 0;
    this.frame.input = null;
    this.frame.status = null;
    this.stopTicker();
    this.unseen = false;
  }

  private draw(): void {
    if (this.left) return;
    if (!this.entered) {
      this.entered = true;
      this.o.keys.open();
      this.o.screen.enter(() => this.draw());
    }
    this.o.screen.draw(paint(this.frame, this.o.screen.size(), this.o.style), this.frame);
  }

  private startTicker(): void {
    if (this.ticker) return;
    this.ticker = setInterval(() => {
      if (!this.frame.status) return;
      this.frame.status.tick++;
      this.draw();
    }, 120);
    this.ticker.unref?.();
  }

  private stopTicker(): void {
    if (this.ticker) clearInterval(this.ticker);
    this.ticker = null;
  }

  private async gate(label = 'Press Enter to continue'): Promise<void> {
    if (!this.unseen || this.left) return;
    await this.read({ kind: 'continue', label }, async (k) => (k.kind === 'enter' ? true : null));
  }

  private async read<T>(input: Input, onKey: (k: Key) => Promise<T | null>): Promise<T> {
    this.frame.input = input;
    this.frame.status = null;
    this.stopTicker();
    this.o.keys.flush();
    this.draw();
    try {
      for (;;) {
        const k = await this.o.keys.next(this.frame);
        if (k.kind === 'interrupt') throw new PromptAborted('interrupted');
        if (this.navigate(k)) continue;
        if (k.kind === 'escape' && this.frame.app === 'console') throw new PromptAborted('back');
        const r = await onKey(k);
        if (r !== null) {
          this.unseen = false;
          return r;
        }
        this.draw();
      }
    } finally {
      this.frame.input = null;
      this.frame.view = 'main';
    }
  }

  private navigate(k: Key): boolean {
    const f = this.frame;
    if (k.kind === 'tab' && (f.details.length > 0 || f.view === 'details')) {
      f.view = f.view === 'main' ? 'details' : 'main';
      f.scroll = 0;
      this.draw();
      return true;
    }
    if (f.view !== 'details') return false;
    const size = this.o.screen.size();
    const step = { up: -1, down: 1, pageup: -(size.rows - 8), pagedown: size.rows - 8 } as const;
    if (k.kind in step) {
      const by = step[k.kind as keyof typeof step];
      f.scroll = Math.max(0, Math.min(maxScroll(f, size), f.scroll + by));
    } else if (k.kind === 'escape' || k.kind === 'enter') {
      f.view = 'main';
    }
    this.draw();
    return true;
  }

  private ask(question: string, def?: string): Promise<string> {
    const yn = YES_NO.exec(question);
    if (yn) return this.line(yn[1] as string, yn[2] as string, false, true);
    return this.line(question, def ?? '', false).then((v) =>
      v === '' && def !== undefined ? def : v,
    );
  }

  private line(label: string, hint: string, hidden: boolean, yesNo = false): Promise<string> {
    const input: Input & { kind: 'line' } = { kind: 'line', label, hint, value: '', hidden };
    return this.read(input, async (k) => {
      if (k.kind === 'eof' && input.value === '') throw new PromptAborted('end of input');
      if (k.kind === 'enter') {
        const shown = hidden ? '' : yesNo ? yesNoAnswer(input.value, hint) : input.value || hint;
        this.frame.blocks.push({ kind: 'answer', question: label, answer: shown });
        if (!hidden) this.o.log.add(this.section, `> ${label}: ${shown}`);
        return input.value;
      }
      if (k.kind === 'backspace') input.value = Array.from(input.value).slice(0, -1).join('');
      else if (k.kind === 'clear') input.value = '';
      else if (k.kind === 'char') {
        if (!yesNo) input.value += k.ch;
        else if (/^[yYnN]$/.test(k.ch)) input.value = k.ch;
      }
      return null;
    });
  }

  private menu<T extends string>(
    question: string,
    options: readonly (readonly [T, string])[],
    def: T,
  ): Promise<T> {
    const start = Math.max(
      0,
      options.findIndex(([k]) => k === def),
    );
    const input: Input & { kind: 'menu' } = {
      kind: 'menu',
      label: question,
      options: options.map(([, label]) => label),
      selected: start,
    };
    return this.read(input, async (k) => {
      if (k.kind === 'up') input.selected = (input.selected + options.length - 1) % options.length;
      else if (k.kind === 'down') input.selected = (input.selected + 1) % options.length;
      else if (k.kind === 'char' && /^[1-9]$/.test(k.ch) && Number(k.ch) <= options.length) {
        input.selected = Number(k.ch) - 1;
      } else if (k.kind === 'enter') {
        const [key, label] = options[input.selected] as readonly [T, string];
        this.frame.blocks.push({ kind: 'answer', question, answer: label.replace(/ \(.*$/, '') });
        this.o.log.add(this.section, `> ${question}: ${label}`);
        return key;
      }
      return null;
    });
  }
}

function yesNoAnswer(value: string, hint: string): string {
  const v = value === '' ? (hint === 'Y/n' ? 'y' : 'n') : value.toLowerCase();
  return v === 'y' ? 'Yes' : 'No';
}

export function useScreen(
  io: { stdin: { isTTY?: boolean }; stdout: { isTTY?: boolean } },
  env: NodeJS.ProcessEnv,
): boolean {
  return (
    io.stdin.isTTY === true &&
    io.stdout.isTTY === true &&
    env.TERM !== undefined &&
    env.TERM !== 'dumb'
  );
}
