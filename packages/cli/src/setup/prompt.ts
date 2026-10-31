import type { Writable } from 'node:stream';
import { StringDecoder } from 'node:string_decoder';
import { type HiddenInput, PromptAborted } from '../passphrase.ts';

export { PromptAborted };

export interface Prompter {
  ask(question: string, def?: string): Promise<string>;
  secret(question: string): Promise<string>;
  menu?<T extends string>(
    question: string,
    options: readonly (readonly [T, string])[],
    def: T,
  ): Promise<T>;
}

export async function confirm(p: Prompter, question: string, def: boolean): Promise<boolean> {
  for (;;) {
    const a = (await p.ask(`${question} ${def ? '[Y/n]' : '[y/N]'}`)).trim().toLowerCase();
    if (a === '') return def;
    if (a === 'y' || a === 'yes') return true;
    if (a === 'n' || a === 'no') return false;
  }
}

export async function choose<T extends string>(
  p: Prompter,
  question: string,
  options: readonly (readonly [T, string])[],
  def: T,
  out: (t: string) => void,
): Promise<T> {
  if (p.menu) return p.menu(question, options, def);
  out(`${question}\n`);
  options.forEach(([key, label], i) => {
    out(`  ${i + 1}) ${label}${key === def ? '  (default)' : ''}\n`);
  });
  for (;;) {
    const a = (await p.ask('Choice', String(options.findIndex(([k]) => k === def) + 1))).trim();
    const n = Number(a);
    if (Number.isInteger(n) && n >= 1 && n <= options.length) return options[n - 1]?.[0] as T;
    const byKey = options.find(([k]) => k === a.toLowerCase());
    if (byKey) return byKey[0];
  }
}

export class TtyPrompter implements Prompter {
  private pending = '';
  private readonly decoder = new StringDecoder('utf8');
  private readonly input: HiddenInput;
  private readonly output: Writable;

  constructor(input: HiddenInput, output: Writable) {
    this.input = input;
    this.output = output;
  }

  ask(question: string, def?: string): Promise<string> {
    const shown = def !== undefined && def !== '' ? `${question} [${def}]: ` : `${question}: `;
    return this.line(shown, false).then((v) => (v === '' && def !== undefined ? def : v));
  }

  secret(question: string): Promise<string> {
    return this.line(`${question}: `, true);
  }

  private line(prompt: string, hidden: boolean): Promise<string> {
    const input = this.input;
    if (!input.isTTY || typeof input.setRawMode !== 'function') {
      return Promise.reject(new PromptAborted('no TTY to prompt on'));
    }
    const setRaw = input.setRawMode.bind(input);
    return new Promise((resolve, reject) => {
      let value = '';
      let inEscape = 0;
      const finish = (err: Error | null, rest: string) => {
        input.off('data', onData);
        input.pause();
        this.pending = rest;
        setRaw(false);
        this.output.write('\n');
        if (err) reject(err);
        else resolve(value);
      };
      const feed = (s: string): boolean => {
        for (let i = 0; i < s.length; i++) {
          const ch = s[i] as string;
          if (inEscape > 0) {
            if (inEscape === 1 && (ch === '[' || ch === 'O')) inEscape = 2;
            else if (inEscape === 1 || (ch >= '@' && ch <= '~')) inEscape = 0;
            continue;
          }
          if (ch === '\r' || ch === '\n') {
            let rest = s.slice(i + 1);
            if (ch === '\r' && rest.startsWith('\n')) rest = rest.slice(1);
            finish(null, rest);
            return true;
          }
          if (ch === '\u0003') {
            finish(new PromptAborted('interrupted'), '');
            return true;
          }
          if (ch === '\u0004') {
            if (value.length === 0) {
              finish(new PromptAborted('end of input'), '');
              return true;
            }
            continue;
          }
          if (ch === '\u007f' || ch === '\b') {
            if (value.length > 0) {
              value = Array.from(value).slice(0, -1).join('');
              if (!hidden) this.output.write('\b \b');
            }
            continue;
          }
          if (ch === '\u0015') {
            if (!hidden) this.output.write('\b \b'.repeat(Array.from(value).length));
            value = '';
            continue;
          }
          if (ch === '\u001b') {
            inEscape = 1;
            continue;
          }
          if (ch < ' ') continue;
          value += ch;
          if (!hidden) this.output.write(ch);
        }
        return false;
      };
      const onData = (chunk: Buffer | string) => {
        const s = typeof chunk === 'string' ? chunk : this.decoder.write(chunk);
        feed(s);
      };
      this.output.write(prompt);
      setRaw(true);
      const buffered = this.pending;
      this.pending = '';
      if (feed(buffered)) return;
      input.on('data', onData);
      input.resume();
    });
  }
}
