import type { Readable, Writable } from 'node:stream';

export class PromptAborted extends Error {}

export type Unlock = () => Promise<string>;

export interface HiddenInput extends Readable {
  isTTY?: boolean;
  setRawMode?: (mode: boolean) => unknown;
}

export function readHiddenLine(
  prompt: string,
  input: HiddenInput,
  output: Writable,
): Promise<string> {
  if (!input.isTTY || typeof input.setRawMode !== 'function') {
    return Promise.reject(new PromptAborted('no TTY to prompt on'));
  }
  const setRaw = input.setRawMode.bind(input);
  return new Promise((resolve, reject) => {
    let value = '';
    const finish = (err: Error | null, rest = '') => {
      input.off('data', onData);
      input.pause();
      if (rest.length > 0) input.unshift(Buffer.from(rest, 'utf8'));
      setRaw(false);
      output.write('\n');
      if (err) reject(err);
      else resolve(value);
    };
    const onData = (chunk: Buffer | string) => {
      const s = typeof chunk === 'string' ? chunk : chunk.toString('utf8');
      for (let i = 0; i < s.length; i++) {
        const ch = s[i] as string;
        if (ch === '\r' || ch === '\n') {
          let rest = s.slice(i + 1);
          if (ch === '\r' && rest.startsWith('\n')) rest = rest.slice(1);
          return finish(null, rest);
        }
        if (ch === '\u0003') return finish(new PromptAborted('interrupted'));
        if (ch === '\u0004') {
          if (value.length === 0) return finish(new PromptAborted('end of input'));
          continue;
        }
        if (ch === '\u007f' || ch === '\b') {
          value = Array.from(value).slice(0, -1).join('');
          continue;
        }
        if (ch === '\u0015') {
          value = '';
          continue;
        }
        if (ch < ' ') continue;
        value += ch;
      }
    };
    output.write(prompt);
    setRaw(true);
    input.on('data', onData);
    input.resume();
  });
}
