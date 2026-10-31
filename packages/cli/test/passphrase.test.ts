import { createInterface } from 'node:readline';
import { PassThrough } from 'node:stream';
import { describe, expect, it } from 'vitest';
import { type HiddenInput, PromptAborted, readHiddenLine } from '../src/passphrase.ts';

function fakeTty(): HiddenInput & PassThrough & { raw: boolean[] } {
  const s = new PassThrough() as unknown as HiddenInput & PassThrough & { raw: boolean[] };
  s.isTTY = true;
  s.raw = [];
  s.setRawMode = (m: boolean) => {
    s.raw.push(m);
    return s;
  };
  return s;
}

function sink() {
  const out = new PassThrough();
  let text = '';
  out.on('data', (c: Buffer) => {
    text += c.toString();
  });
  return { out, text: () => text };
}

describe('no-echo passphrase prompt', () => {
  it('reads one line without echo, with backspace, and restores cooked mode', async () => {
    const tty = fakeTty();
    const { out, text } = sink();
    const p = readHiddenLine('Passphrase: ', tty, out);
    tty.write('hunterX\u007f2\r');
    expect(await p).toBe('hunter2');
    expect(tty.raw).toEqual([true, false]);
    expect(text()).toBe('Passphrase: \n');
    expect(text()).not.toContain('hunter');
  });

  it("doesn't swallow what was typed after Enter: the approver still reads it", async () => {
    const tty = fakeTty();
    const p = readHiddenLine('P: ', tty, sink().out);
    tty.write('secret\ry\n');
    expect(await p).toBe('secret');
    const rl = createInterface({ input: tty, terminal: false });
    const line = await new Promise<string>((res) => rl.once('line', res));
    rl.close();
    expect(line).toBe('y');
  });

  it('Ctrl-C and Ctrl-D on an empty line abort', async () => {
    const a = fakeTty();
    const pa = readHiddenLine('P: ', a, sink().out);
    a.write('abc\u0003');
    await expect(pa).rejects.toBeInstanceOf(PromptAborted);
    expect(a.raw.at(-1)).toBe(false);

    const b = fakeTty();
    const pb = readHiddenLine('P: ', b, sink().out);
    b.write('\u0004');
    await expect(pb).rejects.toBeInstanceOf(PromptAborted);
  });

  it('refuses to prompt without a TTY', async () => {
    const s = new PassThrough() as unknown as HiddenInput;
    await expect(readHiddenLine('P: ', s, sink().out)).rejects.toThrow(/no TTY/);
  });
});
