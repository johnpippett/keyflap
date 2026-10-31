import { runInNewContext } from 'node:vm';
import { describe, expect, it } from 'vitest';
import { sourceFiles } from './source-tree.ts';

const swSource = (): string => {
  const file = sourceFiles('packages/approver/src/page', /\.js$/).find((f) =>
    f.path.endsWith('/sw.js'),
  );
  if (!file) throw new Error('no sw.js');
  return file.text;
};

function serviceWorker() {
  const shown: { title: string; options: Record<string, unknown> }[] = [];
  const listeners = new Map<string, (event: unknown) => void>();
  const self = {
    addEventListener: (name: string, fn: (event: unknown) => void) => listeners.set(name, fn),
    skipWaiting: () => {},
    clients: { claim: () => {} },
    registration: {
      showNotification: (title: string, options: Record<string, unknown>) => {
        shown.push({ title, options });
      },
    },
  };
  runInNewContext(swSource(), { self });
  const push = (data?: unknown) =>
    listeners.get('push')?.({
      data: data === undefined ? null : { json: () => data },
      waitUntil: () => {},
    });
  return { shown, push };
}

describe('every push alerts the phone again (Safari replaces a same-tag notification silently)', () => {
  it('two approval pushes in a row get different tags', () => {
    const sw = serviceWorker();
    sw.push();
    sw.push();
    const [a, b] = sw.shown;
    expect(a?.title).toBe('Approval requested');
    expect(b?.title).toBe('Approval requested');
    expect(a?.options.tag).not.toBe(b?.options.tag);
  });

  it('so do two human-check pushes and two address warnings', () => {
    for (const data of [
      { t: 'handoff', host: 'rp.localhost' },
      { t: 'address', on: 'Mac' },
    ]) {
      const sw = serviceWorker();
      sw.push(data);
      sw.push(data);
      expect(sw.shown).toHaveLength(2);
      expect(sw.shown[0]?.options.tag).not.toBe(sw.shown[1]?.options.tag);
    }
  });
});
