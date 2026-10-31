import { runInNewContext } from 'node:vm';
import { describe, expect, it } from 'vitest';
import { sourceFiles } from './source-tree.ts';

const page = (name: string): string => {
  const file = sourceFiles('packages/approver/src/page', /\.js$/).find((f) =>
    f.path.endsWith(`/${name}`),
  );
  if (!file) throw new Error(`no page script ${name}`);
  return file.text;
};

const CHANGED = (on: string) =>
  `The approval address on your ${on} was changed. Don't approve anything until you've checked it at your ${on}.`;
const UNVERIFIED = (on: string) =>
  `Keyflap can't check the approval address on your ${on} right now. Approvals are off until it can.`;

function pushTo(sw: string, data: unknown): { title: string; options: Record<string, unknown> }[] {
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
  runInNewContext(sw, { self });
  listeners.get('push')?.({ data: { json: () => data }, waitUntil: () => {} });
  return shown;
}

describe('the approver page says what happened to the approval address, in fixed words', () => {
  it('the service worker shows the warning for the named platform, and "computer" for anything else', () => {
    const sw = page('sw.js');
    expect(pushTo(sw, { t: 'address', on: 'Mac' })).toEqual([
      {
        title: 'Approval address changed',
        options: expect.objectContaining({ body: CHANGED('Mac'), requireInteraction: true }),
      },
    ]);
    for (const on of ['computer', undefined, '<b>evil</b>', 'mac']) {
      const [n] = pushTo(sw, { t: 'address', on });
      expect(n?.options.body, String(on)).toBe(CHANGED('computer'));
    }
    expect(pushTo(sw, { t: 'approval' })[0]?.title).toBe('Approval requested');
  });

  it('the page uses the same sentence for the 401 and its own for a paused address', () => {
    const lines = page('app.js').match(
      /^const (?:platformWord|addressChangedText|addressUnverifiedText) =[^;]*;/gm,
    );
    expect(lines).toHaveLength(3);
    const texts = runInNewContext(
      `${(lines ?? []).join('\n')}\n({ addressChangedText, addressUnverifiedText })`,
    ) as {
      addressChangedText: (on: unknown) => string;
      addressUnverifiedText: (on: unknown) => string;
    };
    expect(texts.addressChangedText('Mac')).toBe(CHANGED('Mac'));
    expect(texts.addressChangedText(undefined)).toBe(CHANGED('computer'));
    expect(texts.addressUnverifiedText('Mac')).toBe(UNVERIFIED('Mac'));
    expect(texts.addressUnverifiedText('x')).toBe(UNVERIFIED('computer'));
  });

  it('an approval refused during a short pause says to try again, not a code', () => {
    const app = page('app.js');
    const line = app.match(/^const notApprovedText =[^;]*;/m)?.[0];
    expect(line).toBeDefined();
    const notApprovedText = runInNewContext(`${line}\nnotApprovedText`) as (m: string) => string;
    expect(notApprovedText('approver_address_unverified')).toBe(
      "Not approved: Keyflap can't check the approval address right now. Try again in a moment.",
    );
    expect(notApprovedText('expired')).toBe('Not approved: expired');
    expect(app).toContain('fail(notApprovedText(e.message || String(e)))');
  });
});
