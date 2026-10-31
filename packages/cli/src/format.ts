import type { TermStyle } from '@aab/approver';

export function formatDuration(ms: number): string {
  const unit = (n: number, w: string) => `${n} ${w}${n === 1 ? '' : 's'}`;
  const s = Math.round(ms / 1000);
  if (s < 60) return unit(s, 'second');
  const m = Math.round(s / 60);
  if (m < 60) return unit(m, 'minute');
  const h = Math.floor(m / 60);
  const min = m % 60;
  if (h < 48 || h % 24 !== 0 || min !== 0) {
    return min === 0 ? unit(h, 'hour') : `${unit(h, 'hour')} ${unit(min, 'minute')}`;
  }
  return unit(h / 24, 'day');
}

export function styleMarks(text: string, st: TermStyle): string {
  if (st.level === 0) return text;
  return text.replace(/^( *)([✓✗]) /gm, (_m, sp: string, mark: string) =>
    mark === '✓' ? `${sp}${st.ok(mark)} ` : `${sp.slice(1)}${st.bad(mark)}`,
  );
}
