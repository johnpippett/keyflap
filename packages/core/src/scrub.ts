export const REDACTED = '[redacted]';

export const MIN_SCRUBBED_LENGTH = 4;

export function secretForms(secret: string): string[] {
  const collapsed = secret.replace(/\s+/g, ' ').trim();
  const forms = new Set<string>();
  for (const v of new Set([secret, collapsed])) {
    forms.add(v);
    forms.add(JSON.stringify(v).slice(1, -1));
    forms.add(encodeURIComponent(v));
    forms.add(new URLSearchParams({ v }).toString().slice(2));
    forms.add(encodeURI(v));
    for (const [prefix, part] of [
      ['?', 'search'],
      ['/', 'pathname'],
      ['#', 'hash'],
    ] as const) {
      try {
        forms.add(new URL(`http://x/${prefix === '/' ? '' : prefix}${v}`)[part].slice(1));
      } catch {}
    }
  }
  return [...forms]
    .filter((f) => f.length >= MIN_SCRUBBED_LENGTH)
    .sort((a, b) => b.length - a.length);
}

function allForms(secrets: Iterable<string>): string[] {
  const all = new Set<string>();
  for (const s of secrets) for (const f of secretForms(s)) all.add(f);
  return [...all].sort((a, b) => b.length - a.length);
}

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function tryDecode(s: string): string[] {
  const out: string[] = [];
  for (const v of [s, s.replace(/\+/g, ' ')]) {
    try {
      out.push(decodeURIComponent(v));
    } catch {}
  }
  return out;
}

export function scrubString(text: string, secrets: Iterable<string>): string {
  const list = [...secrets];
  let out = text;
  for (const f of allForms(list)) {
    if (out.includes(f)) out = out.split(f).join(REDACTED);
    if (/%[0-9A-F]{2}/.test(f)) out = out.replace(new RegExp(escapeRe(f), 'gi'), REDACTED);
  }
  if (/[%+]/.test(out)) {
    const needles = list
      .flatMap((v) => [v, v.replace(/\s+/g, ' ').trim()])
      .filter((v) => v.length >= MIN_SCRUBBED_LENGTH);
    out = out.replace(/[^\s"']*[%+][^\s"']*/g, (tok) =>
      tryDecode(tok).some((d) => needles.some((n) => d.includes(n))) ? REDACTED : tok,
    );
  }
  return out;
}

export function truncateScrubbed(text: string, max: number, secrets: Iterable<string>): string {
  if (text.length <= max) return text;
  let cut = text.slice(0, max);
  let drop = 0;
  for (const f of allForms(secrets)) {
    for (let k = Math.min(f.length - 1, cut.length); k > drop; k--) {
      if (cut.endsWith(f.slice(0, k))) {
        drop = k;
        break;
      }
    }
  }
  cut = cut.slice(0, cut.length - drop);
  return cut;
}

export function scrubDeep<T>(value: T, secrets: readonly string[]): T {
  if (secrets.length === 0) return value;
  const walk = (v: unknown): unknown => {
    if (typeof v === 'string') return scrubString(v, secrets);
    if (Array.isArray(v)) return v.map(walk);
    if (v !== null && typeof v === 'object') {
      const out: Record<string, unknown> = {};
      for (const [k, x] of Object.entries(v)) out[scrubString(k, secrets)] = walk(x);
      return out;
    }
    return v;
  };
  return walk(value) as T;
}
