export interface SourceComment {
  start: number;
  end: number;
  text: string;
}

const DIRECTIVE =
  /biome-ignore|@ts-(?:ignore|expect-error|nocheck|check)\b|eslint-|@vitest-environment|@license|@preserve|^\/\*!|^\/\/\/\s*<reference|sourceMappingURL/;

const REGEX_AFTER_WORD = new Set([
  'return',
  'typeof',
  'instanceof',
  'in',
  'of',
  'new',
  'delete',
  'void',
  'throw',
  'case',
  'do',
  'else',
  'yield',
  'await',
]);

const isWordStart = (c: string) => /[A-Za-z_$]/.test(c);
const isWordChar = (c: string) => /[A-Za-z0-9_$]/.test(c);
const isDigit = (c: string) => /[0-9]/.test(c);
const isSpace = (c: string) => c === ' ' || c === '\t' || c === '\n' || c === '\r';

export function scanComments(src: string): SourceComment[] {
  const out: SourceComment[] = [];
  const stack: ('brace' | 'template')[] = [];
  const n = src.length;
  let i = 0;
  let regexOk = true;

  const template = () => {
    while (i < n) {
      const c = src[i];
      if (c === '\\') i += 2;
      else if (c === '`') {
        i++;
        return;
      } else if (c === '$' && src[i + 1] === '{') {
        i += 2;
        stack.push('template');
        return;
      } else i++;
    }
  };

  const quoted = (q: string) => {
    i++;
    while (i < n && src[i] !== q) i += src[i] === '\\' ? 2 : 1;
    i++;
  };

  const regex = (): boolean => {
    let j = i + 1;
    let inClass = false;
    while (j < n) {
      const c = src[j];
      if (c === '\n') return false;
      if (c === '\\') j += 2;
      else if (c === '[') {
        inClass = true;
        j++;
      } else if (c === ']') {
        inClass = false;
        j++;
      } else if (c === '/' && !inClass) {
        j++;
        while (j < n && isWordChar(src[j] as string)) j++;
        i = j;
        return true;
      } else j++;
    }
    return false;
  };

  if (src.startsWith('#!')) while (i < n && src[i] !== '\n') i++;

  while (i < n) {
    const c = src[i] as string;
    const d = src[i + 1];
    if (c === '/' && d === '/') {
      let e = src.indexOf('\n', i);
      if (e === -1) e = n;
      out.push({ start: i, end: e, text: src.slice(i, e) });
      i = e;
    } else if (c === '/' && d === '*') {
      let e = src.indexOf('*/', i + 2);
      e = e === -1 ? n : e + 2;
      out.push({ start: i, end: e, text: src.slice(i, e) });
      i = e;
    } else if (c === '"' || c === "'") {
      quoted(c);
      regexOk = false;
    } else if (c === '`') {
      i++;
      template();
      regexOk = false;
    } else if (c === '/') {
      if (regexOk && regex()) regexOk = false;
      else {
        i++;
        regexOk = true;
      }
    } else if (c === '{') {
      stack.push('brace');
      i++;
      regexOk = true;
    } else if (c === '}') {
      const frame = stack.pop();
      i++;
      if (frame === 'template') {
        template();
        regexOk = false;
      } else regexOk = true;
    } else if (c === ')' || c === ']') {
      i++;
      regexOk = false;
    } else if (isWordStart(c)) {
      const s = i;
      while (i < n && isWordChar(src[i] as string)) i++;
      let p = s - 1;
      while (p >= 0 && isSpace(src[p] as string)) p--;
      const member = src[p] === '.' && src[p - 1] !== '.';
      regexOk = !member && REGEX_AFTER_WORD.has(src.slice(s, i));
    } else if (isDigit(c)) {
      while (i < n && (isWordChar(src[i] as string) || src[i] === '.')) i++;
      regexOk = false;
    } else if (isSpace(c)) {
      i++;
    } else {
      i++;
      regexOk = true;
    }
  }
  return out;
}

export function isDirective(c: SourceComment): boolean {
  return DIRECTIVE.test(c.text);
}

export function stripComments(src: string, comments: readonly SourceComment[]): string {
  let out = '';
  let pos = 0;
  for (const c of comments) {
    let s = c.start;
    let e = c.end;
    const lineStart = src.lastIndexOf('\n', s - 1) + 1;
    let lineEnd = src.indexOf('\n', e);
    if (lineEnd === -1) lineEnd = src.length;
    const before = src.slice(lineStart, s);
    const after = src.slice(e, lineEnd);
    if (before.trim() === '' && after.trim() === '') {
      s = lineStart;
      e = Math.min(lineEnd + 1, src.length);
    } else if (after.trim() === '') {
      while (s > pos && (src[s - 1] === ' ' || src[s - 1] === '\t')) s--;
    }
    out += src.slice(pos, s);
    pos = Math.max(pos, e);
  }
  return out + src.slice(pos);
}
