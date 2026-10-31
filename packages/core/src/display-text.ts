const UNSAFE_SOURCE =
  '[\\u0000-\\u001f\\u007f-\\u009f\\u061c\\u200e\\u200f\\u2028-\\u202e\\u2066-\\u2069]';
const UNSAFE = new RegExp(UNSAFE_SOURCE);
const UNSAFE_ALL = new RegExp(UNSAFE_SOURCE, 'g');

export function hasUnsafeText(s: string): boolean {
  return UNSAFE.test(s);
}

export function printable(s: string): string {
  return s.replace(UNSAFE_ALL, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
}
