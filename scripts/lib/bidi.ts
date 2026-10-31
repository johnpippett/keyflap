const RANGES: readonly (readonly [number, number])[] = [
  [0x061c, 0x061c],
  [0x200e, 0x200f],
  [0x2028, 0x2029],
  [0x202a, 0x202e],
  [0x2066, 0x2069],
];

export interface BidiHit {
  line: number;
  codePoint: number;
}

export function findBidi(src: string): BidiHit[] {
  const hits: BidiHit[] = [];
  let line = 1;
  for (const ch of src) {
    const codePoint = ch.codePointAt(0) ?? 0;
    if (codePoint === 0x0a) line++;
    else if (RANGES.some(([lo, hi]) => codePoint >= lo && codePoint <= hi)) {
      hits.push({ line, codePoint });
    }
  }
  return hits;
}

export function codePointLabel(codePoint: number): string {
  return `U+${codePoint.toString(16).toUpperCase().padStart(4, '0')}`;
}
