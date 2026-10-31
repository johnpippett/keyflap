export function toB64url(buf: Uint8Array): string {
  return Buffer.from(buf.buffer, buf.byteOffset, buf.byteLength).toString('base64url');
}

export function fromB64url(s: string): Buffer {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s)) {
    throw new Error('invalid base64url');
  }
  return Buffer.from(s, 'base64url');
}
