import { describe, expect, it } from 'vitest';
import { parseExport, planImport, runImport } from '../src/password-import.ts';

const PW_EXAMPLE = 'chrome-pw-Example1!';
const PW_GITHUB = 'gh-pw-one-1234';
const CSV = [
  'name,url,username,password,note',
  `example.com,https://example.com/login,alice,${PW_EXAMPLE},`,
  `github.com,https://github.com/login,dave,${PW_GITHUB},`,
].join('\n');

const plan = () => planImport(parseExport(CSV), { sites: [], all: true }, []);

describe('password import: a store failure shows a fixed note, never the error text', () => {
  it('prints no password and none of the error message, however the store fails', async () => {
    const out: string[] = [];
    const result = await runImport(
      plan(),
      async (login) => {
        throw new Error(`signer said no to ${login.password} for ${login.username}`);
      },
      (text) => out.push(text),
      '/tmp/export.csv',
    );
    expect(result).toEqual({ stored: 0, failed: 2 });
    const text = out.join('\n');
    expect(text.match(/the signer refused it, not stored/g)).toHaveLength(2);
    for (const leaked of [PW_EXAMPLE, PW_GITHUB, 'signer said', 'no to']) {
      expect(text).not.toContain(leaked);
    }
  });

  it('control: a successful store lists the new ids', async () => {
    const out: string[] = [];
    const result = await runImport(
      plan(),
      async (login) => ({ id: `id-${login.domain}`, domain: login.domain }),
      (text) => out.push(text),
      '/tmp/export.csv',
    );
    expect(result).toEqual({ stored: 2, failed: 0 });
    expect(out.join('\n')).toContain('id-example.com');
  });
});
