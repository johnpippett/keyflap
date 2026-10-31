import { describe, expect, it } from 'vitest';
import { protonPassEnv } from '../src/daemon.ts';

const TOKEN = 'pst_not-a-real-token::not-a-real-key';

describe('protonPassEnv: what the signer hands to pass-cli', () => {
  const env = protonPassEnv({
    HOME: '/home/u',
    PATH: '/usr/bin',
    PROTON_PASS_PERSONAL_ACCESS_TOKEN: TOKEN,
    PROTON_PASS_SESSION_DIR: '/home/u/.keyflap/pass-session',
    PROTON_PASS_KEY_PROVIDER: 'fs',
    KEYFLAP_PASSPHRASE: 'broker-passphrase',
    OP_SERVICE_ACCOUNT_TOKEN: 'ops_other-vault-token',
  });

  it('never passes the personal access token', () => {
    expect(Object.keys(env).filter((k) => k.includes('ACCESS_TOKEN'))).toEqual([]);
    expect(Object.values(env).filter((v) => v.includes(TOKEN))).toEqual([]);
  });

  it('keeps the session dir and key provider pass-cli needs to find its login', () => {
    expect(env).toMatchObject({
      PROTON_PASS_SESSION_DIR: '/home/u/.keyflap/pass-session',
      PROTON_PASS_KEY_PROVIDER: 'fs',
    });
  });

  it('passes no broker or other-vault secret', () => {
    expect(env).not.toHaveProperty('KEYFLAP_PASSPHRASE');
    expect(env).not.toHaveProperty('OP_SERVICE_ACCOUNT_TOKEN');
  });
});
