import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { OnePasswordSource, SourceError } from '../src/index.ts';
import { type FakeOpAccount, fakeOp } from './fake.ts';

const ANSWERS_AS = fileURLToPath(new URL('./fake-op-answers-as.ts', import.meta.url));
const TOKEN = 'ops_fakeServiceAccountToken_DO_NOT_LEAK';
const V_AGENT = 'agentvault0000000000000000';
const V_PERSONAL = 'personalvault0000000000000';
const I_ASKED = 'itemasked00000000000000000';
const I_OTHER = 'itemother00000000000000000';
const I_ELSEWHERE = 'itemelsewhere0000000000000';
const I_DUP = 'itemdup0000000000000000000';
const PW_ASKED = 'asked-for-Secr3t-password';
const PW_OTHER = 'same-vault-other-Secr3t';
const PW_PERSONAL = 'other-vault-Secr3t';

function account(): FakeOpAccount {
  return {
    token: TOKEN,
    vaults: [
      {
        id: V_AGENT,
        name: 'Agent',
        items: [
          { id: I_ASKED, title: 'Asked', password: PW_ASKED, urls: ['asked.test'] },
          { id: I_OTHER, title: 'Other', password: PW_OTHER, urls: ['other.test'] },
          { id: I_DUP, title: 'Dup', password: PW_OTHER, urls: ['dup.test'] },
        ],
      },
      {
        id: V_PERSONAL,
        name: 'Personal',
        items: [
          { id: I_ELSEWHERE, title: 'P', password: PW_PERSONAL, urls: ['p.test'] },
          { id: I_DUP, title: 'Dup', password: PW_PERSONAL, urls: ['dup.test'] },
        ],
      },
    ],
  };
}

async function outcome(p: Promise<unknown>): Promise<string> {
  try {
    await p;
    return 'resolved';
  } catch (err) {
    return err instanceof SourceError ? err.reason : `other: ${(err as Error).message}`;
  }
}

function source(answerAs?: { vaultId?: string; itemId?: string }): OnePasswordSource {
  const f = fakeOp(account());
  return new OnePasswordSource({
    bin: ANSWERS_AS,
    trust: { mode: 'same-user' },
    env: { ...f.env, ...(answerAs ? { KEYFLAP_FAKE_ANSWER_AS: JSON.stringify(answerAs) } : {}) },
  });
}

describe('1Password source: op must answer for the item that was asked about', () => {
  it('returns the item when op answers for it', async () => {
    const secret = await source().fetch(`1password:${V_AGENT}:${I_ASKED}`, 'r');
    expect(secret.password).toBe(PW_ASKED);
  });

  it('refuses a different item of the same vault', async () => {
    const src = source({ itemId: I_OTHER });
    expect(await outcome(src.fetch(`1password:${V_AGENT}:${I_ASKED}`, 'r'))).toBe(
      'source_bad_output',
    );
  });

  it('refuses an item of a different vault', async () => {
    const src = source({ vaultId: V_PERSONAL, itemId: I_ELSEWHERE });
    expect(await outcome(src.fetch(`1password:${V_AGENT}:${I_ASKED}`, 'r'))).toBe(
      'source_bad_output',
    );
  });

  it('refuses the same item id answered from a different vault', async () => {
    const src = source({ vaultId: V_PERSONAL });
    expect(await outcome(src.fetch(`1password:${V_AGENT}:${I_DUP}`, 'r'))).toBe(
      'source_bad_output',
    );
  });
});
