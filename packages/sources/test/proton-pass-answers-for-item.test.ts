import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { ProtonPassSource, SourceError } from '../src/index.ts';
import { type FakeVaultFile, fakePassCli } from './fake.ts';

const ANSWERS_AS = fileURLToPath(new URL('./fake-pass-cli-answers-as.ts', import.meta.url));
const SAME_USER = { mode: 'same-user' } as const;
const PW_ASKED = 'asked-for-Secr3t-password';
const PW_AGENT_OTHER = 'same-vault-other-Secr3t';
const PW_PERSONAL = 'other-vault-Secr3t';

function vault(): FakeVaultFile {
  return {
    loggedIn: true,
    vaults: [
      {
        name: 'Agent',
        share_id: 'SHARE_agent',
        vault_id: 'V1',
        items: [
          { id: 'asked', title: 'Asked', login: { password: PW_ASKED, urls: ['asked.test'] } },
          {
            id: 'other',
            title: 'Other',
            login: { password: PW_AGENT_OTHER, urls: ['other.test'] },
          },
          { id: 'dup', title: 'Dup', login: { password: PW_AGENT_OTHER, urls: ['dup.test'] } },
        ],
      },
      {
        name: 'Personal',
        share_id: 'SHARE_personal',
        vault_id: 'V2',
        items: [
          { id: 'elsewhere', title: 'P', login: { password: PW_PERSONAL, urls: ['p.test'] } },
          { id: 'dup', title: 'Dup', login: { password: PW_PERSONAL, urls: ['dup.test'] } },
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

function source(answerAs?: { shareId?: string; itemId?: string }): ProtonPassSource {
  const f = fakePassCli(vault());
  return new ProtonPassSource({
    bin: ANSWERS_AS,
    trust: SAME_USER,
    env: { ...f.env, ...(answerAs ? { KEYFLAP_FAKE_ANSWER_AS: JSON.stringify(answerAs) } : {}) },
  });
}

describe('Proton Pass source: pass-cli must answer for the item that was asked about', () => {
  it('returns the item when pass-cli answers for it', async () => {
    const secret = await source().fetch('proton-pass:SHARE_agent:asked', 'r');
    expect(secret.password).toBe(PW_ASKED);
  });

  it('refuses a different item of the same vault', async () => {
    const src = source({ itemId: 'other' });
    expect(await outcome(src.fetch('proton-pass:SHARE_agent:asked', 'r'))).toBe(
      'source_bad_output',
    );
  });

  it('refuses an item of a different vault', async () => {
    const src = source({ shareId: 'SHARE_personal', itemId: 'elsewhere' });
    expect(await outcome(src.fetch('proton-pass:SHARE_agent:asked', 'r'))).toBe(
      'source_bad_output',
    );
  });

  it('refuses the same item id answered from a different vault', async () => {
    const src = source({ shareId: 'SHARE_personal' });
    expect(await outcome(src.fetch('proton-pass:SHARE_agent:dup', 'r'))).toBe('source_bad_output');
  });
});
