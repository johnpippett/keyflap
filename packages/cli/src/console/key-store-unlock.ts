import type { Unlock } from '../passphrase.ts';
import type { PassphraseAsk } from '../setup/run.ts';

const ATTEMPTS = 3;

export class KeyStoreUnlock {
  private value: string | null = null;
  private readonly source: PassphraseAsk;
  private readonly isNew: () => boolean;

  constructor(source: PassphraseAsk, isNew: () => boolean) {
    this.source = source;
    this.isNew = isNew;
  }

  readonly ask: PassphraseAsk = async (o) => {
    if (o.retry) this.value = null;
    this.value ??= await this.source(o);
    return this.value;
  };

  async with<T>(use: (unlock: Unlock) => Promise<T>): Promise<T> {
    for (let attempt = 1; ; attempt++) {
      try {
        return await use(() => this.ask({ isNew: this.isNew(), retry: attempt > 1 }));
      } catch (err) {
        if (attempt < ATTEMPTS && /wrong passphrase/.test((err as Error).message)) continue;
        throw err;
      }
    }
  }
}
