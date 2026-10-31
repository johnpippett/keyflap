import { type AddressPhase, type AddressState, addressPhase } from '@aab/signer/approver-address';

export type AddressRefusal = 'approver_address_changed' | 'approver_address_unverified';

export const ADDRESS_REFUSAL: Readonly<Record<'latched' | 'paused', AddressRefusal>> = {
  latched: 'approver_address_changed',
  paused: 'approver_address_unverified',
};

const REFUSAL_BY_PHASE: Readonly<Record<AddressPhase, AddressRefusal | null>> = {
  unwatched: null,
  ok: null,
  holding: ADDRESS_REFUSAL.paused,
  paused: ADDRESS_REFUSAL.paused,
  latched: ADDRESS_REFUSAL.latched,
};

export function addressRefusal(state: AddressState, now: number): AddressRefusal | null {
  return REFUSAL_BY_PHASE[addressPhase(state, now)];
}

export interface AddressSyncSigner {
  approverAddress(o: { pending: boolean }): Promise<{ state: AddressState }>;
}

export interface AddressSyncPhone {
  readonly origin: string;
  busy(): boolean;
  setAddressState(state: AddressState): void;
  warnAddressChanged(): Promise<void>;
  cancelAll(reason: AddressRefusal): void;
  signOutAll(): void;
}

export interface ApproverAddressSyncOptions {
  signer: AddressSyncSigner;
  phone: AddressSyncPhone;
  audit: (event: string, fields: Record<string, unknown>) => void;
  pollMs?: { idle: number; fast: number };
  now?: () => number;
}

const DEFAULT_POLL_MS = { idle: 1_000, fast: 250 };

export function sameAddressState(a: AddressState, b: AddressState): boolean {
  if (a.kind !== b.kind) return false;
  if (a.kind === 'latched' && b.kind === 'latched') return a.seen === b.seen;
  if (a.kind === 'paused' && b.kind === 'paused') return a.detail === b.detail;
  return true;
}

export class ApproverAddressSync {
  private readonly signer: AddressSyncSigner;
  private readonly phone: AddressSyncPhone;
  private readonly audit: ApproverAddressSyncOptions['audit'];
  private readonly poll: { idle: number; fast: number };
  private readonly now: () => number;
  private last: AddressState = { kind: 'ok', checkedAt: 0 };
  private lastPhase: AddressPhase = 'ok';
  private timer: ReturnType<typeof setTimeout> | null = null;
  private polls: Promise<void> = Promise.resolve();
  private stopped = false;

  constructor(opts: ApproverAddressSyncOptions) {
    this.signer = opts.signer;
    this.phone = opts.phone;
    this.audit = opts.audit;
    this.poll = opts.pollMs ?? DEFAULT_POLL_MS;
    this.now = opts.now ?? Date.now;
  }

  state(): AddressState {
    return this.last;
  }

  async start(): Promise<AddressState> {
    await this.pollInOrder();
    this.schedule();
    return this.last;
  }

  async refresh(): Promise<AddressState> {
    await this.pollInOrder();
    return this.last;
  }

  stop(): void {
    this.stopped = true;
    if (this.timer !== null) clearTimeout(this.timer);
    this.timer = null;
  }

  private schedule(): void {
    if (this.stopped || this.timer !== null || this.last.kind === 'unwatched') return;
    const delay = this.phone.busy() ? this.poll.fast : this.poll.idle;
    this.timer = setTimeout(() => {
      this.timer = null;
      this.pollInOrder().finally(() => this.schedule());
    }, delay);
    this.timer.unref();
  }

  private pollInOrder(): Promise<void> {
    this.polls = this.polls.then(() => this.pollOnce());
    return this.polls;
  }

  private async pollOnce(): Promise<void> {
    let state: AddressState;
    try {
      ({ state } = await this.signer.approverAddress({ pending: this.phone.busy() }));
    } catch {
      return;
    }
    if (this.stopped) return;
    this.phone.setAddressState(state);
    const prev = this.last;
    const prevPhase = this.lastPhase;
    const phase = addressPhase(state, this.now());
    this.last = state;
    this.lastPhase = phase;
    const changed = !sameAddressState(prev, state);
    if (!changed && phase === prevPhase) return;
    const origin = this.phone.origin;
    switch (state.kind) {
      case 'latched':
        await this.phone.warnAddressChanged();
        this.audit('approver.address_tripped', { origin, seen: state.seen });
        this.phone.cancelAll(ADDRESS_REFUSAL.latched);
        this.phone.signOutAll();
        return;
      case 'paused':
        if (changed) this.audit('approver.address_unreadable', { origin, detail: state.detail });
        if (phase === 'paused') this.phone.cancelAll(ADDRESS_REFUSAL.paused);
        return;
      case 'ok':
        if (prev.kind === 'paused') this.audit('approver.address_readable', { origin });
        if (prev.kind === 'latched') this.audit('approver.address_cleared', { origin });
        return;
      case 'unwatched':
        return;
    }
  }
}
