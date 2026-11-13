interface Letter<T> {
  value: T;
  at: number;
  read: boolean;
}

export class Mailbox<T> {
  private readonly windowMs: number;
  private readonly capacity: number;
  private readonly letters: Letter<T>[] = [];

  constructor(o: { windowMs: number; capacity?: number }) {
    this.windowMs = o.windowMs;
    this.capacity = Math.max(1, o.capacity ?? 1);
  }

  put(value: T, now: number): void {
    this.letters.push({ value, at: now, read: false });
    if (this.letters.length > this.capacity) {
      this.letters.splice(0, this.letters.length - this.capacity);
    }
  }

  private find(now: number, match: (v: T) => boolean): Letter<T> | undefined {
    for (let i = this.letters.length - 1; i >= 0; i--) {
      const l = this.letters[i] as Letter<T>;
      if (!l.read && now - l.at <= this.windowMs && match(l.value)) return l;
    }
    return undefined;
  }

  has(now: number, match: (v: T) => boolean = () => true): boolean {
    return this.find(now, match) !== undefined;
  }

  take(now: number, match: (v: T) => boolean = () => true): T | undefined {
    const l = this.find(now, match);
    if (!l) return undefined;
    l.read = true;
    return l.value;
  }
}
