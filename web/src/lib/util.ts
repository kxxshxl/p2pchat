/** Serialises async work per key (one queue per conversation keeps ratchet updates ordered). */
export class KeyedMutex {
  private readonly tails = new Map<string, Promise<unknown>>();

  run<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const previous = this.tails.get(key) ?? Promise.resolve();
    const result = previous.then(fn, fn);
    const tail = result.catch(() => undefined);
    this.tails.set(key, tail);
    void tail.then(() => {
      if (this.tails.get(key) === tail) this.tails.delete(key);
    });
    return result;
  }
}

/** Tiny observable store for useSyncExternalStore. */
export class Observable<S> {
  private current: S;
  private readonly listeners = new Set<() => void>();

  constructor(initial: S) {
    this.current = initial;
  }

  get state(): S {
    return this.current;
  }

  update(fn: (state: S) => S): void {
    this.current = fn(this.current);
    for (const listener of this.listeners) listener();
  }

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };

  getSnapshot = (): S => this.current;
}

export function uuid(): string {
  return crypto.randomUUID();
}

export function downloadText(filename: string, text: string): void {
  const url = URL.createObjectURL(new Blob([text], { type: "application/json" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
