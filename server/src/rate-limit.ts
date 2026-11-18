/** In-memory token buckets — enough for a single-process deployment. */

interface Bucket {
  tokens: number;
  updatedAt: number;
}

export class RateLimiter {
  private readonly buckets = new Map<string, Bucket>();
  private readonly capacity: number;
  private readonly refillPerMs: number;

  /** `capacity` requests may burst; the bucket refills at `perSecond` tokens/s. */
  constructor(capacity: number, perSecond: number) {
    this.capacity = capacity;
    this.refillPerMs = perSecond / 1000;
  }

  take(key: string, now = Date.now()): boolean {
    const bucket = this.buckets.get(key) ?? { tokens: this.capacity, updatedAt: now };
    bucket.tokens = Math.min(this.capacity, bucket.tokens + (now - bucket.updatedAt) * this.refillPerMs);
    bucket.updatedAt = now;
    const allowed = bucket.tokens >= 1;
    if (allowed) bucket.tokens -= 1;
    this.buckets.set(key, bucket);
    if (this.buckets.size > 50_000) this.sweep(now);
    return allowed;
  }

  private sweep(now: number): void {
    for (const [key, bucket] of this.buckets) {
      if (bucket.tokens + (now - bucket.updatedAt) * this.refillPerMs >= this.capacity) this.buckets.delete(key);
    }
  }
}
