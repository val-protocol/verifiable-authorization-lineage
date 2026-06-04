/**
 * In-memory replay-protection cache.
 *
 * Cache key = sha256(timestamp + '.' + body) → drops duplicates of the EXACT
 * same delivery, including the EXACT same timestamp (replay attempts).
 *
 * For single-instance receivers this is sufficient. Multi-instance receivers
 * SHOULD swap in a shared store (Redis SETNX with TTL, etcd, etc.) so a
 * replay reaching a different replica is still rejected. The interface
 * `ReplayCache` is the seam — implement the same shape backed by Redis.
 *
 * The cache prunes itself when more than `maxEntries` items accumulate (LRU
 * by insertion order, sufficient because the tolerance window bounds the
 * useful lifetime of any cached entry to 5 minutes).
 */
import { createHash } from 'node:crypto';

export interface ReplayCache {
  /** Returns true if this delivery has already been observed. */
  hasSeen(timestamp: number, body: string): boolean;
  /** Records the delivery; subsequent hasSeen() returns true within ttlSeconds. */
  record(timestamp: number, body: string): void;
  /** Convenience: hasSeen → record. Returns true iff this is a replay. */
  checkAndRecord(timestamp: number, body: string): boolean;
}

export class InMemoryReplayCache implements ReplayCache {
  private readonly entries = new Map<string, number>();
  constructor(
    private readonly ttlSeconds = 300,
    private readonly maxEntries = 10_000,
    private readonly now: () => number = () => Math.floor(Date.now() / 1000),
  ) {}

  private key(timestamp: number, body: string): string {
    return createHash('sha256').update(`${timestamp}.${body}`).digest('hex');
  }

  private prune(): void {
    const cutoff = this.now() - this.ttlSeconds;
    for (const [k, ts] of this.entries) {
      if (ts < cutoff) this.entries.delete(k);
      else break; // Map iterates in insertion order; safe to break once a fresh entry is hit
    }
    // Hard cap as a defense against pathological pre-prune growth (e.g. clock skew).
    while (this.entries.size > this.maxEntries) {
      const oldest = this.entries.keys().next().value;
      if (oldest === undefined) break;
      this.entries.delete(oldest);
    }
  }

  hasSeen(timestamp: number, body: string): boolean {
    this.prune();
    return this.entries.has(this.key(timestamp, body));
  }

  record(timestamp: number, body: string): void {
    this.prune();
    this.entries.set(this.key(timestamp, body), this.now());
  }

  checkAndRecord(timestamp: number, body: string): boolean {
    this.prune();
    const k = this.key(timestamp, body);
    if (this.entries.has(k)) return true;
    this.entries.set(k, this.now());
    return false;
  }

  /** Test-only: snapshot the cache size. */
  size(): number {
    return this.entries.size;
  }
}
