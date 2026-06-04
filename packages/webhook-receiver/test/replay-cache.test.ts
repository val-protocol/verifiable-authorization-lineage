import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { InMemoryReplayCache } from '../src/replay-cache';

describe('InMemoryReplayCache', () => {
  it('accepts fresh deliveries', () => {
    const cache = new InMemoryReplayCache(300, 100, () => 1000);
    assert.equal(cache.checkAndRecord(1000, 'body1'), false);
    assert.equal(cache.checkAndRecord(1000, 'body2'), false);
  });

  it('rejects exact replays (same timestamp + same body)', () => {
    const cache = new InMemoryReplayCache(300, 100, () => 1000);
    cache.record(1000, 'body1');
    assert.equal(cache.checkAndRecord(1000, 'body1'), true);
  });

  it('does NOT reject different bodies at the same timestamp', () => {
    const cache = new InMemoryReplayCache(300, 100, () => 1000);
    cache.record(1000, 'body1');
    assert.equal(cache.checkAndRecord(1000, 'body2'), false);
  });

  it('does NOT reject same body at different timestamp', () => {
    const cache = new InMemoryReplayCache(300, 100, () => 1000);
    cache.record(1000, 'body1');
    assert.equal(cache.checkAndRecord(1001, 'body1'), false);
  });

  it('prunes entries older than TTL', () => {
    let now = 1000;
    const cache = new InMemoryReplayCache(300, 100, () => now);
    cache.record(1000, 'body1');
    assert.equal(cache.size(), 1);
    now = 1000 + 301; // walk past the TTL
    cache.checkAndRecord(now, 'body2'); // triggers prune
    assert.equal(cache.size(), 1); // body1 evicted, body2 present
  });
});
