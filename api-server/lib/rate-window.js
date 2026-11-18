'use strict';

/**
 * Minimal in-memory sliding-window counter, keyed by an arbitrary string
 * (email, IP, user id, ...). Shared by several families: login lockout
 * (CWE-307), GraphQL batched-operation counting (CWE-799), and the
 * "Denial of Wallet" SMS budget simulation (CWE-770/400).
 */
class SlidingWindowCounter {
  constructor(windowMs) {
    this.windowMs = windowMs;
    this.buckets = new Map();
  }

  _prune(key, now) {
    const rec = this.buckets.get(key);
    if (rec && now - rec.start > this.windowMs) this.buckets.delete(key);
  }

  increment(key, amount = 1) {
    const now = Date.now();
    this._prune(key, now);
    let rec = this.buckets.get(key);
    if (!rec) {
      rec = { start: now, count: 0 };
      this.buckets.set(key, rec);
    }
    rec.count += amount;
    return rec.count;
  }

  get(key) {
    const now = Date.now();
    this._prune(key, now);
    return this.buckets.get(key)?.count ?? 0;
  }

  reset(key) {
    this.buckets.delete(key);
  }
}

module.exports = { SlidingWindowCounter };
