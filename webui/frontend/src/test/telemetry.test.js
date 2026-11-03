import { describe, expect, it } from 'vitest';

import { FEED, HISTORY, initialState, ratesOf, reduce } from '../lib/telemetry.js';

const snap = (over = {}) => ({
  type: 'snapshot', ts_ms: 1000, interval_ms: 500,
  io: { read_ops: 10, write_ops: 4, read_bytes: 4096, write_bytes: 2048, read_lat_us: 120 },
  ...over,
});

describe('ratesOf', () => {
  it('scales per-interval counters to per-second rates', () => {
    const r = ratesOf(snap());
    expect(r.readIops).toBe(20);
    expect(r.writeIops).toBe(8);
    expect(r.readBps).toBe(8192);
    expect(r.writeBps).toBe(4096);
    expect(r.readLat).toBe(120);
    expect(r.writeLat).toBe(0);
  });

  it('tolerates a missing io block and a zero interval', () => {
    const r = ratesOf({ interval_ms: 0 });
    expect(r.readIops).toBe(0);
    expect(Number.isFinite(r.readBps)).toBe(true);
  });
});

describe('reduce', () => {
  it('tracks both connections separately', () => {
    let s = reduce(initialState, { type: 'socket', connected: true });
    s = reduce(s, { type: 'status', connected: false, error: 'no socket' });
    expect(s.connected).toBe(true);
    expect(s.daemon).toEqual({ connected: false, error: 'no socket' });
  });

  it('keeps a bounded history', () => {
    let s = initialState;
    for (let i = 0; i < HISTORY + 5; i += 1) s = reduce(s, snap({ ts_ms: i }));
    expect(s.history).toHaveLength(HISTORY);
    expect(s.history.at(-1).t).toBe(HISTORY + 4);
    expect(s.rates.readIops).toBe(20);
  });

  it('drops events it has already seen', () => {
    const ev = (seq) => ({ seq, kind: 'alert', msg: `e${seq}` });
    let s = reduce(initialState, { type: 'events', events: [ev(1), ev(2)] });
    s = reduce(s, snap({ events: [ev(2), ev(3)] }));
    s = reduce(s, { type: 'events', events: [ev(1), ev(3)] });
    expect(s.events.map((e) => e.seq)).toEqual([1, 2, 3]);
  });

  it('keeps events from a restarted daemon, and drops its replays', () => {
    const ev = (seq, ts) => ({ seq, ts_ms: ts });
    let s = reduce(initialState, { type: 'events', events: [1, 2, 3, 4, 5].map((n) => ev(n, 1000 + n)) });
    s = reduce(s, { type: 'events', events: [ev(1, 5000), ev(2, 5001)] }); // remounted
    s = reduce(s, { type: 'events', events: [ev(1, 5000), ev(2, 5001), ev(3, 5002)] }); // replay
    expect(s.events.map((e) => e.ts_ms)).toEqual([1001, 1002, 1003, 1004, 1005, 5000, 5001, 5002]);
  });

  it('caps the feed', () => {
    const events = Array.from({ length: FEED + 10 }, (_, i) => ({ seq: i + 1 }));
    const s = reduce(initialState, { type: 'events', events });
    expect(s.events).toHaveLength(FEED);
    expect(s.events[0].seq).toBe(11);
  });

  it('replaces the tree and ignores unknown messages', () => {
    let s = reduce(initialState, { type: 'tree', entries: [{ path: '/a' }], truncated: true });
    expect(s.tree).toEqual([{ path: '/a' }]);
    expect(s.treeTruncated).toBe(true);
    expect(reduce(s, { type: 'nonsense' })).toBe(s);
  });
});
