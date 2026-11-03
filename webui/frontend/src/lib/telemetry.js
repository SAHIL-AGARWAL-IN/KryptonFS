// Folds the daemon's telemetry messages (forwarded by the console server)
// into what the UI draws. Mirrors kryptonfs_dash.telemetry.TelemetryState:
// per-second rates, a bounded history, de-duplicated events.

import { useEffect, useReducer } from 'react';

export const HISTORY = 120;
export const FEED = 300;

export const initialState = {
  connected: false, // browser <-> console
  daemon: { connected: false, error: '' }, // console <-> kryptonfs
  snapshot: null,
  rates: null,
  history: [], // [{t, readIops, writeIops, readBps, writeBps, readLat, writeLat}]
  tree: [],
  treeTruncated: false,
  events: [],
  seenSeq: 0,
  seenTs: 0,
};

export function ratesOf(snap) {
  const io = snap.io ?? {};
  const perS = 1000 / Math.max(snap.interval_ms ?? 1000, 1);
  return {
    readIops: (io.read_ops ?? 0) * perS,
    writeIops: (io.write_ops ?? 0) * perS,
    readBps: (io.read_bytes ?? 0) * perS,
    writeBps: (io.write_bytes ?? 0) * perS,
    readLat: io.read_lat_us ?? 0,
    writeLat: io.write_lat_us ?? 0,
    readLatMax: io.read_lat_max_us ?? 0,
    writeLatMax: io.write_lat_max_us ?? 0,
    errors: io.errors ?? 0,
  };
}

// The backlog on (re)connect repeats events already taken, and sequence
// numbers restart with the daemon (a remount), so an event is new when its
// number or its time is past the newest one taken.
function takeEvents(state, events) {
  let { seenSeq, seenTs } = state;
  const fresh = [];
  for (const e of events ?? []) {
    const seq = e.seq ?? 0;
    const ts = e.ts_ms ?? 0;
    if (seq > seenSeq || ts > seenTs) {
      fresh.push(e);
      seenSeq = seq;
      seenTs = ts;
    }
  }
  if (!fresh.length) return state;
  return { ...state, seenSeq, seenTs, events: [...state.events, ...fresh].slice(-FEED) };
}

export function reduce(state, msg) {
  switch (msg.type) {
    case 'socket':
      return { ...state, connected: msg.connected };
    case 'status':
      return { ...state, daemon: { connected: !!msg.connected, error: msg.error ?? '' } };
    case 'snapshot': {
      const rates = ratesOf(msg);
      const point = { t: msg.ts_ms ?? Date.now(), ...rates };
      const next = { ...state, snapshot: msg, rates,
        history: [...state.history, point].slice(-HISTORY) };
      return takeEvents(next, msg.events);
    }
    case 'events':
      return takeEvents(state, msg.events);
    case 'tree':
      return { ...state, tree: msg.entries ?? [], treeTruncated: !!msg.truncated };
    default:
      return state;
  }
}

// One WebSocket per page; reconnects with backoff and resyncs from the
// server's hello messages, so nothing needs to be persisted here.
export function useTelemetry() {
  const [state, dispatch] = useReducer(reduce, initialState);
  useEffect(() => {
    let ws;
    let closed = false;
    let delay = 500;
    let timer;
    const connect = () => {
      const proto = location.protocol === 'https:' ? 'wss' : 'ws';
      ws = new WebSocket(`${proto}://${location.host}/ws`);
      ws.onopen = () => { delay = 500; dispatch({ type: 'socket', connected: true }); };
      ws.onmessage = (e) => { try { dispatch(JSON.parse(e.data)); } catch { /* ignore torn frame */ } };
      ws.onclose = () => {
        dispatch({ type: 'socket', connected: false });
        if (!closed) { timer = setTimeout(connect, delay); delay = Math.min(delay * 2, 8000); }
      };
    };
    connect();
    return () => { closed = true; clearTimeout(timer); ws?.close(); };
  }, []);
  return state;
}
