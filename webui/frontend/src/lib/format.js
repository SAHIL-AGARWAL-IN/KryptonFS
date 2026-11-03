// Human-readable numbers, matching the terminal dashboard's formatting.

export function bytes(n) {
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let v = Number(n) || 0;
  let i = 0;
  while (Math.abs(v) >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
  return i === 0 ? `${Math.round(v)} B` : `${v.toFixed(1)} ${units[i]}`;
}

export function latency(us) {
  const v = Number(us) || 0;
  if (v < 1000) return `${Math.round(v)} µs`;
  if (v < 1_000_000) return `${(v / 1000).toFixed(1)} ms`;
  return `${(v / 1_000_000).toFixed(2)} s`;
}

export function rate(perSecond) {
  const v = Number(perSecond) || 0;
  return v >= 100 ? Math.round(v).toLocaleString() : v.toFixed(v >= 10 ? 0 : 1);
}

export function clock(ms) {
  return new Date(ms).toLocaleTimeString([], { hour12: false });
}

export function when(ms) {
  return new Date(ms).toLocaleString([], { dateStyle: 'short', timeStyle: 'short' });
}

export function ago(ms, lang = 'en') {
  if (ms == null || ms < 0) return lang === 'hi' ? 'कभी नहीं' : 'never';
  const s = ms / 1000;
  return lang === 'hi' ? `${s.toFixed(1)} से. पहले` : `${s.toFixed(1)} s ago`;
}

export function joinPath(dir, name) {
  return (dir.endsWith('/') ? dir : `${dir}/`) + name;
}

export function parentOf(path) {
  if (path === '/' || !path) return '/';
  const i = path.replace(/\/+$/, '').lastIndexOf('/');
  return i <= 0 ? '/' : path.slice(0, i);
}

export function hexGroups(hex, group = 4) {
  return (hex.match(new RegExp(`.{1,${group * 2}}`, 'g')) ?? []).join(' ');
}
