import { describe, expect, it } from 'vitest';

import { ago, bytes, hexGroups, joinPath, latency, parentOf, rate } from '../lib/format.js';

describe('format', () => {
  it('formats sizes in binary units', () => {
    expect(bytes(0)).toBe('0 B');
    expect(bytes(1023)).toBe('1023 B');
    expect(bytes(1536)).toBe('1.5 KiB');
    expect(bytes(5 * 1024 ** 3)).toBe('5.0 GiB');
    expect(bytes(undefined)).toBe('0 B');
  });

  it('formats latency', () => {
    expect(latency(999)).toBe('999 µs');
    expect(latency(1500)).toBe('1.5 ms');
    expect(latency(2_500_000)).toBe('2.50 s');
  });

  it('formats rates', () => {
    expect(rate(3.14)).toBe('3.1');
    expect(rate(42.4)).toBe('42');
  });

  it('formats ages in both languages', () => {
    expect(ago(1500)).toBe('1.5 s ago');
    expect(ago(null)).toBe('never');
    expect(ago(-1, 'hi')).toBe('कभी नहीं');
  });

  it('joins and splits paths', () => {
    expect(joinPath('/', 'a')).toBe('/a');
    expect(joinPath('/a', 'b')).toBe('/a/b');
    expect(parentOf('/a/b')).toBe('/a');
    expect(parentOf('/a')).toBe('/');
    expect(parentOf('/a/b/')).toBe('/a');
    expect(parentOf('/')).toBe('/');
  });

  it('groups hex', () => {
    expect(hexGroups('00112233445566778899')).toBe('00112233 44556677 8899');
    expect(hexGroups('')).toBe('');
  });
});
