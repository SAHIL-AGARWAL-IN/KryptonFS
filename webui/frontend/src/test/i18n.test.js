import { describe, expect, it } from 'vitest';

import en from '../i18n/en.js';
import hi from '../i18n/hi.js';
import { translate } from '../i18n/index.jsx';

const placeholders = (s) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();

describe('i18n', () => {
  it('has a Hindi string for every English key, and no extras', () => {
    expect(Object.keys(hi).sort()).toEqual(Object.keys(en).sort());
  });

  it('uses the same placeholders in both languages', () => {
    for (const key of Object.keys(en)) {
      expect([key, placeholders(hi[key])]).toEqual([key, placeholders(en[key])]);
    }
  });

  it('fills placeholders and falls back to the key', () => {
    expect(translate('en', 'map.server', { n: 2 })).toBe('Server 2');
    expect(translate('hi', 'no.such.key')).toBe('no.such.key');
  });
});
