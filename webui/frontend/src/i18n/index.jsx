import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';

import en from './en.js';
import hi from './hi.js';

export const DICTS = { en, hi };

export function translate(lang, key, vars = {}) {
  const s = DICTS[lang]?.[key] ?? en[key] ?? key;
  return s.replace(/\{(\w+)\}/g, (_, k) => (vars[k] ?? `{${k}}`));
}

const I18n = createContext({ lang: 'en', t: (k) => k, setLang: () => {} });

function initialLang() {
  try {
    const saved = localStorage.getItem('krypton-console-lang');
    if (saved === 'en' || saved === 'hi') return saved;
  } catch { /* storage blocked */ }
  return navigator.language?.startsWith('hi') ? 'hi' : 'en';
}

export function I18nProvider({ children }) {
  const [lang, setLangState] = useState(initialLang);
  const setLang = useCallback((l) => {
    setLangState(l);
    try { localStorage.setItem('krypton-console-lang', l); } catch { /* storage blocked */ }
  }, []);
  useEffect(() => { document.documentElement.lang = lang; }, [lang]);
  const value = useMemo(() => ({ lang, setLang, t: (k, v) => translate(lang, k, v) }), [lang, setLang]);
  return <I18n.Provider value={value}>{children}</I18n.Provider>;
}

export const useI18n = () => useContext(I18n);
