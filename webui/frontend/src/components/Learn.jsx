// Learn mode: Krypto explains whatever panel you point at, in the chosen
// language, and can walk through every panel in order ("Take the tour").

import { createContext, useCallback, useContext, useMemo, useState } from 'react';

import { useI18n } from '../i18n/index.jsx';
import Krypto from './Krypto.jsx';

// The tour's order: [view, explanation id]. The ids are i18n keys under learn.*.
export const TOUR = [
  ['overview', 'overview.map'],
  ['overview', 'overview.io'],
  ['overview', 'overview.security'],
  ['overview', 'overview.feed'],
  ['files', 'files.list'],
  ['files', 'files.stored'],
  ['cluster', 'cluster.nodes'],
  ['cluster', 'cluster.lock'],
  ['attacks', 'attacks.lab'],
];

const LearnCtx = createContext(null);

export function LearnProvider({ children, setView, attacksEnabled }) {
  const [enabled, setEnabled] = useState(false);
  const [focus, setFocus] = useState(null);       // explanation id being shown
  const [tourStep, setTourStep] = useState(null); // index into TOUR while touring
  const steps = useMemo(() => TOUR.filter(([v]) => v !== 'attacks' || attacksEnabled),
    [attacksEnabled]);

  const goStep = useCallback((i) => {
    if (i < 0 || i >= steps.length) { setTourStep(null); setFocus(null); return; }
    const [view, id] = steps[i];
    setView(view);
    setTourStep(i);
    setFocus(id);
    requestAnimationFrame(() => document.getElementById(`learn-${id}`)
      ?.scrollIntoView({ behavior: 'smooth', block: 'center' }));
  }, [setView, steps]);

  const value = useMemo(() => ({
    enabled, focus, tourStep, steps,
    toggle: () => { setEnabled((e) => !e); setFocus(null); setTourStep(null); },
    explain: (id) => { setEnabled(true); setFocus(id); setTourStep(null); },
    startTour: () => { setEnabled(true); goStep(0); },
    goStep,
    close: () => { setFocus(null); setTourStep(null); },
  }), [enabled, focus, tourStep, steps, goStep]);
  return <LearnCtx.Provider value={value}>{children}</LearnCtx.Provider>;
}

export const useLearn = () => useContext(LearnCtx);

// Wrap a panel: in learn mode it gets Krypto's "explain this" button, and
// the panel being explained is outlined.
export function Explain({ id, children, className = '' }) {
  const learn = useLearn();
  const { t } = useI18n();
  const active = learn?.enabled && learn.focus === id;
  return (
    <section id={`learn-${id}`}
             className={`relative scroll-mt-24 rounded-lg transition-shadow ${active ? 'shadow-[0_0_0_2px_#00e5ff]' : ''} ${className}`}>
      {learn?.enabled && (
        <button type="button" onClick={() => learn.explain(id)}
                className="absolute -top-3 right-3 z-10 flex items-center gap-1 rounded-full border border-cyan bg-ink px-2 py-0.5 text-xs font-bold text-cyan"
                aria-label={t('top.learn')}>
          <Krypto className="h-4 w-4" /> ?
        </button>
      )}
      {children}
    </section>
  );
}

// Krypto docked in the corner, saying the current explanation.
export function Guide() {
  const learn = useLearn();
  const { t } = useI18n();
  if (!learn?.enabled) return null;
  const touring = learn.tourStep !== null;
  const text = learn.focus ? t(`learn.${learn.focus}`) : t('learn.hello');
  return (
    <aside className="fixed bottom-4 right-4 z-40 flex max-w-[min(30rem,calc(100vw-2rem))] items-end gap-3"
           aria-live="polite">
      <div className="rounded-xl border border-rule bg-deck p-4 shadow-2xl shadow-black/60">
        <p className="text-[.95rem] leading-relaxed">{text}</p>
        <div className="mt-3 flex flex-wrap items-center gap-2">
          {touring ? (
            <>
              <span className="num mr-auto text-xs text-mist">{learn.tourStep + 1} / {learn.steps.length}</span>
              <button type="button" className="btn" disabled={learn.tourStep === 0}
                      onClick={() => learn.goStep(learn.tourStep - 1)}>{t('learn.back')}</button>
              <button type="button" className="btn btn-primary"
                      onClick={() => learn.goStep(learn.tourStep + 1)}>
                {learn.tourStep === learn.steps.length - 1 ? t('learn.done') : t('learn.next')}
              </button>
            </>
          ) : (
            <button type="button" className="btn btn-primary" onClick={learn.startTour}>{t('learn.tour')}</button>
          )}
        </div>
      </div>
      <Krypto className="h-24 w-20 shrink-0" talking mood="calm" />
    </aside>
  );
}

const AdvancedCtx = createContext(false);
export const AdvancedProvider = AdvancedCtx.Provider;
export const useAdvanced = () => useContext(AdvancedCtx);
