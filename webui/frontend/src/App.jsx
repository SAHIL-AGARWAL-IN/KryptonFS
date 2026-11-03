// Krypton Console: rail navigation, a status bar, and four views.

import { useCallback, useEffect, useState } from 'react';

import AttackLab from './components/AttackLab.jsx';
import ClusterMap from './components/ClusterMap.jsx';
import ClusterView from './components/ClusterView.jsx';
import FilesView from './components/FilesView.jsx';
import IoPanel from './components/IoPanel.jsx';
import Krypto from './components/Krypto.jsx';
import { AdvancedProvider, Explain, Guide, LearnProvider, useLearn } from './components/Learn.jsx';
import Login from './components/Login.jsx';
import { Feed, MountTree, Protection } from './components/Security.jsx';
import { useI18n } from './i18n/index.jsx';
import { api } from './lib/api.js';
import { parentOf } from './lib/format.js';
import { useTelemetry } from './lib/telemetry.js';

const VIEWS = ['overview', 'files', 'cluster', 'attacks'];

function useHashView() {
  const read = () => {
    const h = location.hash.slice(1);
    return VIEWS.includes(h) ? h : 'overview';
  };
  const [view, setViewState] = useState(read);
  useEffect(() => {
    const on = () => setViewState(read());
    window.addEventListener('hashchange', on);
    return () => window.removeEventListener('hashchange', on);
  }, []);
  const setView = useCallback((v) => {
    if (location.hash.slice(1) !== v) history.replaceState(null, '', `#${v}`);
    setViewState(v);
  }, []);
  return [view, setView];
}

function Toasts({ toasts }) {
  return (
    <div className="pointer-events-none fixed left-1/2 top-4 z-50 flex w-[min(32rem,calc(100vw-2rem))] -translate-x-1/2 flex-col gap-2"
         aria-live="polite">
      {toasts.map((x) => (
        <div key={x.id} role={x.kind === 'bad' ? 'alert' : 'status'}
             className={`rounded-md border px-4 py-2 text-sm shadow-xl shadow-black/50 ${x.kind === 'bad' ? 'border-coral bg-[#1d0f0e] text-coral' : 'border-neon-dim bg-[#0c160b] text-neon'}`}>
          {x.text}
        </div>
      ))}
    </div>
  );
}

function Toggle({ on, onClick, children }) {
  return (
    <button type="button" aria-pressed={on} onClick={onClick}
            className={`rounded-md border px-2.5 py-1 text-sm font-bold ${on ? 'border-cyan text-cyan' : 'border-rule text-mist hover:text-bone'}`}>
      {children}
    </button>
  );
}

function Console({ session, signOut }) {
  const { t, lang, setLang } = useI18n();
  const learn = useLearn();
  const [view, setView] = [session.view, session.setView];
  const tel = useTelemetry();
  const [cluster, setCluster] = useState(null);
  const [advanced, setAdvanced] = useState(false);
  const [toasts, setToasts] = useState([]);
  const [filesTarget, setFilesTarget] = useState(null);

  const notify = useCallback((kind, text) => {
    const id = Math.random();
    setToasts((x) => [...x, { id, kind, text }]);
    setTimeout(() => setToasts((x) => x.filter((y) => y.id !== id)), kind === 'bad' ? 7000 : 3500);
  }, []);

  const refreshCluster = useCallback(async () => {
    try { setCluster(await api.cluster()); } catch { /* shown via telemetry status */ }
  }, []);
  useEffect(() => {
    refreshCluster();
    const timer = setInterval(refreshCluster, 3000);
    return () => clearInterval(timer);
  }, [refreshCluster]);

  const mounted = cluster?.mounted ?? false;
  const features = session.features;
  const live = tel.connected && tel.daemon.connected;
  const nav = VIEWS.filter((v) => v !== 'attacks' || features.attacks);

  return (
    <AdvancedProvider value={advanced}>
      <div className="flex min-h-full">
        <div className="hidden shrink-0 border-r border-rule md:block">
        <nav aria-label="Main" className="sticky top-0 flex h-screen w-52 flex-col px-3 py-5">
          <div className="mb-8 flex items-center gap-2.5 px-2">
            <Krypto className="h-10 w-8" mood={tel.snapshot?.sandbox?.failed ? 'alert' : 'calm'} />
            <div className="font-display text-lg font-bold leading-tight">Krypton<span className="text-cyan">FS</span></div>
          </div>
          <ul className="space-y-1">
            {nav.map((v) => (
              <li key={v}>
                <button type="button" onClick={() => setView(v)} aria-current={view === v ? 'page' : undefined}
                        className={`w-full rounded-md px-3 py-2 text-left font-bold ${view === v ? 'bg-cyan-deep text-cyan' : 'text-mist hover:bg-deck hover:text-bone'}`}>
                  {t(`nav.${v}`)}
                </button>
              </li>
            ))}
          </ul>
        </nav>
        </div>

        <div className="min-w-0 flex-1">
          <header className="sticky top-0 z-30 flex flex-wrap items-center gap-x-4 gap-y-2 border-b border-rule bg-ink/95 px-4 py-3 backdrop-blur md:px-8">
            <select aria-label="Main" className="field w-auto md:hidden" value={view} onChange={(e) => setView(e.target.value)}>
              {nav.map((v) => <option key={v} value={v}>{t(`nav.${v}`)}</option>)}
            </select>
            <span className={`chip ${mounted ? 'border-neon-dim text-neon' : 'border-coral text-coral'}`}>
              {mounted ? t('top.unlocked') : t('top.locked')}
            </span>
            <span className="flex items-center gap-1.5 text-sm text-mist">
              <span className={`h-2 w-2 rounded-full ${live ? 'bg-neon' : 'bg-coral'}`} />
              {!tel.connected ? t('top.offline') : !tel.daemon.connected ? t('top.daemonDown') : t('top.live')}
            </span>
            <div className="ml-auto flex flex-wrap items-center gap-2">
              <Toggle on={learn.enabled} onClick={learn.toggle}>{t('top.learn')}</Toggle>
              <Toggle on={advanced} onClick={() => setAdvanced((a) => !a)}>{t('top.advanced')}</Toggle>
              <button type="button" className="rounded-md border border-rule px-2.5 py-1 text-sm font-bold text-mist hover:text-bone"
                      lang={lang === 'en' ? 'hi' : 'en'} onClick={() => setLang(lang === 'en' ? 'hi' : 'en')}>
                {t('top.language')}
              </button>
              {session.loginRequired && (
                <button type="button" className="rounded-md px-2.5 py-1 text-sm text-mist hover:text-bone" onClick={signOut}>
                  {t('top.signOut')}
                </button>
              )}
            </div>
          </header>

          <main className="mx-auto max-w-[1400px] px-4 py-8 md:px-8">
            <h1 className="mb-6 font-display text-2xl font-bold">
              {view === 'overview' ? t('map.title') : t(`nav.${view}`)}
            </h1>

            {view === 'overview' && (
              <div className="space-y-10">
                <Explain id="overview.map" className="-mx-2 px-2">
                  <ClusterMap snapshot={tel.snapshot} rates={tel.rates} cluster={cluster} />
                </Explain>
                <div className="grid gap-10 xl:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
                  <div className="space-y-10">
                    <Explain id="overview.io">
                      <h2 className="panel-title mb-4">{t('io.title')}</h2>
                      <IoPanel history={tel.history} rates={tel.rates} snapshot={tel.snapshot} />
                    </Explain>
                    <Explain id="overview.feed">
                      <h2 className="panel-title mb-4">{t('feed.title')}</h2>
                      <Feed events={tel.events} />
                    </Explain>
                  </div>
                  <div className="space-y-10">
                    <Explain id="overview.security">
                      <h2 className="panel-title mb-4">{t('sec.title')}</h2>
                      <Protection snapshot={tel.snapshot} />
                    </Explain>
                    <section>
                      <h2 className="panel-title mb-4">{t('tree.title')}</h2>
                      <MountTree tree={tel.tree} truncated={tel.treeTruncated}
                                 onOpen={(e) => {
                                   setFilesTarget(e.dir ? { dir: e.path } : { dir: parentOf(e.path), file: e.path });
                                   setView('files');
                                 }} />
                    </section>
                  </div>
                </div>
              </div>
            )}
            {view === 'files' && <FilesView target={filesTarget} mounted={mounted} notify={notify} />}
            {view === 'cluster' && (
              <ClusterView cluster={cluster} snapshot={tel.snapshot} mode={session.mode}
                           refresh={refreshCluster} notify={notify} />
            )}
            {view === 'attacks' && (
              <AttackLab enabled={features.attacks} onDone={refreshCluster} notify={notify} />
            )}
          </main>
        </div>
      </div>
      <Guide />
      <Toasts toasts={toasts} />
    </AdvancedProvider>
  );
}

export default function App() {
  const [session, setSession] = useState(null);
  const [error, setError] = useState('');
  const [view, setView] = useHashView();

  const load = useCallback(() => {
    api.session().then(setSession).catch((e) => setError(e.message));
  }, []);
  useEffect(load, [load]);

  if (error) return <p className="p-8 text-coral">{error}</p>;
  if (!session) return null;
  if (session.loginRequired && !session.signedIn) return <Login onSignedIn={load} />;

  return (
    <LearnProvider setView={setView} attacksEnabled={session.features.attacks}>
      <Console session={{ ...session, view, setView }}
               signOut={async () => { await api.logout().catch(() => {}); load(); }} />
    </LearnProvider>
  );
}
