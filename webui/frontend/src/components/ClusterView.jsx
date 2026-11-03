// Storage servers (start / stop / crash, recent log) and the volume lock.

import { useState } from 'react';

import { useI18n } from '../i18n/index.jsx';
import { api } from '../lib/api.js';
import { ago, bytes, latency } from '../lib/format.js';
import { Explain, useAdvanced } from './Learn.jsx';

function NodeCard({ node, health, nodeControl, refresh, notify }) {
  const { t, lang } = useI18n();
  const advanced = useAdvanced();
  const [busy, setBusy] = useState(false);
  const [log, setLog] = useState(null);
  const state = health?.state ?? (node.running ? 'unknown' : 'down');
  const up = node.running;

  const run = async (fn) => {
    setBusy(true);
    try { await fn(); await refresh(); } catch (e) { notify('bad', e.message); } finally { setBusy(false); }
  };

  return (
    <li className={`rounded-lg border p-4 ${up ? 'border-rule' : 'border-coral/70'}`}>
      <div className="flex items-start justify-between gap-3">
        <div>
          <h3 className="font-display text-lg font-bold">{t('map.server', { n: node.id })}</h3>
          <p className={`text-sm font-bold ${up ? 'text-neon' : 'text-coral'}`}>
            {up ? t('cluster.running') : t('cluster.stopped')}
            {health && <span className="font-normal text-mist"> · {t(`state.${state}`)}</span>}
          </p>
        </div>
        {health?.rtt_us > 0 && up && <span className="num text-sm text-mist">{latency(health.rtt_us)}</span>}
      </div>
      <p className="num mt-2 text-sm text-mist">
        {t('cluster.stored', { n: node.objects.toLocaleString(), size: bytes(node.bytes) })}
        {advanced && node.pid && up && <> · {t('cluster.pid', { pid: node.pid })}</>}
        {advanced && health && <> · {ago(health.last_seen_ms, lang)}</>}
      </p>

      {!node.managed ? <p className="mt-3 text-sm text-mist">{t('cluster.unmanaged')}</p>
        : !nodeControl ? <p className="mt-3 text-sm text-mist">{t('cluster.controlOff')}</p>
        : (
          <div className="mt-4 flex flex-wrap gap-2">
            {up ? (
              <>
                <button type="button" className="btn" disabled={busy}
                        onClick={() => run(() => api.stopNode(node.id, 'graceful'))}>{t('cluster.stop')}</button>
                <button type="button" className="btn btn-danger" disabled={busy}
                        onClick={() => run(() => api.stopNode(node.id, 'crash'))}>{t('cluster.crash')}</button>
              </>
            ) : (
              <button type="button" className="btn btn-primary" disabled={busy}
                      onClick={() => run(() => api.startNode(node.id))}>{t('cluster.start')}</button>
            )}
            {advanced && (
              <button type="button" className="btn ml-auto" onClick={async () => {
                if (log) { setLog(null); return; }
                try { setLog((await api.nodeLog(node.id)).lines); } catch (e) { notify('bad', e.message); }
              }}>{t('cluster.log')}</button>
            )}
          </div>
        )}
      {log && (
        <pre className="mt-3 max-h-56 overflow-auto rounded bg-ink p-3 font-mono text-xs text-mist">{log.join('\n') || '—'}</pre>
      )}
    </li>
  );
}

function VolumeLock({ mounted, mode, refresh, notify }) {
  const { t } = useI18n();
  const [pass, setPass] = useState('');
  const [busy, setBusy] = useState(false);
  const run = async (fn) => {
    setBusy(true);
    try { await fn(); setPass(''); await refresh(); } catch (e) { notify('bad', e.message); } finally { setBusy(false); }
  };
  return (
    <div className="max-w-xl">
      <p className="mb-4">{mounted ? t('lock.unlockedBody') : t('lock.lockedBody')}</p>
      {mounted ? (
        <button type="button" className="btn btn-danger" disabled={busy} onClick={() => run(api.lock)}>
          {busy ? t('lock.busy') : t('lock.lock')}
        </button>
      ) : (
        <form className="flex flex-wrap items-end gap-2" onSubmit={(e) => { e.preventDefault(); run(() => api.unlock(pass)); }}>
          <div className="min-w-[16rem] flex-1">
            <label htmlFor="passphrase" className="mb-1 block text-sm text-mist">{t('lock.passphrase')}</label>
            <input id="passphrase" type="password" className="field" autoComplete="off" value={pass}
                   onChange={(e) => setPass(e.target.value)} />
          </div>
          <button type="submit" className="btn btn-primary" disabled={busy || !pass}>
            {busy ? t('lock.busy') : t('lock.unlock')}
          </button>
          {mode === 'demo' && <p className="w-full text-xs text-mist">{t('lock.demoHint')}</p>}
        </form>
      )}
    </div>
  );
}

export default function ClusterView({ cluster, snapshot, mode, refresh, notify }) {
  const { t } = useI18n();
  const health = Object.fromEntries((snapshot?.nodes ?? []).map((n) => [n.id, n]));
  return (
    <div className="space-y-10">
      <Explain id="cluster.nodes">
        <p className="mb-4 max-w-prose text-mist">{t('cluster.intro')}</p>
        <ul className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {(cluster?.nodes ?? []).map((n) => (
            <NodeCard key={n.id} node={n} health={health[n.id]} nodeControl={cluster.features?.nodeControl}
                      refresh={refresh} notify={notify} />
          ))}
        </ul>
      </Explain>
      <Explain id="cluster.lock">
        <h3 className="panel-title mb-3">{t('lock.title')}</h3>
        <VolumeLock mounted={cluster?.mounted} mode={mode} refresh={refresh} notify={notify} />
      </Explain>
    </div>
  );
}
