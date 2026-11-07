// Protection status (sandbox workers, where the key lives, the crypto
// suite), the security event feed, and the compact mount tree.

import { useI18n } from '../i18n/index.jsx';
import { bytes, clock } from '../lib/format.js';
import { useAdvanced } from './Learn.jsx';

// The daemon reports the key's whereabouts in English; translate the two
// forms it sends and pass anything else through.
function keyStatus(t, text) {
  if (!text) return '…';
  const held = /^held by (\d+) jailed crypto workers/.exec(text);
  if (held) return t('sec.keyHeld', { n: held[1] });
  if (text.startsWith('unavailable')) return t('sec.keyUnavailable');
  return text;
}

export function Protection({ snapshot }) {
  const { t } = useI18n();
  const advanced = useAdvanced();
  const sandbox = snapshot?.sandbox ?? { workers: [] };
  const keys = snapshot?.keys ?? {};
  const pool = (kind) => sandbox.workers.filter((w) => w.kind === kind);

  const Row = ({ label, children }) => (
    <div className="grid grid-cols-[7.5rem_1fr] gap-3 border-t border-rule py-2 first:border-t-0">
      <dt className="text-sm text-mist">{label}</dt>
      <dd className="min-w-0 text-sm">{children}</dd>
    </div>
  );
  const Dots = ({ workers }) => (
    <span className="inline-flex gap-1 align-middle">
      {workers.map((w) => (
        <span key={w.pid} title={advanced ? `pid ${w.pid}` : undefined}
              className={`h-2.5 w-2.5 rounded-full ${w.alive ? 'bg-neon' : 'bg-coral'}`} />
      ))}
    </span>
  );

  return (
    <div>
      <div className="mb-3">
        {sandbox.failed
          ? <span className="chip border-coral bg-coral-dim text-coral">{t('sec.failed')}</span>
          : sandbox.workers.length > 0 && <span className="chip border-neon-dim text-neon">{t('sec.jailed')}</span>}
      </div>
      <dl>
        <Row label={t('sec.scan')}><Dots workers={pool('scan')} /></Row>
        <Row label={t('sec.crypto')}><Dots workers={pool('crypto')} /></Row>
        <Row label={t('sec.key')}>
          <span className={keys.volume_key?.startsWith('unavailable') ? 'text-coral' : 'text-neon'}>
            {keyStatus(t, keys.volume_key)}
          </span>
        </Row>
        <Row label={t('sec.cipher')}>
          {keys.cipher ?? '…'}
          {advanced && keys.kdf && <span className="block text-xs text-mist">{keys.kdf} × {keys.kdf_iterations?.toLocaleString()}</span>}
        </Row>
        <Row label={t('sec.identity')}>
          {keys.identity_id ? t('sec.identityValue', { id: keys.identity_id }) : t('sec.localStore')}
        </Row>
      </dl>
    </div>
  );
}

const LEVEL = {
  info: 'border-l-cyan-dim',
  warn: 'border-l-coral',
  alert: 'border-l-coral bg-coral-dim/30',
};

export function Feed({ events }) {
  const { t } = useI18n();
  if (!events.length) return <p className="text-sm text-mist">{t('feed.empty')}</p>;
  return (
    <ol className="max-h-80 space-y-1.5 overflow-y-auto pr-1">
      {[...events].reverse().slice(0, 80).map((e) => (
        // seq restarts with the daemon, so it alone is not unique.
        <li key={`${e.ts_ms}-${e.seq}`} className={`rounded-r border-l-[3px] py-1.5 pl-3 pr-2 ${LEVEL[e.level] ?? LEVEL.info}`}>
          <div className="num flex gap-2 text-xs text-mist">
            <span>{clock(e.ts_ms)}</span>
            <span className={e.level === 'info' ? 'text-cyan' : 'font-bold text-coral'}>{e.kind}</span>
          </div>
          <div className="break-words text-sm">{e.msg}</div>
        </li>
      ))}
    </ol>
  );
}

export function MountTree({ tree, truncated, onOpen }) {
  const { t } = useI18n();
  const entries = tree.filter((e) => e.path !== '/');
  if (!entries.length) return <p className="text-sm text-mist">{t('tree.empty')}</p>;
  return (
    <div>
      <ul className="max-h-80 overflow-y-auto font-mono text-[13px]">
        {entries.slice(0, 400).map((e) => (
          <li key={e.path} style={{ paddingLeft: `${(e.depth - 1) * 1.1}rem` }}>
            <button type="button" onClick={() => onOpen(e)}
                    className="flex w-full justify-between gap-3 rounded px-1.5 py-0.5 text-left hover:bg-deck">
              <span className={`truncate ${e.dir ? 'text-cyan' : 'text-bone'}`}>
                {e.path.split('/').pop()}{e.dir ? '/' : ''}
              </span>
              {!e.dir && <span className="num shrink-0 text-mist">{bytes(e.size)}</span>}
            </button>
          </li>
        ))}
      </ul>
      {truncated && <p className="mt-2 text-xs text-mist">{t('tree.truncated')}</p>}
    </div>
  );
}
