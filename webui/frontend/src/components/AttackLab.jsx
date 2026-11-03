// Attack lab: run a real attack against the demo volume and see each step
// of KryptonFS's response.

import { useState } from 'react';

import { useI18n } from '../i18n/index.jsx';
import { api } from '../lib/api.js';
import Krypto from './Krypto.jsx';
import { Explain } from './Learn.jsx';

const ATTACKS = [
  { kind: 'malware', key: 'malware' },
  { kind: 'tamper', key: 'tamper' },
  { kind: 'kill-node', key: 'kill' },
];

function Attack({ kind, k, onDone, notify }) {
  const { t } = useI18n();
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const run = async () => {
    setBusy(true);
    setResult(null);
    try {
      setResult(await api.attack(kind));
      onDone();
    } catch (e) {
      notify('bad', e.message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <li className="flex flex-col rounded-lg border border-rule p-5">
      <h3 className="font-display text-lg font-bold">{t(`attacks.${k}.title`)}</h3>
      <p className="mt-1 text-sm text-mist">{t(`attacks.${k}.body`)}</p>
      <div className="mt-4">
        <button type="button" className="btn btn-danger" disabled={busy} onClick={run}>
          {busy ? t('attacks.running') : t('attacks.run')}
        </button>
      </div>
      {result && (
        <div className="mt-5">
          <div className="mb-3 flex items-center gap-3">
            <Krypto className="h-12 w-10" mood={result.defended ? 'happy' : 'alert'} />
            <span className={`chip ${result.defended ? 'border-neon text-neon' : 'border-coral text-coral'}`}>
              {result.defended ? t('attacks.defended') : t('attacks.notDefended')}
            </span>
          </div>
          {/* The steps really are a sequence, so they are numbered. */}
          <ol className="space-y-2">
            {result.steps.map((s, i) => (
              <li key={i} className="grid grid-cols-[1.75rem_1fr] gap-2">
                <span className={`num mt-0.5 grid h-6 w-6 place-items-center rounded-full border text-xs font-bold
                                  ${s.ok ? 'border-cyan-dim text-cyan' : 'border-coral text-coral'}`}>{i + 1}</span>
                <div className="min-w-0">
                  <div className="text-sm font-bold">{t(`step.${s.code}.title`, s.params)}</div>
                  <div className="break-words text-sm text-mist">{t(`step.${s.code}.detail`, s.params)}</div>
                </div>
              </li>
            ))}
          </ol>
        </div>
      )}
    </li>
  );
}

export default function AttackLab({ enabled, onDone, notify }) {
  const { t } = useI18n();
  if (!enabled) return <p className="text-mist">{t('attacks.off')}</p>;
  return (
    <Explain id="attacks.lab">
      <p className="mb-5 max-w-prose text-mist">{t('attacks.intro')}</p>
      <ul className="grid gap-4 lg:grid-cols-3">
        {ATTACKS.map((a) => <Attack key={a.kind} kind={a.kind} k={a.key} onDone={onDone} notify={notify} />)}
      </ul>
    </Explain>
  );
}
