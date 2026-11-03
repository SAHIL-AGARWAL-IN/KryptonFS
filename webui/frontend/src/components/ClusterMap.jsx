// The cluster map: your volume on the left, the storage servers on the
// right, and live traffic between them. Writes travel out in cyan, reads
// come back in green; a server that is down turns coral and goes quiet.
// Each server shows a grid of the encrypted blocks it holds.

import { useEffect, useState } from 'react';

import { useI18n } from '../i18n/index.jsx';
import { latency } from '../lib/format.js';
import Krypto from './Krypto.jsx';

const W = 920;
const VAULT_X = 150;
const SERVER_X = 600;
const CARD_W = 310;
const CARD_H = 92;
const ROW = CARD_H + 18;
const GRID_COLS = 12;
const GRID_ROWS = 4;

const STATE_COLOR = { up: '#39ff14', degraded: '#ff6f61', draining: '#ff6f61', down: '#ff6f61',
  unknown: '#7d8d9c' };

function useReducedMotion() {
  const [reduced, setReduced] = useState(false);
  useEffect(() => {
    const m = window.matchMedia('(prefers-reduced-motion: reduce)');
    setReduced(m.matches);
    const on = (e) => setReduced(e.matches);
    m.addEventListener('change', on);
    return () => m.removeEventListener('change', on);
  }, []);
  return reduced;
}

// 0 ops -> 0 packets; then 1..4 packets on a log scale.
const packets = (perSecond) => (perSecond <= 0 ? 0 : Math.min(4, 1 + Math.floor(Math.log10(perSecond + 1) * 1.5)));

export default function ClusterMap({ snapshot, rates, cluster }) {
  const { t } = useI18n();
  const reduced = useReducedMotion();
  const nodes = snapshot?.nodes ?? [];
  const backend = snapshot?.volume?.backend;

  if (!snapshot) {
    return <p className="py-16 text-center text-mist">{t('map.noTelemetry')}</p>;
  }
  if (backend === 'local' || nodes.length === 0) {
    return <p className="py-16 text-center text-mist">{t('map.local')}</p>;
  }

  const objects = Object.fromEntries((cluster?.nodes ?? []).map((n) => [n.id, n.objects]));
  const maxObjects = Math.max(1, ...Object.values(objects));
  const H = Math.max(310, nodes.length * ROW + 20);
  const VAULT = { x: VAULT_X, y: H / 2 };
  const writeN = packets(rates?.writeIops ?? 0);
  const readN = packets(rates?.readIops ?? 0);

  return (
    <>
    <svg viewBox={`0 0 ${W} ${H}`} className="hidden w-full sm:block" role="img" aria-label={t('map.title')}>
      {nodes.map((n, i) => {
        const y = 10 + ROW * (i + 0.5);
        const d = `M ${VAULT.x + 70} ${VAULT.y} C ${VAULT.x + 260} ${VAULT.y}, ${SERVER_X - 200} ${y}, ${SERVER_X - 8} ${y}`;
        const back = `M ${SERVER_X - 8} ${y} C ${SERVER_X - 200} ${y}, ${VAULT.x + 260} ${VAULT.y}, ${VAULT.x + 70} ${VAULT.y}`;
        const up = n.state === 'up' || n.state === 'degraded';
        const color = STATE_COLOR[n.state] ?? STATE_COLOR.unknown;
        const cells = Math.round(((objects[n.id] ?? 0) / maxObjects) * GRID_COLS * GRID_ROWS);
        return (
          <g key={n.id}>
            <path d={d} fill="none" stroke={up ? '#0f5d6b' : '#5a2622'} strokeWidth="2"
                  strokeDasharray={up ? undefined : '6 6'} />
            {up && !reduced && Array.from({ length: writeN }, (_, k) => (
              <circle key={`w${k}`} r="3.5" fill="#00e5ff">
                <animateMotion dur="1.8s" repeatCount="indefinite" path={d} begin={`${(k * 1.8) / writeN}s`} />
              </circle>
            ))}
            {up && !reduced && Array.from({ length: readN }, (_, k) => (
              <circle key={`r${k}`} r="3" fill="#39ff14">
                <animateMotion dur="2.2s" repeatCount="indefinite" path={back} begin={`${(k * 2.2) / readN}s`} />
              </circle>
            ))}
            {up && n.rtt_us > 0 && (
              <text x={SERVER_X - 60} y={y - 9} fill="#7d8d9c" fontSize="12" fontFamily="JetBrains Mono" textAnchor="middle">
                {latency(n.rtt_us)}
              </text>
            )}

            <g transform={`translate(${SERVER_X} ${y - CARD_H / 2})`}>
              <rect width={CARD_W} height={CARD_H} rx="10" fill="#0c1117" stroke={up ? '#1a2631' : '#ff6f61'} />
              <text x="16" y="26" fill="#dfe7ee" fontSize="16" fontFamily="Chakra Petch" fontWeight="700">
                {t('map.server', { n: n.id })}
              </text>
              <circle cx="20" cy="45" r="5" fill={color} />
              <text x="32" y="50" fill={color} fontSize="13" fontWeight="700" fontFamily="Nunito">
                {t(`state.${n.state}`)}
              </text>
              <text x="16" y="76" fill="#7d8d9c" fontSize="12" fontFamily="Nunito">
                {t('map.blocks', { n: (objects[n.id] ?? 0).toLocaleString() })}
              </text>
              {Array.from({ length: GRID_COLS * GRID_ROWS }, (_, c) => (
                <rect key={c} x={CARD_W - 128 + (c % GRID_COLS) * 10} y={18 + Math.floor(c / GRID_COLS) * 10}
                      width="7" height="7" rx="1.5"
                      fill={c < cells ? (up ? '#00e5ff' : '#5a2622') : '#1a2631'}
                      opacity={c < cells ? 0.55 + 0.45 * ((c * 37) % 7) / 7 : 1} />
              ))}
              {n.disk_total > 0 && (
                <g transform={`translate(${CARD_W - 128} 66)`}>
                  <rect width="118" height="5" rx="2.5" fill="#1a2631" />
                  <rect width={Math.max(2, 118 * (n.disk_used / n.disk_total))} height="5" rx="2.5"
                        fill={n.disk_used / n.disk_total >= 0.8 ? '#ff6f61' : '#39ff14'} />
                </g>
              )}
            </g>
          </g>
        );
      })}

      <g transform={`translate(${VAULT.x - 70} ${VAULT.y - 92})`}>
        <foreignObject width="140" height="175">
          <div className="flex h-full flex-col items-center justify-start">
            <Krypto className="h-28 w-24" mood={nodes.some((n) => n.state === 'down') ? 'alert' : 'calm'} />
          </div>
        </foreignObject>
      </g>
      <text x={VAULT.x} y={VAULT.y + 105} fill="#dfe7ee" fontSize="16" fontFamily="Chakra Petch" fontWeight="700" textAnchor="middle">
        {t('map.volume')}
      </text>
      <text x={VAULT.x} y={VAULT.y + 125} fill="#7d8d9c" fontSize="12" fontFamily="Nunito" textAnchor="middle">
        {t('map.volumeSub')}
      </text>
    </svg>
    {/* Phones: the map's text would be too small to read, so list the servers. */}
    <ul className="space-y-2 sm:hidden">
      {nodes.map((n) => {
        const color = STATE_COLOR[n.state] ?? STATE_COLOR.unknown;
        return (
          <li key={n.id} className="flex items-center gap-3 rounded-lg border border-rule bg-deck px-4 py-3">
            <span className="h-2.5 w-2.5 shrink-0 rounded-full" style={{ background: color }} />
            <span className="font-display font-bold">{t('map.server', { n: n.id })}</span>
            <span className="text-sm font-bold" style={{ color }}>{t(`state.${n.state}`)}</span>
            <span className="ml-auto text-right text-sm text-mist">
              {t('map.blocks', { n: (objects[n.id] ?? 0).toLocaleString() })}
            </span>
          </li>
        );
      })}
    </ul>
    </>
  );
}
