// Reads and writes per second over the last minute (Chart.js), with the
// current throughput, wait times and cache figures beside it.

import {
  CategoryScale, Chart as ChartJS, Filler, LinearScale, LineElement, PointElement, Tooltip,
} from 'chart.js';
import { Line } from 'react-chartjs-2';

import { useI18n } from '../i18n/index.jsx';
import { bytes, latency, rate } from '../lib/format.js';
import { useAdvanced } from './Learn.jsx';

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Filler, Tooltip);

function Figure({ label, value, sub, tone = 'text-bone' }) {
  return (
    <div className="min-w-0">
      <div className="text-xs text-mist">{label}</div>
      <div className={`num font-display text-2xl font-bold leading-tight ${tone}`}>{value}</div>
      {sub && <div className="num text-xs text-mist">{sub}</div>}
    </div>
  );
}

export default function IoPanel({ history, rates, snapshot }) {
  const { t } = useI18n();
  const advanced = useAdvanced();
  const cache = snapshot?.cache ?? {};
  const lookups = (cache.hits ?? 0) + (cache.misses ?? 0);
  const hitPct = lookups ? (100 * (cache.hits ?? 0)) / lookups : 0;
  const usedPct = cache.frames ? Math.round((100 * (cache.used ?? 0)) / cache.frames) : 0;

  const data = {
    labels: history.map((p) => p.t),
    datasets: [
      { label: t('io.reads'), data: history.map((p) => p.readIops), borderColor: '#39ff14',
        backgroundColor: 'rgba(57,255,20,.08)', fill: true, tension: 0.35, pointRadius: 0, borderWidth: 2 },
      { label: t('io.writes'), data: history.map((p) => p.writeIops), borderColor: '#00e5ff',
        backgroundColor: 'rgba(0,229,255,.08)', fill: true, tension: 0.35, pointRadius: 0, borderWidth: 2 },
    ],
  };
  const options = {
    animation: false,
    maintainAspectRatio: false,
    interaction: { mode: 'index', intersect: false },
    plugins: { legend: { display: false },
      tooltip: { callbacks: { title: () => '', label: (c) => `${c.dataset.label}: ${rate(c.parsed.y)} / s` } } },
    scales: {
      x: { display: false },
      y: { beginAtZero: true, grid: { color: '#1a2631' }, border: { display: false },
        ticks: { color: '#7d8d9c', maxTicksLimit: 4, font: { family: 'JetBrains Mono', size: 11 } } },
    },
  };

  return (
    <div className="grid gap-5 lg:grid-cols-[1fr_15rem]">
      <div className="relative h-48 min-w-0">
        <Line data={data} options={options} aria-label={t('io.title')} role="img" />
      </div>
      <div className="grid grid-cols-2 content-start gap-4">
        <Figure label={`${t('io.reads')} · ${t('io.perSecond')}`} value={rate(rates?.readIops)} tone="text-neon"
                sub={`${bytes(rates?.readBps)}/s`} />
        <Figure label={`${t('io.writes')} · ${t('io.perSecond')}`} value={rate(rates?.writeIops)} tone="text-cyan"
                sub={`${bytes(rates?.writeBps)}/s`} />
        <Figure label={t('io.latency')} value={latency(rates?.readLat)}
                sub={advanced ? `${t('io.latencyMax')} ${latency(Math.max(rates?.readLatMax ?? 0, rates?.writeLatMax ?? 0))}` : null} />
        <Figure label={t('io.cache')} value={`${hitPct.toFixed(1)}%`}
                tone={hitPct >= 90 || !lookups ? 'text-bone' : 'text-coral'} />
      </div>
      {advanced && (
        <p className="num text-xs text-mist lg:col-span-2">
          {t('io.cacheUsed', { pct: usedPct, dirty: (cache.dirty ?? 0).toLocaleString() })}
          {' · '}write {latency(rates?.writeLat)} · {(cache.evictions ?? 0).toLocaleString()} evictions
          {rates?.errors ? <span className="text-coral"> · {t('io.errors', { n: rates.errors })}</span> : null}
        </p>
      )}
    </div>
  );
}
