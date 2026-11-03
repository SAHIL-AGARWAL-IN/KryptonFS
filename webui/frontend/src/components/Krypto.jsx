// Krypto, the KryptonFS mascot (same character as the explainer video).
// mood: 'calm' (cyan) | 'happy' (green) | 'alert' (coral)

const FACE = { calm: '#00e5ff', happy: '#39ff14', alert: '#ff6f61' };

export default function Krypto({ mood = 'calm', talking = false, className = '', title }) {
  const face = FACE[mood] ?? FACE.calm;
  return (
    <svg viewBox="0 0 120 150" className={`${talking ? 'k-talk' : ''} ${className}`}
         role={title ? 'img' : undefined} aria-label={title} aria-hidden={title ? undefined : true}>
      <line x1="60" y1="30" x2="60" y2="12" stroke="#00e5ff" strokeWidth="3" strokeLinecap="round" />
      <circle cx="60" cy="9" r="5" fill="#00e5ff" />
      <rect x="62" y="7" width="8" height="3" rx="1.5" fill="#00e5ff" />
      <rect x="4" y="66" width="12" height="30" rx="6" fill="#16222d" stroke="#00e5ff" strokeWidth="2" />
      <rect x="104" y="66" width="12" height="30" rx="6" fill="#16222d" stroke="#00e5ff" strokeWidth="2" />
      <rect x="12" y="30" width="96" height="100" rx="22" fill="#16222d" stroke="#00e5ff" strokeWidth="3" />
      <rect x="24" y="42" width="72" height="42" rx="12" fill="#04090d" stroke="#1f5966" strokeWidth="2" />
      <ellipse className="k-eye" cx="46" cy="60" rx="6" ry="7" fill={face} />
      <ellipse className="k-eye" cx="74" cy="60" rx="6" ry="7" fill={face} />
      <rect className="k-mouth" x="53" y="72" width="14" height="4" rx="2" fill={face} />
      <circle cx="60" cy="106" r="15" fill="#0b151c" stroke="#1f5966" strokeWidth="2" />
      <circle cx="60" cy="106" r="10" fill="none" stroke="#00e5ff" strokeWidth="2" strokeDasharray="2 3.2" />
      <line x1="60" y1="106" x2="60" y2="98" stroke="#39ff14" strokeWidth="2.5" strokeLinecap="round" />
      <rect x="30" y="128" width="20" height="14" rx="5" fill="#16222d" stroke="#00e5ff" strokeWidth="2" />
      <rect x="70" y="128" width="20" height="14" rx="5" fill="#16222d" stroke="#00e5ff" strokeWidth="2" />
    </svg>
  );
}
