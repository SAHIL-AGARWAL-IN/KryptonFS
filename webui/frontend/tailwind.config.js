/** Palette from the KryptonFS spec: matte black, electric cyan, neon green,
 *  muted coral. Surfaces are a cool, slightly blue-biased black so the cyan
 *  reads as light coming out of the dark rather than a sticker on top. */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        ink: '#07090c',      // page ground
        deck: '#0c1117',     // raised surfaces
        rule: '#1a2631',     // hairlines, empty tracks
        mist: '#7d8d9c',     // secondary text
        bone: '#dfe7ee',     // primary text
        cyan: { DEFAULT: '#00e5ff', dim: '#0f5d6b', deep: '#0b2329' },
        neon: { DEFAULT: '#39ff14', dim: '#1f6b12' },
        coral: { DEFAULT: '#ff6f61', dim: '#5a2622' },
      },
      fontFamily: {
        display: ['"Chakra Petch"', '"Noto Sans Devanagari"', 'system-ui', 'sans-serif'],
        body: ['Nunito', '"Noto Sans Devanagari"', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'Consolas', 'monospace'],
      },
      keyframes: {
        pulse_travel: { '0%': { offsetDistance: '0%', opacity: 0 }, '10%,90%': { opacity: 1 },
          '100%': { offsetDistance: '100%', opacity: 0 } },
      },
    },
  },
  plugins: [],
};
