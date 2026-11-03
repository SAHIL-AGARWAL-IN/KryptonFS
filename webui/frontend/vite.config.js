import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

// `npm run dev` serves the UI with hot reload and forwards the API and the
// live telemetry socket to the console server (python -m kryptonfs_web serve).
const target = process.env.KFS_CONSOLE ?? 'http://127.0.0.1:8080';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': { target, changeOrigin: false },
      '/ws': { target: target.replace(/^http/, 'ws'), ws: true },
    },
  },
  build: { outDir: 'dist', emptyOutDir: true, chunkSizeWarningLimit: 900 },
  test: { environment: 'node' },
});
