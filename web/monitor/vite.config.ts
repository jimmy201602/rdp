import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// `npm run dev` proxies the API to an rdpgw started with -monitor 127.0.0.1:8090.
const backend = process.env.RDPGW_MONITOR ?? 'http://127.0.0.1:8090';

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': { target: backend, ws: true, changeOrigin: true },
    },
  },
  build: { chunkSizeWarningLimit: 1500 },
});
