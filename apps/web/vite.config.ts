import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

/**
 * Dev server lives on 4200 so it does not collide with control-plane 3000–3007.
 * All API traffic is proxied to the gateway — the UI never talks to a service
 * port directly.
 */
export default defineConfig({
  plugins: [react()],
  server: {
    port: 4200,
    strictPort: true,
    proxy: {
      '/v1': 'http://127.0.0.1:3000',
      '/docs': 'http://127.0.0.1:3000',
      '/health': 'http://127.0.0.1:3000',
    },
  },
  preview: {
    port: 4200,
    strictPort: true,
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
});
