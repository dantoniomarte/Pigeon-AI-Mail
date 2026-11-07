import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// `base: './'` keeps asset URLs relative, so the built `dist/` can be served
// from any path (the API serves it from /usr/local/share/pigeon/web).
export default defineConfig({
  base: './',
  plugins: [react()],
  build: {
    outDir: 'dist',
    target: 'es2020',
    sourcemap: false,
    assetsInlineLimit: 4096,
  },
});
