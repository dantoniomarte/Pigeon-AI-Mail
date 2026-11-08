import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

// Tests run in jsdom so component-level assertions (labels, aria-live,
// indeterminate checkboxes) work exactly as they do in the browser.
export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    globals: true,
    include: ['src/**/*.test.{ts,tsx}'],
    setupFiles: ['./src/test/setup.ts'],
  },
});
