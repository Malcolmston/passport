import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { fileURLToPath } from 'node:url';

// The passport repo is served as a GitHub *project* page at
// https://malcolmston.github.io/passport/, so assets must be based under
// /passport/. The generated API reference is published alongside it under
// /passport/api/ (see .github/workflows/pages.yml).
export default defineConfig({
  base: '/passport/',
  plugins: [react()],
  resolve: {
    alias: {
      // Import the shared component library from the vendored `go` submodule.
      'go-ui': fileURLToPath(new URL('./vendor/go/ui/src/index.ts', import.meta.url)),
    },
  },
  build: { outDir: 'dist', emptyOutDir: true },
});
