import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { defineConfig } from 'vitest/config';

// libsodium-wrappers-sumo ships an ESM entry (`libsodium-wrappers.mjs`) that
// re-imports a sibling `libsodium-sumo.mjs` which is absent from the published
// ESM build; only the CommonJS build (`modules-sumo/libsodium-wrappers.js`) is
// self-contained. Under Node/Vitest we point the module at that working CJS
// entry so the WASM core loads. This is a TEST-ENV shim only: real app bundlers
// (the PWA's / antibody's Vite) optimise the dep with their own pipeline.
// The package's `exports` map blocks every deep subpath (even ./package.json),
// so we can't `require.resolve` into it. Point straight at the CJS entry under
// this project's node_modules — it is self-contained and loads the WASM core.
const here = dirname(fileURLToPath(import.meta.url));
const sumoCjs = join(
  here,
  'node_modules',
  'libsodium-wrappers-sumo',
  'dist',
  'modules-sumo',
  'libsodium-wrappers.js',
);

export default defineConfig({
  resolve: {
    alias: { 'libsodium-wrappers-sumo': sumoCjs },
  },
});
