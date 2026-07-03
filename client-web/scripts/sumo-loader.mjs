// An ESM resolve hook that redirects the bare `libsodium-wrappers-sumo` import to
// the package's self-contained CommonJS build. The published ESM entry re-imports
// a sibling `libsodium-sumo.mjs` that is missing from the build, so plain Node
// ESM can't load it; the CJS build works. Used only by the vector generator (and
// mirrors what vitest.config.ts does via a Vite alias).
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const sumoCjs = join(
  here,
  '..',
  'node_modules',
  'libsodium-wrappers-sumo',
  'dist',
  'modules-sumo',
  'libsodium-wrappers.js',
);

export function resolve(specifier, context, next) {
  if (specifier === 'libsodium-wrappers-sumo') {
    return { url: pathToFileURL(sumoCjs).href, shortCircuit: true };
  }
  return next(specifier, context);
}
