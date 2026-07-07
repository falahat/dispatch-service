// Flat ESLint config for the browser signer. Type-checked TypeScript rules, no
// framework plugins — this package is pure crypto with no DOM/JSX. It does use the
// Web Platform crypto globals (WebCrypto `crypto` + `btoa`/`TextEncoder`), which
// exist in every target browser and in Node 18+, so they are declared below.
import js from '@eslint/js';
import tseslint from '@typescript-eslint/eslint-plugin';
import tsparser from '@typescript-eslint/parser';

export default [
  // Build/tooling scripts + configs are Node-side and not part of the
  // type-checked, browser-targeted library sources.
  { ignores: ['dist/**', 'node_modules/**', 'scripts/**', '*.config.js', '*.config.ts'] },
  js.configs.recommended,
  {
    files: ['**/*.ts'],
    languageOptions: {
      globals: {
        crypto: 'readonly',
        btoa: 'readonly',
        TextEncoder: 'readonly',
      },
      parser: tsparser,
      parserOptions: {
        project: './tsconfig.json',
        tsconfigRootDir: import.meta.dirname,
      },
    },
    plugins: { '@typescript-eslint': tseslint },
    rules: {
      ...tseslint.configs.recommended.rules,
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/explicit-function-return-type': 'error',
    },
  },
];
