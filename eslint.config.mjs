import js from '@eslint/js';
import tseslint from '@typescript-eslint/eslint-plugin';
import tsparser from '@typescript-eslint/parser';

export default [
  { ignores: ['**/dist/**', '**/node_modules/**', '.nx/**', 'libs/db/src/generated/**', '**/__fixtures__/**'] },
  js.configs.recommended,
  {
    files: ['**/*.{ts,tsx}'],
    languageOptions: {
      parser: tsparser,
      parserOptions: { ecmaVersion: 2023, sourceType: 'module', ecmaFeatures: { jsx: true } },
    },
    plugins: { '@typescript-eslint': tseslint },
    rules: {
      ...tseslint.configs.recommended.rules,
      // TypeScript already resolves every identifier; no-undef only produces
      // false positives on node globals and type-only names.
      'no-undef': 'off',
      // Contracts intentionally declare `const X = z.object(...)` alongside
      // `type X = z.infer<typeof X>`. Values and types live in separate
      // declaration spaces, and tsc already rejects a genuine redeclaration.
      'no-redeclare': 'off',
      '@typescript-eslint/no-redeclare': 'off',
      '@typescript-eslint/no-explicit-any': 'warn',
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
      'no-console': ['warn', { allow: ['warn', 'error'] }],
    },
  },
  {
    // Build tooling and seeds run in Node and print to stdout on purpose.
    files: ['tools/**/*.mjs', '*.config.ts', 'libs/db/prisma/seed.ts'],
    rules: { 'no-undef': 'off', 'no-console': 'off' },
  },
];
