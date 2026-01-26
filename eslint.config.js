import js from '@eslint/js';
import globals from 'globals';

export default [
    js.configs.recommended,
    {
        languageOptions: {
            ecmaVersion: 2022,
            sourceType: 'module',
            globals: {
                ...globals.node
            }
        },
        rules: {
            'no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
            'no-console': 'off',
            'eqeqeq': ['error', 'always'],
            'curly': ['error', 'all'],
            'semi': ['error', 'always'],
            'quotes': ['error', 'single', { avoidEscape: true }]
        }
    },
    {
        // Test files can use both Node and Jest globals
        files: ['test/**/*.js', 'test/**/*.cjs'],
        languageOptions: {
            globals: {
                ...globals.node,
                ...globals.jest
            }
        }
    },
    {
        ignores: ['node_modules/**', 'lib/**/*.cjs', 'lib/**/*.d.ts', 'lib/**/*.d.cts', '.stryker-tmp/**']
    }
];
