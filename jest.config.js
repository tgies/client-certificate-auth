/** @type {import('jest').Config} */
export default {
    testMatch: [
        '**/test/test-unit-*.js',
        '**/test/test-unit-*.cjs',
        '**/test/test-integration-*.js',
    ],
    testTimeout: 10000,
    verbose: true,
};
