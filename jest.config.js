/** @type {import('jest').Config} */
export default {
    testMatch: [
        '**/test/test-unit-*.js',
        '**/test/test-unit-*.cjs',
        '**/test/test-integration-*.js',
        '**/test/test-e2e-*.js',
    ],
    collectCoverageFrom: [
        'lib/**/*.js',
        'lib/**/*.cjs',
    ],
    testTimeout: 10000,
    verbose: true,
};
