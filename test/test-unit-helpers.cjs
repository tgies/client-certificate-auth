/*!
 * client-certificate-auth/helpers - CommonJS unit tests
 */

'use strict';

const assert = require('node:assert/strict');
const helpers = require('../lib/helpers.cjs');

describe('helpers (CommonJS wrapper)', () => {
    it('should expose only a load() function', () => {
        const keys = Object.keys(helpers);
        assert.deepEqual(keys, ['load']);
        assert.equal(typeof helpers.load, 'function');
    });

    it('should return cached module on subsequent calls', async () => {
        const first = await helpers.load();
        const second = await helpers.load();
        assert.strictEqual(first, second);
    });

    it('should export all expected helper functions', async () => {
        const mod = await helpers.load();
        const expectedFunctions = [
            'allowCN',
            'allowFingerprints',
            'allowIssuer',
            'allowSubject',
            'allowOU',
            'allowOrganization',
            'allowSerial',
            'allowSAN',
            'allowEmail',
            'allOf',
            'anyOf',
        ];

        for (const name of expectedFunctions) {
            assert.equal(typeof mod[name], 'function', `${name} should be a function`);
        }
    });

    it('should produce a working allowCN callback', async () => {
        const { allowCN } = await helpers.load();
        const validator = allowCN(['admin', 'service-a']);

        assert.equal(validator({ subject: { CN: 'admin' } }), true);
        assert.equal(validator({ subject: { CN: 'intruder' } }), false);
    });
});
