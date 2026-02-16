/*!
 * client-certificate-auth/parsers - CommonJS unit tests
 */

'use strict';

const assert = require('node:assert/strict');
const parsers = require('../lib/parsers.cjs');

describe('parsers (CommonJS wrapper)', () => {
    it('should expose only a load() function', () => {
        const keys = Object.keys(parsers);
        assert.deepEqual(keys, ['load']);
        assert.equal(typeof parsers.load, 'function');
    });

    it('should return cached module on subsequent calls', async () => {
        const first = await parsers.load();
        const second = await parsers.load();
        assert.strictEqual(first, second);
    });

    it('should export all expected parser functions and constants', async () => {
        const mod = await parsers.load();
        const expectedFunctions = [
            'parseUrlPem',
            'parseUrlPemAws',
            'parseXfcc',
            'parseBase64Der',
            'parseRfc9440',
            'pemToCertificate',
            'derToCertificate',
            'parseHeaderValue',
            'getCertificateFromHeaders',
        ];

        for (const name of expectedFunctions) {
            assert.equal(typeof mod[name], 'function', `${name} should be a function`);
        }

        assert.equal(typeof mod.PRESETS, 'object', 'PRESETS should be an object');
    });

    it('should parse a URL-encoded PEM certificate via parseUrlPem', async () => {
        const selfsigned = require('selfsigned');
        const testCert = await selfsigned.generate(
            [{ name: 'commonName', value: 'CJS Parser Test' }],
            { algorithm: 'sha256', keySize: 2048, days: 1 }
        );

        const { parseUrlPem } = await parsers.load();
        const encoded = encodeURIComponent(testCert.cert);
        const cert = parseUrlPem(encoded);

        assert.ok(cert, 'should parse the certificate');
        assert.equal(cert.subject.CN, 'CJS Parser Test');
    });
});
