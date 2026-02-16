/*!
 * client-certificate-auth/extractor - CommonJS unit tests
 */

'use strict';

const assert = require('node:assert/strict');
const extractor = require('../lib/extractor.cjs');

describe('extractor (CommonJS wrapper)', () => {
    it('should expose only a load() function', () => {
        const keys = Object.keys(extractor);
        assert.deepEqual(keys, ['load']);
        assert.equal(typeof extractor.load, 'function');
    });

    it('should return cached module on subsequent calls', async () => {
        const first = await extractor.load();
        const second = await extractor.load();
        assert.strictEqual(first, second);
    });

    it('should export the extractClientCertificate function', async () => {
        const mod = await extractor.load();
        assert.equal(
            typeof mod.extractClientCertificate,
            'function',
            'extractClientCertificate should be a function'
        );
    });

    it('should extract a certificate from a socket-based request', async () => {
        const { extractClientCertificate } = await extractor.load();

        const mockReq = {
            headers: {},
            socket: {
                authorized: true,
                getPeerCertificate: () => ({
                    subject: { CN: 'CJS Extractor Test' },
                    issuer: { CN: 'Test CA' },
                    fingerprint: 'AA:BB:CC:DD:EE:FF',
                }),
            },
        };

        const result = extractClientCertificate(mockReq);
        assert.equal(result.success, true);
        assert.equal(result.certificate.subject.CN, 'CJS Extractor Test');
        assert.equal(result.reason, null);
    });
});
