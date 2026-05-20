/*!
 * client-certificate-auth/fetch - CommonJS unit tests
 */

'use strict';

const assert = require('node:assert/strict');
const fetchAdapter = require('../lib/fetch.cjs');

describe('fetch (CommonJS wrapper)', () => {
    it('should expose only a load() function', () => {
        const keys = Object.keys(fetchAdapter);
        assert.deepEqual(keys, ['load']);
        assert.equal(typeof fetchAdapter.load, 'function');
    });

    it('should return cached module on subsequent calls', async () => {
        const first = await fetchAdapter.load();
        const second = await fetchAdapter.load();
        assert.strictEqual(first, second);
    });

    it('should export the extractClientCertificateFromRequest function', async () => {
        const mod = await fetchAdapter.load();
        assert.equal(
            typeof mod.extractClientCertificateFromRequest,
            'function',
            'extractClientCertificateFromRequest should be a function'
        );
    });

    it('should extract a certificate from a Web Request', async () => {
        const selfsigned = require('selfsigned');
        const testCert = await selfsigned.generate(
            [{ name: 'commonName', value: 'CJS Fetch Test' }],
            { algorithm: 'sha256', keySize: 2048, days: 1 }
        );

        // Convert PEM body (no delimiters) to base64 DER, then to Azure App
        // Service shape: bare base64-DER carried in X-ARR-ClientCert.
        const base64Der = testCert.cert
            .split('\n')
            .filter(line => !line.startsWith('-----'))
            .join('');

        const { extractClientCertificateFromRequest } = await fetchAdapter.load();
        const request = new Request('https://example.com', {
            headers: { 'X-ARR-ClientCert': base64Der },
        });

        const result = extractClientCertificateFromRequest(request, {
            certificateSource: 'azure-app-service',
        });

        assert.equal(result.success, true);
        assert.equal(result.certificate.subject.CN, 'CJS Fetch Test');
    });
});
