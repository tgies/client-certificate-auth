/*!
 * client-certificate-auth/lambda - CommonJS unit tests
 */

'use strict';

const assert = require('node:assert/strict');
const lambda = require('../lib/lambda.cjs');

describe('lambda (CommonJS wrapper)', () => {
    it('should expose only a load() function', () => {
        const keys = Object.keys(lambda);
        assert.deepEqual(keys, ['load']);
        assert.equal(typeof lambda.load, 'function');
    });

    it('should return cached module on subsequent calls', async () => {
        const first = await lambda.load();
        const second = await lambda.load();
        assert.strictEqual(first, second);
    });

    it('should export the extractClientCertificateFromLambdaEvent function', async () => {
        const mod = await lambda.load();
        assert.equal(
            typeof mod.extractClientCertificateFromLambdaEvent,
            'function',
            'extractClientCertificateFromLambdaEvent should be a function'
        );
    });

    it('should extract a certificate from a v2.0 API Gateway event', async () => {
        const selfsigned = require('selfsigned');
        const testCert = await selfsigned.generate(
            [{ name: 'commonName', value: 'CJS Lambda Test' }],
            { algorithm: 'sha256', keySize: 2048, days: 1 }
        );

        const { extractClientCertificateFromLambdaEvent } = await lambda.load();
        const result = extractClientCertificateFromLambdaEvent({
            requestContext: {
                authentication: {
                    clientCert: { clientCertPem: testCert.cert },
                },
            },
        });

        assert.equal(result.success, true);
        assert.equal(result.certificate.subject.CN, 'CJS Lambda Test');
    });

    it('should report lambda_event_missing_clientcert when no cert is in the event', async () => {
        const { extractClientCertificateFromLambdaEvent } = await lambda.load();
        const result = extractClientCertificateFromLambdaEvent({});
        assert.equal(result.success, false);
        assert.equal(result.reason, 'lambda_event_missing_clientcert');
    });
});
