import assert from 'node:assert/strict';
import { extractClientCertificateFromLambdaEvent } from '../lib/lambda.js';
import { generateClientCertificate } from './test-helpers.js';

describe('extractClientCertificateFromLambdaEvent', () => {
  let testPem;

  beforeAll(async () => {
    const testCert = await generateClientCertificate('lambda.example.com');
    testPem = testCert.cert;
  });

  describe('v2 payload (HTTP API)', () => {
    it('should extract certificate from event.requestContext.authentication.clientCert', () => {
      const event = {
        requestContext: {
          authentication: {
            clientCert: {
              clientCertPem: testPem,
              subjectDN: 'CN=lambda.example.com',
              issuerDN: 'CN=lambda.example.com',
              serialNumber: '01',
              validity: { notBefore: '...', notAfter: '...' },
            },
          },
        },
      };

      const result = extractClientCertificateFromLambdaEvent(event);

      assert.strictEqual(result.success, true);
      assert.ok(result.certificate);
      assert.strictEqual(result.certificate.subject.CN, 'lambda.example.com');
      assert.strictEqual(result.reason, null);
    });
  });

  describe('v1 payload (REST API)', () => {
    it('should extract certificate from event.requestContext.identity.clientCert', () => {
      const event = {
        requestContext: {
          identity: {
            clientCert: {
              clientCertPem: testPem,
            },
          },
        },
      };

      const result = extractClientCertificateFromLambdaEvent(event);

      assert.strictEqual(result.success, true);
      assert.ok(result.certificate);
      assert.strictEqual(result.certificate.subject.CN, 'lambda.example.com');
      assert.strictEqual(result.reason, null);
    });
  });

  describe('v2 takes precedence over v1', () => {
    it('should prefer v2 path when both v1 and v2 client certs are present', async () => {
      const v1Cert = await generateClientCertificate('v1.example.com');
      const v2Cert = await generateClientCertificate('v2.example.com');

      const event = {
        requestContext: {
          authentication: {
            clientCert: { clientCertPem: v2Cert.cert },
          },
          identity: {
            clientCert: { clientCertPem: v1Cert.cert },
          },
        },
      };

      const result = extractClientCertificateFromLambdaEvent(event);

      assert.strictEqual(result.success, true);
      assert.strictEqual(result.certificate.subject.CN, 'v2.example.com');
    });
  });

  describe('missing fields', () => {
    it('should return error reason when requestContext is missing', () => {
      const result = extractClientCertificateFromLambdaEvent({});
      assert.strictEqual(result.success, false);
      assert.strictEqual(result.certificate, null);
      assert.strictEqual(result.reason, 'lambda_event_missing_clientcert');
    });

    it('should return error reason when authentication and identity are both absent', () => {
      const result = extractClientCertificateFromLambdaEvent({
        requestContext: {},
      });
      assert.strictEqual(result.success, false);
      assert.strictEqual(result.reason, 'lambda_event_missing_clientcert');
    });

    it('should return error reason when clientCert is missing under authentication', () => {
      const result = extractClientCertificateFromLambdaEvent({
        requestContext: { authentication: {} },
      });
      assert.strictEqual(result.success, false);
      assert.strictEqual(result.reason, 'lambda_event_missing_clientcert');
    });

    it('should return error reason when clientCert is missing under identity', () => {
      const result = extractClientCertificateFromLambdaEvent({
        requestContext: { identity: {} },
      });
      assert.strictEqual(result.success, false);
      assert.strictEqual(result.reason, 'lambda_event_missing_clientcert');
    });

    it('should return error reason when clientCertPem field is missing', () => {
      const result = extractClientCertificateFromLambdaEvent({
        requestContext: {
          authentication: {
            clientCert: { subjectDN: 'CN=somebody' },
          },
        },
      });
      assert.strictEqual(result.success, false);
      assert.strictEqual(result.reason, 'lambda_event_missing_clientcert');
    });

    it('should accept null event without throwing', () => {
      const result = extractClientCertificateFromLambdaEvent(null);
      assert.strictEqual(result.success, false);
      assert.strictEqual(result.reason, 'lambda_event_missing_clientcert');
    });

    it('should accept undefined event without throwing', () => {
      const result = extractClientCertificateFromLambdaEvent(undefined);
      assert.strictEqual(result.success, false);
      assert.strictEqual(result.reason, 'lambda_event_missing_clientcert');
    });
  });

  describe('malformed clientCertPem', () => {
    it('should return malformed reason when clientCertPem is not parseable', () => {
      const event = {
        requestContext: {
          authentication: {
            clientCert: { clientCertPem: 'not a real pem certificate' },
          },
        },
      };

      const result = extractClientCertificateFromLambdaEvent(event);

      assert.strictEqual(result.success, false);
      assert.strictEqual(result.certificate, null);
      assert.strictEqual(result.reason, 'lambda_event_clientcert_malformed');
    });

    it('should return malformed reason for empty string clientCertPem', () => {
      const event = {
        requestContext: {
          authentication: {
            clientCert: { clientCertPem: '' },
          },
        },
      };

      const result = extractClientCertificateFromLambdaEvent(event);

      // Empty string is falsy, treated as missing (not malformed).
      assert.strictEqual(result.success, false);
      assert.strictEqual(result.reason, 'lambda_event_missing_clientcert');
    });
  });
});
