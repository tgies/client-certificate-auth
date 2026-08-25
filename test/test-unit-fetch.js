import assert from 'node:assert/strict';
import { extractClientCertificateFromRequest } from '../lib/fetch.js';
import { generateClientCertificate, pemToDer } from './test-helpers.js';

/**
 * Encode a DER buffer as RFC 9440 single-cert header value: `:base64:`.
 */
function encodeAsRfc9440(derBuffer) {
  return ':' + derBuffer.toString('base64') + ':';
}

describe('extractClientCertificateFromRequest', () => {
  let testPem;
  let testDer;

  beforeAll(async () => {
    const testCert = await generateClientCertificate('fetch.example.com');
    testPem = testCert.cert;
    testDer = pemToDer(testPem);
  });

  describe('default options', () => {
    it('should accept a request without an options argument', () => {
      const request = new Request('https://example.com/api', {
        headers: {},
      });
      const result = extractClientCertificateFromRequest(request);

      // No headers configured, no socket: the extractor falls through to the
      // socket path and reports `socket_not_authorized` since the synthetic
      // req object has no socket field.
      assert.strictEqual(result.success, false);
      assert.strictEqual(result.reason, 'socket_not_authorized');
    });

    it('should strip fallbackToSocket so missing headers report header_missing_or_malformed', () => {
      // fallbackToSocket is stripped; there is no socket to fall back to.
      const request = new Request('https://example.com/api', {
        headers: { 'X-Other-Header': 'unrelated' },
      });

      const result = extractClientCertificateFromRequest(request, {
        certificateSource: 'cloudflare-rfc9440',
        fallbackToSocket: true,
      });

      assert.strictEqual(result.success, false);
      assert.strictEqual(result.reason, 'header_missing_or_malformed');
    });
  });

  describe('with Web Request', () => {
    it('should extract certificate via cloudflare-rfc9440 preset from a Web Request', () => {
      const request = new Request('https://example.com/api', {
        headers: { 'Client-Cert': encodeAsRfc9440(testDer) },
      });

      const result = extractClientCertificateFromRequest(request, {
        certificateSource: 'cloudflare-rfc9440',
      });

      assert.strictEqual(result.success, true);
      assert.ok(result.certificate);
      assert.strictEqual(result.certificate.subject.CN, 'fetch.example.com');
    });

    it('should extract certificate via azure-app-service preset from a Web Request', () => {
      const request = new Request('https://example.com/api', {
        headers: { 'X-ARR-ClientCert': testDer.toString('base64') },
      });

      const result = extractClientCertificateFromRequest(request, {
        certificateSource: 'azure-app-service',
      });

      assert.strictEqual(result.success, true);
      assert.ok(result.certificate);
      assert.strictEqual(result.certificate.subject.CN, 'fetch.example.com');
    });

    it('should extract certificate via aws-alb preset from a Web Request', () => {
      const request = new Request('https://example.com/api', {
        headers: { 'X-Amzn-Mtls-Clientcert': encodeURIComponent(testPem) },
      });

      const result = extractClientCertificateFromRequest(request, {
        certificateSource: 'aws-alb',
      });

      assert.strictEqual(result.success, true);
      assert.ok(result.certificate);
      assert.strictEqual(result.certificate.subject.CN, 'fetch.example.com');
    });

    it('should return error when configured header is missing from the Request', () => {
      const request = new Request('https://example.com/api', {
        headers: { 'X-Other-Header': 'unrelated' },
      });

      const result = extractClientCertificateFromRequest(request, {
        certificateSource: 'cloudflare-rfc9440',
      });

      assert.strictEqual(result.success, false);
      assert.strictEqual(result.reason, 'header_missing_or_malformed');
    });

    it('should return error when configured header carries malformed data', () => {
      const request = new Request('https://example.com/api', {
        headers: { 'Client-Cert': 'not-a-real-cert' },
      });

      const result = extractClientCertificateFromRequest(request, {
        certificateSource: 'cloudflare-rfc9440',
      });

      assert.strictEqual(result.success, false);
      assert.strictEqual(result.reason, 'header_missing_or_malformed');
    });
  });

  describe('verifyHeader / verifyValue', () => {
    it('should accept the request when verifyHeader matches verifyValue', () => {
      const request = new Request('https://example.com/api', {
        headers: {
          'Client-Cert': encodeAsRfc9440(testDer),
          'X-SSL-Verify': 'SUCCESS',
        },
      });

      const result = extractClientCertificateFromRequest(request, {
        certificateSource: 'cloudflare-rfc9440',
        verifyHeader: 'X-SSL-Verify',
        verifyValue: 'SUCCESS',
      });

      assert.strictEqual(result.success, true);
      assert.strictEqual(result.certificate.subject.CN, 'fetch.example.com');
    });

    it('should reject the request when verifyHeader does not match verifyValue', () => {
      const request = new Request('https://example.com/api', {
        headers: {
          'Client-Cert': encodeAsRfc9440(testDer),
          'X-SSL-Verify': 'FAILED:cert_expired',
        },
      });

      const result = extractClientCertificateFromRequest(request, {
        certificateSource: 'cloudflare-rfc9440',
        verifyHeader: 'X-SSL-Verify',
        verifyValue: 'SUCCESS',
      });

      assert.strictEqual(result.success, false);
      assert.strictEqual(result.reason, 'verification_header_mismatch');
    });
  });

  describe('chain extraction', () => {
    it('should link Client-Cert-Chain when present and includeChain is true', async () => {
      const selfsigned = (await import('selfsigned')).default;
      const intermediate = await selfsigned.generate(
        [{ name: 'commonName', value: 'Fetch Intermediate CA' }],
        { algorithm: 'sha256', keySize: 2048, days: 1 }
      );
      const intermediateDer = pemToDer(intermediate.cert);

      const request = new Request('https://example.com/api', {
        headers: {
          'Client-Cert': encodeAsRfc9440(testDer),
          'Client-Cert-Chain': encodeAsRfc9440(intermediateDer),
        },
      });

      const result = extractClientCertificateFromRequest(request, {
        certificateSource: 'cloudflare-rfc9440',
        includeChain: true,
      });

      assert.strictEqual(result.success, true);
      assert.ok(result.certificate.issuerCertificate);
      assert.strictEqual(
        result.certificate.issuerCertificate.subject.CN,
        'Fetch Intermediate CA'
      );
    });
  });

  describe('with plain header-iterable object (non-Request)', () => {
    it('should accept a plain object whose headers field iterates [name, value] tuples', () => {
      const headers = new Map([
        ['client-cert', encodeAsRfc9440(testDer)],
      ]);

      const result = extractClientCertificateFromRequest({ headers }, {
        certificateSource: 'cloudflare-rfc9440',
      });

      assert.strictEqual(result.success, true);
      assert.strictEqual(result.certificate.subject.CN, 'fetch.example.com');
    });

    it('should accept a Headers instance built without a Request', () => {
      const headers = new Headers();
      headers.set('client-cert', encodeAsRfc9440(testDer));

      const result = extractClientCertificateFromRequest({ headers }, {
        certificateSource: 'cloudflare-rfc9440',
      });

      assert.strictEqual(result.success, true);
      assert.strictEqual(result.certificate.subject.CN, 'fetch.example.com');
    });

    it('should not be affected by Object.prototype properties when a header name collides', () => {
      // `__proto__` will exist as a magic setter if the headers object isn't
      // defined as a bare dictionary (i.e. via `Object.create(null)`), causing
      // this to fail. The asserted behavior is that setting a property called
      // `__proto__` just creates a string-valued property called `__proto__`.
      const headers = new Map([
        ['__proto__', encodeAsRfc9440(testDer)],
      ]);

      const result = extractClientCertificateFromRequest({ headers }, {
        certificateHeader: '__proto__',
        headerEncoding: 'rfc9440',
      });

      assert.strictEqual(result.success, true);
      assert.strictEqual(result.certificate.subject.CN, 'fetch.example.com');
    });

    it('should normalize header names to lowercase for the RequestLike Map path', () => {
      // Map preserves casing; mixed-case keys need lowercasing.
      const headers = new Map([
        ['X-ARR-ClientCert', testDer.toString('base64')],
      ]);

      const result = extractClientCertificateFromRequest({ headers }, {
        certificateSource: 'azure-app-service',
      });

      assert.strictEqual(result.success, true);
      assert.strictEqual(result.certificate.subject.CN, 'fetch.example.com');
    });

    it('should ignore malformed tuples so they do not overwrite a valid value', () => {
      for (const malformed of [['client-cert'], ['client-cert', 42], ['client-cert', 'x', 'y']]) {
        const headers = [
          ['client-cert', encodeAsRfc9440(testDer)],
          malformed,
        ];
        const result = extractClientCertificateFromRequest({ headers }, {
          certificateSource: 'cloudflare-rfc9440',
        });
        assert.strictEqual(result.success, true);
        assert.strictEqual(result.certificate.subject.CN, 'fetch.example.com');
      }
    });

    it('should report a failure when the headers iterator throws mid-iteration', () => {
      const throwing = {
        *[Symbol.iterator]() {
          yield ['client-cert', encodeAsRfc9440(testDer)];
          throw new Error('iterator blew up');
        },
      };
      const result = extractClientCertificateFromRequest({ headers: throwing }, {
        certificateSource: 'cloudflare-rfc9440',
      });
      assert.strictEqual(result.success, false);
      assert.strictEqual(result.reason, 'header_missing_or_malformed');
    });

    it('should report a failure when the headers iterator violates the protocol', () => {
      const badProtocol = {
        [Symbol.iterator]() {
          return { next() { return 42; } };
        },
      };
      const result = extractClientCertificateFromRequest({ headers: badProtocol }, {
        certificateSource: 'cloudflare-rfc9440',
      });
      assert.strictEqual(result.success, false);
      assert.strictEqual(result.reason, 'header_missing_or_malformed');
    });

    it('should report a failure when reading request.headers throws', () => {
      const request = { get headers() { throw new Error('headers getter blew up'); } };
      const result = extractClientCertificateFromRequest(request, {
        certificateSource: 'cloudflare-rfc9440',
      });
      assert.strictEqual(result.success, false);
      assert.strictEqual(result.reason, 'header_missing_or_malformed');
    });

    it('should report a failure when the Symbol.iterator accessor throws', () => {
      const headers = {};
      Object.defineProperty(headers, Symbol.iterator, {
        get() { throw new Error('iterator getter blew up'); },
      });
      const result = extractClientCertificateFromRequest({ headers }, {
        certificateSource: 'cloudflare-rfc9440',
      });
      assert.strictEqual(result.success, false);
      assert.strictEqual(result.reason, 'header_missing_or_malformed');
    });
  });

  describe('without iterable headers', () => {
    const cases = [
      ['an undefined request', undefined],
      ['a request without headers', {}],
      ['null headers', { headers: null }],
      ['plain-object headers', { headers: { 'client-cert': 'value' } }],
    ];

    for (const [label, request] of cases) {
      it(`should report header_missing_or_malformed for ${label}`, () => {
        const result = extractClientCertificateFromRequest(request, {
          certificateSource: 'cloudflare-rfc9440',
        });

        assert.strictEqual(result.success, false);
        assert.strictEqual(result.certificate, null);
        assert.strictEqual(result.reason, 'header_missing_or_malformed');
      });
    }

    it('should skip entries that are not [name, value] tuples', () => {
      const headers = [
        'client-cert',
        [42, 'ignored'],
        ['client-cert', encodeAsRfc9440(testDer)],
      ];

      const result = extractClientCertificateFromRequest({ headers }, {
        certificateSource: 'cloudflare-rfc9440',
      });

      assert.strictEqual(result.success, true);
      assert.strictEqual(result.certificate.subject.CN, 'fetch.example.com');
    });
  });

  describe('header-only behavior', () => {
    it('should never access a socket field even if one is present on the request', () => {
      const headers = new Headers();
      headers.set('client-cert', encodeAsRfc9440(testDer));

      const trap = new Proxy({}, {
        get() {
          throw new Error('socket was unexpectedly accessed by the fetch adapter');
        },
      });

      const result = extractClientCertificateFromRequest(
        { headers, socket: trap },
        { certificateSource: 'cloudflare-rfc9440' }
      );

      assert.strictEqual(result.success, true);
    });
  });
});
