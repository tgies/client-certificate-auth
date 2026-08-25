import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { extractClientCertificate, validateExtractorOptions } from '../lib/extractor.js';
import { MAX_CHAIN_CERTS } from '../lib/parsers.js';
import { pemToDer } from './test-helpers.js';

/**
 * Encode a DER-encoded certificate as RFC 9440 single-cert header value:
 * `:base64:`. Cloudflare and other RFC 9440 implementations emit this on
 * the Client-Cert header.
 */
function encodeAsRfc9440(derBuffer) {
  return ':' + derBuffer.toString('base64') + ':';
}

/**
 * Encode a list of DER buffers as RFC 9440 structured-field list of
 * `:base64:` items, comma-separated. Used for Client-Cert-Chain.
 */
function encodeAsRfc9440List(derBuffers) {
  return derBuffers.map(encodeAsRfc9440).join(', ');
}

// Mock certificate for socket tests
const getMockPeerCertificate = () => ({
  subject: {
    C: 'US',
    ST: 'Texas',
    L: 'Waco',
    O: 'SHOE',
    OU: 'Upstairs',
    CN: 'Proctor Davenport'
  },
  issuer: {
    C: 'US',
    ST: 'Texas',
    L: 'Waco',
    O: 'SHOE',
    OU: 'Computers',
    CN: 'SHOE Computers Dept. of Very Big Prime Numbers'
  },
  valid_from: 'Jun 19 03:26:11 2004 GMT',
  valid_to: 'Jan 19 03:14:07 2038 GMT',
  fingerprint: 'BA:DA:DD:EA:DB:EE:FC:CC:CC:CC:07:15:19:88:C0:FF:EE:00:12:00'
});

describe('extractClientCertificate', () => {
  // Generate real certificate for header tests
  let testPem;

  beforeAll(async () => {
    const selfsigned = (await import('selfsigned')).default;
    const testCert = await selfsigned.generate(
      [{ name: 'commonName', value: 'client.example.com' }],
      {
        algorithm: 'sha256',
        keySize: 2048,
        days: 1,
        extensions: [
          { name: 'basicConstraints', cA: false, critical: true },
          { name: 'extKeyUsage', clientAuth: true },
        ],
      }
    );
    testPem = testCert.cert;
  });
  describe('option validation', () => {
    it('should throw if verifyHeader is set without verifyValue', () => {
      const req = { headers: {}, socket: { authorized: false } };
      assert.throws(
        () => extractClientCertificate(req, { verifyHeader: 'X-Verify' }),
        /verifyHeader and verifyValue must both be provided/
      );
    });

    it('should throw if verifyValue is set without verifyHeader', () => {
      const req = { headers: {}, socket: { authorized: false } };
      assert.throws(
        () => extractClientCertificate(req, { verifyValue: 'SUCCESS' }),
        /verifyHeader and verifyValue must both be provided/
      );
    });

    it('should not throw when both verifyHeader and verifyValue are set', () => {
      const req = { headers: {}, socket: { authorized: false } };
      assert.doesNotThrow(() =>
        extractClientCertificate(req, {
          certificateSource: 'aws-alb',
          verifyHeader: 'X-Verify',
          verifyValue: 'SUCCESS',
        })
      );
    });

    it('should throw when verifyHeader and verifyValue are set without a header source', () => {
      const req = { headers: {}, socket: { authorized: false } };
      assert.throws(
        () => extractClientCertificate(req, { verifyHeader: 'X-Verify', verifyValue: 'SUCCESS' }),
        { name: 'Error', message: /verifyHeader requires certificateSource or certificateHeader/ }
      );
    });

    it('should throw when verifyHeader or verifyValue is an empty string', () => {
      const req = { headers: {}, socket: { authorized: false } };
      assert.throws(
        () => extractClientCertificate(req, { certificateSource: 'aws-alb', verifyHeader: '', verifyValue: '' }),
        { name: 'Error', message: /verifyHeader must be a non-empty string/ }
      );
      assert.throws(
        () => extractClientCertificate(req, { certificateSource: 'aws-alb', verifyHeader: 'X-Verify', verifyValue: '' }),
        { name: 'Error', message: /verifyValue must be a non-empty string/ }
      );
    });

    it('should throw when a header-name option is not a string', () => {
      const req = { headers: {}, socket: { authorized: false } };
      for (const [option, value] of [['certificateHeader', 42], ['chainHeader', null], ['verifyHeader', ['X-Verify']]]) {
        assert.throws(
          () => extractClientCertificate(req, {
            certificateSource: 'aws-alb',
            verifyValue: option === 'verifyHeader' ? 'SUCCESS' : undefined,
            [option]: value,
          }),
          { name: 'Error', message: new RegExp(`${option} must be a non-empty string`) },
          `${option} should reject ${JSON.stringify(value)}`
        );
      }
    });

    it('should throw when certificateHeader or chainHeader is an empty string', () => {
      const req = { headers: {}, socket: { authorized: false } };
      assert.throws(
        () => extractClientCertificate(req, { certificateHeader: '', headerEncoding: 'url-pem' }),
        { name: 'Error', message: /certificateHeader must be a non-empty string/ }
      );
      assert.throws(
        () => extractClientCertificate(req, { certificateSource: 'aws-alb', chainHeader: '' }),
        { name: 'Error', message: /chainHeader must be a non-empty string/ }
      );
    });

    it('should throw when fallbackToSocket or includeChain is not a boolean', () => {
      const req = { headers: {}, socket: { authorized: false } };
      assert.throws(
        () => extractClientCertificate(req, { certificateSource: 'aws-alb', fallbackToSocket: 'false' }),
        { name: 'Error', message: /fallbackToSocket must be a boolean/ }
      );
      assert.throws(
        () => extractClientCertificate(req, { includeChain: 1 }),
        { name: 'Error', message: /includeChain must be a boolean/ }
      );
    });

    it('should throw when certificateSource or headerEncoding is an empty string', () => {
      const req = { headers: {}, socket: { authorized: false } };
      assert.throws(
        () => extractClientCertificate(req, { certificateSource: '' }),
        { name: 'Error', message: /unknown certificateSource ''/ }
      );
      assert.throws(
        () => extractClientCertificate(req, { certificateHeader: 'X-Cert', headerEncoding: '' }),
        { name: 'Error', message: /unknown headerEncoding ''/ }
      );
    });

    it('should not throw when neither verifyHeader nor verifyValue is set', () => {
      const req = { headers: {}, socket: { authorized: false } };
      assert.doesNotThrow(() => extractClientCertificate(req, {}));
    });

    it('should not throw when options argument is omitted entirely', () => {
      const req = { headers: {}, socket: { authorized: false } };
      assert.doesNotThrow(() => extractClientCertificate(req));
    });

    it('should throw when certificateSource is unknown', () => {
      const req = { headers: {}, socket: { authorized: false } };
      assert.throws(
        () => extractClientCertificate(req, { certificateSource: 'aws-alp' }),
        { name: 'Error', message: /unknown certificateSource 'aws-alp'/ }
      );
    });

    it('should throw when certificateSource is an inherited Object.prototype key', () => {
      const req = { headers: {}, socket: { authorized: false } };
      for (const key of ['toString', 'constructor', 'hasOwnProperty', '__proto__']) {
        assert.throws(
          () => extractClientCertificate(req, { certificateSource: key }),
          { name: 'Error', message: new RegExp(`unknown certificateSource '${key}'`) },
          `${key} should be rejected as an inherited prototype key`
        );
      }
    });

    it('should throw when headerEncoding is unknown', () => {
      const req = { headers: {}, socket: { authorized: false } };
      assert.throws(
        () => extractClientCertificate(req, {
          certificateHeader: 'X-Cert',
          headerEncoding: 'url-perm',
        }),
        { name: 'Error', message: /unknown headerEncoding 'url-perm'/ }
      );
    });

    it('should throw when certificateHeader is set without headerEncoding or preset', () => {
      const req = { headers: {}, socket: { authorized: false } };
      assert.throws(
        () => extractClientCertificate(req, { certificateHeader: 'X-Cert' }),
        { name: 'Error', message: /certificateHeader requires headerEncoding/ }
      );
    });

    it('should throw when chainHeader is set without a leaf header source', () => {
      const req = { headers: {}, socket: { authorized: false } };
      assert.throws(
        () => extractClientCertificate(req, { chainHeader: 'X-Cert-Chain' }),
        { name: 'Error', message: /chainHeader requires certificateSource or certificateHeader/ }
      );
    });

    it('should not throw when chainHeader is paired with certificateHeader and headerEncoding', () => {
      const req = { headers: {}, socket: { authorized: false } };
      assert.doesNotThrow(() =>
        extractClientCertificate(req, {
          certificateHeader: 'X-Cert',
          chainHeader: 'X-Cert-Chain',
          headerEncoding: 'rfc9440',
        })
      );
    });

    it('should not throw when chainHeader is paired with certificateSource', () => {
      const req = { headers: {}, socket: { authorized: false } };
      assert.doesNotThrow(() =>
        extractClientCertificate(req, {
          certificateSource: 'cloudflare-rfc9440',
          chainHeader: 'X-Custom-Chain',
        })
      );
    });

    it('should not throw when certificateHeader pairs with a preset (encoding from preset)', () => {
      const req = { headers: {}, socket: { authorized: false } };
      assert.doesNotThrow(() =>
        extractClientCertificate(req, {
          certificateSource: 'aws-alb',
          certificateHeader: 'X-Override',
        })
      );
    });

    it('should not throw when certificateSource alone is valid', () => {
      const req = { headers: {}, socket: { authorized: false } };
      assert.doesNotThrow(() =>
        extractClientCertificate(req, { certificateSource: 'envoy' })
      );
    });

    it('should not throw when validateExtractorOptions is called with no arguments', () => {
      assert.doesNotThrow(() => validateExtractorOptions());
    });

    it('should throw TypeError for a container that is not a plain object', () => {
      for (const value of [null, 'aws-alb', 42, true, [], ['aws-alb'], () => {}, Symbol('x')]) {
        assert.throws(
          () => validateExtractorOptions(/** @type {any} */ (value)),
          { name: 'TypeError', message: /options must be an object/ },
          `expected ${String(value)} to be rejected`
        );
      }
    });

    it('should reject a non-object container from extractClientCertificate', () => {
      assert.throws(
        () => extractClientCertificate({ headers: {} }, /** @type {any} */ ('aws-alb')),
        { name: 'TypeError', message: /options must be an object/ }
      );
    });
  });

  describe('unreadable request headers', () => {
    const cases = [
      ['an undefined req', undefined],
      ['a req without headers', {}],
      ['null headers', { headers: null }],
      ['string headers', { headers: 'x-amzn-mtls-clientcert=abc' }],
      ['a throwing headers accessor', { get headers() { throw new Error('accessor threw'); } }],
      ['a throwing certificate header accessor', {
        headers: { get 'x-amzn-mtls-clientcert'() { throw new Error('header trap'); } },
      }],
      ['headers whose keys cannot be enumerated', {
        headers: new Proxy({}, { ownKeys() { throw new Error('ownKeys threw'); } }),
      }],
      ['a throwing rawHeaders accessor', {
        headers: { 'x-amzn-mtls-clientcert': 'irrelevant' },
        get rawHeaders() { throw new Error('rawHeaders trap'); },
      }],
      ['rawHeaders that throw while being walked', {
        headers: { 'x-amzn-mtls-clientcert': 'irrelevant' },
        rawHeaders: new Proxy(['x-amzn-mtls-clientcert', 'v'], {
          get(target, prop) {
            if (prop === 'length') { throw new Error('rawHeaders trap'); }
            return Reflect.get(target, prop);
          },
        }),
      }],
    ];

    for (const [label, req] of cases) {
      it(`should report header_missing_or_malformed for ${label}`, () => {
        const result = extractClientCertificate(req, { certificateSource: 'aws-alb' });

        assert.strictEqual(result.success, false);
        assert.strictEqual(result.certificate, null);
        assert.strictEqual(result.reason, 'header_missing_or_malformed');
      });
    }

    it('should report verification_header_mismatch when a verify header is configured', () => {
      const result = extractClientCertificate({}, {
        certificateSource: 'aws-alb',
        verifyHeader: 'X-SSL-Client-Verify',
        verifyValue: 'SUCCESS',
      });

      assert.strictEqual(result.success, false);
      assert.strictEqual(result.reason, 'verification_header_mismatch');
    });

    it('should discard every header when an unrelated accessor throws', () => {
      const req = {
        headers: {
          'x-amzn-mtls-clientcert': encodeURIComponent(testPem),
          get 'user-agent'() { throw new Error('header trap'); },
        },
      };

      const result = extractClientCertificate(req, { certificateSource: 'aws-alb' });

      assert.strictEqual(result.success, false);
      assert.strictEqual(result.reason, 'header_missing_or_malformed');
    });

    it('should report verification_header_mismatch when the verify header accessor throws', () => {
      const result = extractClientCertificate({
        headers: { get 'x-ssl-client-verify'() { throw new Error('verify trap'); } },
      }, {
        certificateSource: 'aws-alb',
        verifyHeader: 'X-SSL-Client-Verify',
        verifyValue: 'SUCCESS',
      });

      assert.strictEqual(result.success, false);
      assert.strictEqual(result.reason, 'verification_header_mismatch');
    });

    it('should fall back to the socket when fallbackToSocket is true', () => {
      const mockCert = getMockPeerCertificate();
      const req = {
        headers: null,
        socket: { authorized: true, getPeerCertificate: () => mockCert },
      };

      const result = extractClientCertificate(req, {
        certificateSource: 'aws-alb',
        fallbackToSocket: true,
      });

      assert.strictEqual(result.success, true);
      assert.deepStrictEqual(result.certificate, mockCert);
    });

    it('should report socket_not_authorized for an undefined req in socket mode', () => {
      const result = extractClientCertificate(undefined);

      assert.strictEqual(result.success, false);
      assert.strictEqual(result.reason, 'socket_not_authorized');
    });
  });

  describe('repeated header lines', () => {
    const encoded = () => encodeURIComponent(testPem);

    // traefik reads a comma as its own chain separator, so the joined value
    // parses and only the rawHeaders count can reject it.
    const joinedDer = () => `${pemToDer(testPem).toString('base64')},${pemToDer(testPem).toString('base64')}`;

    it('should reject a certificate header that appears more than once in rawHeaders', () => {
      const req = {
        headers: { 'x-forwarded-tls-client-cert': joinedDer() },
        rawHeaders: [
          'X-Forwarded-Tls-Client-Cert', pemToDer(testPem).toString('base64'),
          'Host', 'example.com',
          'x-forwarded-tls-client-cert', pemToDer(testPem).toString('base64'),
        ],
        socket: { authorized: false },
      };

      const result = extractClientCertificate(req, { certificateSource: 'traefik' });

      assert.strictEqual(result.success, false);
      assert.strictEqual(result.certificate, null);
      assert.strictEqual(result.reason, 'header_missing_or_malformed');
    });

    it('should accept the same traefik chain when the header appears once', () => {
      const req = {
        headers: { 'x-forwarded-tls-client-cert': joinedDer() },
        rawHeaders: ['X-Forwarded-Tls-Client-Cert', joinedDer()],
        socket: { authorized: false },
      };

      const result = extractClientCertificate(req, { certificateSource: 'traefik' });

      assert.strictEqual(result.success, true);
      assert.strictEqual(result.certificate.subject.CN, 'client.example.com');
    });

    it('should reject a url-pem certificate header repeated in rawHeaders', () => {
      const req = {
        headers: { 'x-amzn-mtls-clientcert': `${encoded()}, ${encoded()}` },
        rawHeaders: ['X-Amzn-Mtls-Clientcert', encoded(), 'Host', 'example.com', 'x-amzn-mtls-clientcert', encoded()],
        socket: { authorized: false },
      };

      const result = extractClientCertificate(req, { certificateSource: 'aws-alb' });

      assert.strictEqual(result.success, false);
      assert.strictEqual(result.certificate, null);
      assert.strictEqual(result.reason, 'header_missing_or_malformed');
    });

    it('should accept a certificate header that appears exactly once', () => {
      const req = {
        headers: { 'x-amzn-mtls-clientcert': encoded(), 'x-forwarded-for': '10.0.0.1, 10.0.0.2' },
        rawHeaders: ['X-Forwarded-For', '10.0.0.1', 'X-Amzn-Mtls-Clientcert', encoded(), 'X-Forwarded-For', '10.0.0.2'],
        socket: { authorized: false },
      };

      const result = extractClientCertificate(req, { certificateSource: 'aws-alb' });

      assert.strictEqual(result.success, true);
      assert.strictEqual(result.certificate.subject.CN, 'client.example.com');
    });

    it('should fall back to the socket when a repeated header is rejected and fallbackToSocket is true', () => {
      const mockCert = getMockPeerCertificate();
      const req = {
        headers: { 'x-forwarded-tls-client-cert': joinedDer() },
        rawHeaders: [
          'X-Forwarded-Tls-Client-Cert', pemToDer(testPem).toString('base64'),
          'X-Forwarded-Tls-Client-Cert', pemToDer(testPem).toString('base64'),
        ],
        socket: { authorized: true, getPeerCertificate: () => mockCert },
      };

      const result = extractClientCertificate(req, { certificateSource: 'traefik', fallbackToSocket: true });

      assert.strictEqual(result.success, true);
      assert.deepStrictEqual(result.certificate, mockCert);
    });

    it('should read the first XFCC element, which an appending Envoy leaves client-controlled', () => {
      // Envoy APPEND_FORWARD adds its element after the client's, on one header
      // line, so the repeat check sees a single occurrence. Documented in
      // reverse-proxy.md as a configuration the library cannot compensate for.
      const value = `Hash=a;Cert=${encoded()},By=spiffe://mesh;Cert=${encoded()}`;
      const req = {
        headers: { 'x-forwarded-client-cert': value },
        rawHeaders: ['X-Forwarded-Client-Cert', value],
        socket: { authorized: false },
      };

      const result = extractClientCertificate(req, { certificateSource: 'envoy' });

      assert.strictEqual(result.success, true);
      assert.strictEqual(result.certificate.subject.CN, 'client.example.com');
    });

    it('should reject a repeated verification header as verification_header_mismatch', () => {
      const req = {
        headers: { 'x-ssl-client-cert': encoded(), 'x-ssl-client-verify': 'SUCCESS' },
        rawHeaders: ['X-SSL-Client-Verify', 'SUCCESS', 'X-SSL-Client-Cert', encoded(), 'X-SSL-Client-Verify', 'FAILED'],
        socket: { authorized: false },
      };

      const result = extractClientCertificate(req, {
        certificateHeader: 'X-SSL-Client-Cert',
        headerEncoding: 'url-pem',
        verifyHeader: 'X-SSL-Client-Verify',
        verifyValue: 'SUCCESS',
      });

      assert.strictEqual(result.success, false);
      assert.strictEqual(result.reason, 'verification_header_mismatch');
    });

    it('should combine repeated chain header lines as an RFC 9440 list', () => {
      const leaf = encodeAsRfc9440(pemToDer(testPem));
      const req = {
        headers: { 'client-cert': leaf, 'client-cert-chain': `${leaf}, ${leaf}` },
        rawHeaders: ['Client-Cert', leaf, 'Client-Cert-Chain', leaf, 'Client-Cert-Chain', leaf],
        socket: { authorized: false },
      };

      const result = extractClientCertificate(req, { certificateSource: 'cloudflare-rfc9440', includeChain: true });

      assert.strictEqual(result.success, true);
      assert.ok(result.certificate.issuerCertificate);
      assert.ok(result.certificate.issuerCertificate.issuerCertificate);
      assert.strictEqual(result.certificate.issuerCertificate.issuerCertificate.issuerCertificate, undefined);
    });

    it('should ignore rawHeaders that are not an array or contain non-string names', () => {
      for (const rawHeaders of ['X-Amzn-Mtls-Clientcert', [42, encoded(), 'X-Amzn-Mtls-Clientcert', encoded()]]) {
        const req = {
          headers: { 'x-amzn-mtls-clientcert': encoded() },
          rawHeaders,
          socket: { authorized: false },
        };

        const result = extractClientCertificate(req, { certificateSource: 'aws-alb' });

        assert.strictEqual(result.success, true);
      }
    });

    it('should reject repeated header lines as parsed by Node http', async () => {
      const seen = [];
      const server = http.createServer((req, res) => {
        seen.push(extractClientCertificate(req, { certificateSource: 'aws-alb' }));
        res.end();
      });
      await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
      const { port } = server.address();

      const send = (lines) => new Promise((resolve, reject) => {
        const socket = net.connect(port, '127.0.0.1', () => {
          socket.end(['GET / HTTP/1.1', 'Host: example.com', ...lines, 'Connection: close', '', ''].join('\r\n'));
        });
        socket.resume();
        socket.on('error', reject);
        socket.on('close', resolve);
      });

      try {
        await send([`X-Amzn-Mtls-Clientcert: ${encoded()}`, `X-Amzn-Mtls-Clientcert: ${encoded()}`]);
        await send([`X-Amzn-Mtls-Clientcert: ${encoded()}`]);
      } finally {
        await new Promise(resolve => server.close(resolve));
      }

      assert.strictEqual(seen.length, 2);
      assert.strictEqual(seen[0].success, false);
      assert.strictEqual(seen[0].reason, 'header_missing_or_malformed');
      assert.strictEqual(seen[1].success, true);
      assert.strictEqual(seen[1].certificate.subject.CN, 'client.example.com');
    });
  });

  describe('socket extraction', () => {
    it('should extract certificate from authorized socket', () => {
      const mockCert = getMockPeerCertificate();
      const req = {
        headers: {},
        socket: {
          authorized: true,
          getPeerCertificate: () => mockCert,
        },
      };

      const result = extractClientCertificate(req);

      assert.strictEqual(result.success, true);
      assert.deepStrictEqual(result.certificate, mockCert);
      assert.strictEqual(result.reason, null);
    });

    it('should return error when socket is not authorized', () => {
      const req = {
        headers: {},
        socket: {
          authorized: false,
        },
      };

      const result = extractClientCertificate(req);

      assert.strictEqual(result.success, false);
      assert.strictEqual(result.certificate, null);
      assert.strictEqual(result.reason, 'socket_not_authorized');
    });

    it('should return error when socket is missing', () => {
      const req = { headers: {} };

      const result = extractClientCertificate(req);

      assert.strictEqual(result.success, false);
      assert.strictEqual(result.certificate, null);
      assert.strictEqual(result.reason, 'socket_not_authorized');
    });

    it('should return error when certificate cannot be retrieved (empty object)', () => {
      const req = {
        headers: {},
        socket: {
          authorized: true,
          getPeerCertificate: () => ({}),
        },
      };

      const result = extractClientCertificate(req);

      assert.strictEqual(result.success, false);
      assert.strictEqual(result.certificate, null);
      assert.strictEqual(result.reason, 'certificate_not_retrievable');
    });

    it('should return error when certificate cannot be retrieved (null)', () => {
      const req = {
        headers: {},
        socket: {
          authorized: true,
          getPeerCertificate: () => null,
        },
      };

      const result = extractClientCertificate(req);

      assert.strictEqual(result.success, false);
      assert.strictEqual(result.certificate, null);
      assert.strictEqual(result.reason, 'certificate_not_retrievable');
    });

    it('should return error when getPeerCertificate is missing', () => {
      const req = {
        headers: {},
        socket: {
          authorized: true,
          // getPeerCertificate intentionally missing
        },
      };

      const result = extractClientCertificate(req);

      assert.strictEqual(result.success, false);
      assert.strictEqual(result.certificate, null);
      assert.strictEqual(result.reason, 'certificate_not_retrievable');
    });

    it('should include certificate chain when includeChain is true', () => {
      const mockCert = getMockPeerCertificate();
      const req = {
        headers: {},
        socket: {
          authorized: true,
          getPeerCertificate: (detailed) => {
            assert.strictEqual(detailed, true);
            return mockCert;
          },
        },
      };

      const result = extractClientCertificate(req, { includeChain: true });

      assert.strictEqual(result.success, true);
      assert.deepStrictEqual(result.certificate, mockCert);
    });

    it('should not include certificate chain by default', () => {
      const mockCert = getMockPeerCertificate();
      const req = {
        headers: {},
        socket: {
          authorized: true,
          getPeerCertificate: (detailed) => {
            assert.strictEqual(detailed, false);
            return mockCert;
          },
        },
      };

      const result = extractClientCertificate(req, { includeChain: false });

      assert.strictEqual(result.success, true);
    });
  });

  describe('header extraction', () => {
    describe('AWS ALB preset', () => {
      it('should extract certificate from AWS ALB header', () => {
        const encodedCert = encodeURIComponent(testPem);
        const req = {
          headers: {
            'x-amzn-mtls-clientcert': encodedCert,
          },
          socket: { authorized: false },
        };

        const result = extractClientCertificate(req, {
          certificateSource: 'aws-alb',
        });

        assert.strictEqual(result.success, true);
        assert.ok(result.certificate);
        assert.strictEqual(result.certificate.subject.CN, 'client.example.com');
        assert.strictEqual(result.reason, null);
      });
    });

    describe('Envoy preset', () => {
      it('should extract certificate from Envoy XFCC header', () => {
        const xfccValue = `Cert="${encodeURIComponent(testPem)}"`;
        const req = {
          headers: {
            'x-forwarded-client-cert': xfccValue,
          },
          socket: { authorized: false },
        };

        const result = extractClientCertificate(req, {
          certificateSource: 'envoy',
        });

        assert.strictEqual(result.success, true);
        assert.ok(result.certificate);
        assert.strictEqual(result.certificate.subject.CN, 'client.example.com');
      });

      it('should link a chain carried in a multi-block url-pem header', async () => {
        const selfsigned = (await import('selfsigned')).default;
        const intermediate = await selfsigned.generate(
          [{ name: 'commonName', value: 'Intermediate CA' }],
          { algorithm: 'sha256', keySize: 2048, days: 1 }
        );

        const req = {
          headers: {
            'x-custom-cert': encodeURIComponent(`${testPem}\n${intermediate.cert}`),
          },
          socket: { authorized: false },
        };

        const result = extractClientCertificate(req, {
          certificateHeader: 'X-Custom-Cert',
          headerEncoding: 'url-pem',
          includeChain: true,
        });

        assert.strictEqual(result.success, true);
        assert.strictEqual(result.certificate.subject.CN, 'client.example.com');
        assert.ok(result.certificate.issuerCertificate);
        assert.strictEqual(result.certificate.issuerCertificate.subject.CN, 'Intermediate CA');
      });

      it('should strip the url-pem chain when includeChain is false', async () => {
        const selfsigned = (await import('selfsigned')).default;
        const intermediate = await selfsigned.generate(
          [{ name: 'commonName', value: 'Intermediate CA' }],
          { algorithm: 'sha256', keySize: 2048, days: 1 }
        );

        const req = {
          headers: {
            'x-custom-cert': encodeURIComponent(`${testPem}\n${intermediate.cert}`),
          },
          socket: { authorized: false },
        };

        const result = extractClientCertificate(req, {
          certificateHeader: 'X-Custom-Cert',
          headerEncoding: 'url-pem',
        });

        assert.strictEqual(result.success, true);
        assert.strictEqual(result.certificate.subject.CN, 'client.example.com');
        assert.strictEqual(result.certificate.issuerCertificate, undefined);
      });

      it('should reject a traefik header whose leading chain entry is empty', () => {
        const req = {
          headers: {
            'x-forwarded-tls-client-cert': `,${pemToDer(testPem).toString('base64')}`,
          },
          socket: { authorized: false },
        };

        const result = extractClientCertificate(req, { certificateSource: 'traefik' });

        assert.strictEqual(result.success, false);
        assert.strictEqual(result.certificate, null);
        assert.strictEqual(result.reason, 'header_missing_or_malformed');
      });

      it('should reject a url-pem header whose leading block is malformed', () => {
        const invalidBlock = '-----BEGIN CERTIFICATE-----\nNOT_VALID_BASE64\n-----END CERTIFICATE-----\n';

        const req = {
          headers: {
            'x-custom-cert': encodeURIComponent(`${invalidBlock}${testPem}`),
          },
          socket: { authorized: false },
        };

        const result = extractClientCertificate(req, {
          certificateHeader: 'X-Custom-Cert',
          headerEncoding: 'url-pem',
          includeChain: true,
        });

        assert.strictEqual(result.success, false);
        assert.strictEqual(result.certificate, null);
        assert.strictEqual(result.reason, 'header_missing_or_malformed');
      });
    });

    describe('Cloudflare preset', () => {
      it('should extract certificate from the cf-client-cert-der-base64 header', () => {
        const req = {
          headers: {
            'cf-client-cert-der-base64': pemToDer(testPem).toString('base64'),
          },
          socket: { authorized: false },
        };

        const result = extractClientCertificate(req, { certificateSource: 'cloudflare' });

        assert.strictEqual(result.success, true);
        assert.strictEqual(result.certificate.subject.CN, 'client.example.com');
      });

      it('should reject a malformed cf-client-cert-der-base64 header', () => {
        const req = {
          headers: { 'cf-client-cert-der-base64': 'invalid' },
          socket: { authorized: false },
        };

        const result = extractClientCertificate(req, { certificateSource: 'cloudflare' });

        assert.strictEqual(result.success, false);
        assert.strictEqual(result.reason, 'header_missing_or_malformed');
      });
    });

    describe('Traefik preset', () => {
      it('should extract certificate from the x-forwarded-tls-client-cert header', () => {
        const req = {
          headers: {
            'x-forwarded-tls-client-cert': pemToDer(testPem).toString('base64'),
          },
          socket: { authorized: false },
        };

        const result = extractClientCertificate(req, { certificateSource: 'traefik' });

        assert.strictEqual(result.success, true);
        assert.strictEqual(result.certificate.subject.CN, 'client.example.com');
      });

      it('should reject a malformed x-forwarded-tls-client-cert header', () => {
        const req = {
          headers: { 'x-forwarded-tls-client-cert': 'invalid' },
          socket: { authorized: false },
        };

        const result = extractClientCertificate(req, { certificateSource: 'traefik' });

        assert.strictEqual(result.success, false);
        assert.strictEqual(result.reason, 'header_missing_or_malformed');
      });
    });

    describe('AWS ALB verify preset', () => {
      it('should extract certificate from x-amzn-mtls-clientcert-leaf header', () => {
        const encodedCert = encodeURIComponent(testPem);
        const req = {
          headers: {
            'x-amzn-mtls-clientcert-leaf': encodedCert,
          },
          socket: { authorized: false },
        };

        const result = extractClientCertificate(req, {
          certificateSource: 'aws-alb-verify',
        });

        assert.strictEqual(result.success, true);
        assert.ok(result.certificate);
        assert.strictEqual(result.certificate.subject.CN, 'client.example.com');
      });

      it('should not read x-amzn-mtls-clientcert (passthrough header) when in verify preset', () => {
        const encodedCert = encodeURIComponent(testPem);
        const req = {
          headers: {
            'x-amzn-mtls-clientcert': encodedCert,
          },
          socket: { authorized: false },
        };

        const result = extractClientCertificate(req, {
          certificateSource: 'aws-alb-verify',
        });

        assert.strictEqual(result.success, false);
        assert.strictEqual(result.reason, 'header_missing_or_malformed');
      });
    });

    describe('Azure App Service preset', () => {
      it('should extract certificate from x-arr-clientcert header (base64 DER)', () => {
        // Azure App Service forwards bare base64-encoded DER (the body of a
        // PEM cert without the BEGIN/END delimiters). The base64-der parser
        // accepts that directly.
        const derBuffer = pemToDer(testPem);
        const headerValue = derBuffer.toString('base64');
        const req = {
          headers: {
            'x-arr-clientcert': headerValue,
          },
          socket: { authorized: false },
        };

        const result = extractClientCertificate(req, {
          certificateSource: 'azure-app-service',
        });

        assert.strictEqual(result.success, true);
        assert.ok(result.certificate);
        assert.strictEqual(result.certificate.subject.CN, 'client.example.com');
      });

      it('should return error when x-arr-clientcert is missing', () => {
        const req = {
          headers: {},
          socket: { authorized: false },
        };

        const result = extractClientCertificate(req, {
          certificateSource: 'azure-app-service',
        });

        assert.strictEqual(result.success, false);
        assert.strictEqual(result.reason, 'header_missing_or_malformed');
      });
    });

    describe('Cloudflare RFC 9440 preset', () => {
      it('should extract certificate from Client-Cert header (RFC 9440)', () => {
        const derBuffer = pemToDer(testPem);
        const req = {
          headers: {
            'client-cert': encodeAsRfc9440(derBuffer),
          },
          socket: { authorized: false },
        };

        const result = extractClientCertificate(req, {
          certificateSource: 'cloudflare-rfc9440',
        });

        assert.strictEqual(result.success, true);
        assert.ok(result.certificate);
        assert.strictEqual(result.certificate.subject.CN, 'client.example.com');
      });

      it('should link chain from Client-Cert-Chain header when includeChain is true', async () => {
        const selfsigned = (await import('selfsigned')).default;
        const intermediate = await selfsigned.generate(
          [{ name: 'commonName', value: 'Intermediate CA' }],
          { algorithm: 'sha256', keySize: 2048, days: 1 }
        );
        const root = await selfsigned.generate(
          [{ name: 'commonName', value: 'Root CA' }],
          { algorithm: 'sha256', keySize: 2048, days: 1 }
        );

        const leafDer = pemToDer(testPem);
        const intermediateDer = pemToDer(intermediate.cert);
        const rootDer = pemToDer(root.cert);

        const req = {
          headers: {
            'client-cert': encodeAsRfc9440(leafDer),
            'client-cert-chain': encodeAsRfc9440List([intermediateDer, rootDer]),
          },
          socket: { authorized: false },
        };

        const result = extractClientCertificate(req, {
          certificateSource: 'cloudflare-rfc9440',
          includeChain: true,
        });

        assert.strictEqual(result.success, true);
        assert.ok(result.certificate);
        assert.strictEqual(result.certificate.subject.CN, 'client.example.com');
        assert.ok(result.certificate.issuerCertificate);
        assert.strictEqual(result.certificate.issuerCertificate.subject.CN, 'Intermediate CA');
        assert.ok(result.certificate.issuerCertificate.issuerCertificate);
        assert.strictEqual(
          result.certificate.issuerCertificate.issuerCertificate.subject.CN,
          'Root CA'
        );
      });

      it('should strip chain by default when includeChain is false', async () => {
        const selfsigned = (await import('selfsigned')).default;
        const intermediate = await selfsigned.generate(
          [{ name: 'commonName', value: 'Intermediate CA' }],
          { algorithm: 'sha256', keySize: 2048, days: 1 }
        );

        const leafDer = pemToDer(testPem);
        const intermediateDer = pemToDer(intermediate.cert);

        const req = {
          headers: {
            'client-cert': encodeAsRfc9440(leafDer),
            'client-cert-chain': encodeAsRfc9440List([intermediateDer]),
          },
          socket: { authorized: false },
        };

        const result = extractClientCertificate(req, {
          certificateSource: 'cloudflare-rfc9440',
        });

        assert.strictEqual(result.success, true);
        assert.ok(result.certificate);
        assert.strictEqual(result.certificate.issuerCertificate, undefined);
      });

      it('should succeed with leaf only when chain header is absent', () => {
        const derBuffer = pemToDer(testPem);
        const req = {
          headers: {
            'client-cert': encodeAsRfc9440(derBuffer),
          },
          socket: { authorized: false },
        };

        const result = extractClientCertificate(req, {
          certificateSource: 'cloudflare-rfc9440',
          includeChain: true,
        });

        assert.strictEqual(result.success, true);
        assert.ok(result.certificate);
        assert.strictEqual(result.certificate.subject.CN, 'client.example.com');
        assert.strictEqual(result.certificate.issuerCertificate, undefined);
      });

      it('should leave issuerCertificate unset when every chain entry fails to parse', () => {
        const leafDer = pemToDer(testPem);

        const req = {
          headers: {
            'client-cert': encodeAsRfc9440(leafDer),
            'client-cert-chain': ':not_base64:, :also_garbage:',
          },
          socket: { authorized: false },
        };

        const result = extractClientCertificate(req, {
          certificateSource: 'cloudflare-rfc9440',
          includeChain: true,
        });

        // Leaf still parses; chain is empty after filtering parse failures.
        assert.strictEqual(result.success, true);
        assert.ok(result.certificate);
        assert.strictEqual(result.certificate.issuerCertificate, undefined);
      });

      it('should drop malformed chain entries and link the survivors', async () => {
        const selfsigned = (await import('selfsigned')).default;
        const intermediate = await selfsigned.generate(
          [{ name: 'commonName', value: 'Intermediate CA' }],
          { algorithm: 'sha256', keySize: 2048, days: 1 }
        );

        const leafDer = pemToDer(testPem);
        const intermediateDer = pemToDer(intermediate.cert);

        const chainValue = [
          ':not_base64:',
          encodeAsRfc9440(intermediateDer),
          ':also_garbage:',
        ].join(', ');

        const req = {
          headers: {
            'client-cert': encodeAsRfc9440(leafDer),
            'client-cert-chain': chainValue,
          },
          socket: { authorized: false },
        };

        const result = extractClientCertificate(req, {
          certificateSource: 'cloudflare-rfc9440',
          includeChain: true,
        });

        assert.strictEqual(result.success, true);
        assert.ok(result.certificate);
        assert.ok(result.certificate.issuerCertificate);
        assert.strictEqual(result.certificate.issuerCertificate.subject.CN, 'Intermediate CA');
        assert.strictEqual(result.certificate.issuerCertificate.issuerCertificate, undefined);
      });
    });

    describe('chain header length cap', () => {
      it('should reject a chain header that would exceed MAX_CHAIN_CERTS certificates with the leaf', () => {
        const leafDer = pemToDer(testPem);
        const makeReq = (count) => ({
          headers: {
            'client-cert': encodeAsRfc9440(leafDer),
            'client-cert-chain': Array(count).fill(':x:').join(', '),
          },
          socket: { authorized: false },
        });

        const atCap = extractClientCertificate(makeReq(MAX_CHAIN_CERTS - 1), {
          certificateSource: 'cloudflare-rfc9440',
          includeChain: true,
        });
        assert.strictEqual(atCap.success, true);
        assert.strictEqual(atCap.certificate.issuerCertificate, undefined);

        const overCap = extractClientCertificate(makeReq(MAX_CHAIN_CERTS), {
          certificateSource: 'cloudflare-rfc9440',
          includeChain: true,
        });
        assert.strictEqual(overCap.success, false);
        assert.strictEqual(overCap.certificate, null);
        assert.strictEqual(overCap.reason, 'header_missing_or_malformed');
      });

      it('should count every certificate a single chain item expands into', () => {
        // One url-pem item can carry several concatenated certificates, so the
        // cap bounds the leaf plus every parsed certificate, not the
        // comma-separated item count.
        const multiBlock = (count) => encodeURIComponent(Array(count).fill(testPem).join('\n'));
        const makeReq = (count) => ({
          headers: {
            'x-custom-cert': encodeURIComponent(testPem),
            'x-custom-chain': multiBlock(count),
          },
          socket: { authorized: false },
        });
        const options = {
          certificateHeader: 'X-Custom-Cert',
          chainHeader: 'X-Custom-Chain',
          headerEncoding: 'url-pem',
          includeChain: true,
        };

        const atCap = extractClientCertificate(makeReq(MAX_CHAIN_CERTS - 1), options);
        assert.strictEqual(atCap.success, true);
        assert.ok(atCap.certificate.issuerCertificate);

        const overCap = extractClientCertificate(makeReq(MAX_CHAIN_CERTS), options);
        assert.strictEqual(overCap.success, false);
        assert.strictEqual(overCap.certificate, null);
        assert.strictEqual(overCap.reason, 'header_missing_or_malformed');
      });
    });

    describe('chainHeader option (explicit)', () => {
      it('should link chain when using custom certificateHeader + chainHeader', async () => {
        const selfsigned = (await import('selfsigned')).default;
        const intermediate = await selfsigned.generate(
          [{ name: 'commonName', value: 'Intermediate CA' }],
          { algorithm: 'sha256', keySize: 2048, days: 1 }
        );

        const leafDer = pemToDer(testPem);
        const intermediateDer = pemToDer(intermediate.cert);

        const req = {
          headers: {
            'x-leaf-cert': encodeAsRfc9440(leafDer),
            'x-chain-cert': encodeAsRfc9440List([intermediateDer]),
          },
          socket: { authorized: false },
        };

        const result = extractClientCertificate(req, {
          certificateHeader: 'X-Leaf-Cert',
          chainHeader: 'X-Chain-Cert',
          headerEncoding: 'rfc9440',
          includeChain: true,
        });

        assert.strictEqual(result.success, true);
        assert.ok(result.certificate);
        assert.ok(result.certificate.issuerCertificate);
        assert.strictEqual(result.certificate.issuerCertificate.subject.CN, 'Intermediate CA');
      });

      it('should override preset chainHeader when explicit chainHeader is provided', async () => {
        const selfsigned = (await import('selfsigned')).default;
        const intermediate = await selfsigned.generate(
          [{ name: 'commonName', value: 'Override Intermediate CA' }],
          { algorithm: 'sha256', keySize: 2048, days: 1 }
        );

        const leafDer = pemToDer(testPem);
        const intermediateDer = pemToDer(intermediate.cert);

        const req = {
          headers: {
            'client-cert': encodeAsRfc9440(leafDer),
            'x-custom-chain': encodeAsRfc9440List([intermediateDer]),
            // The preset's default `client-cert-chain` is absent on purpose.
          },
          socket: { authorized: false },
        };

        const result = extractClientCertificate(req, {
          certificateSource: 'cloudflare-rfc9440',
          chainHeader: 'X-Custom-Chain',
          includeChain: true,
        });

        assert.strictEqual(result.success, true);
        assert.ok(result.certificate);
        assert.ok(result.certificate.issuerCertificate);
        assert.strictEqual(
          result.certificate.issuerCertificate.subject.CN,
          'Override Intermediate CA'
        );
      });

      it('should ignore chain header when its value is an array (duplicate headers)', async () => {
        const leafDer = pemToDer(testPem);

        const req = {
          headers: {
            'client-cert': encodeAsRfc9440(leafDer),
            'client-cert-chain': ['header1', 'header2'],
          },
          socket: { authorized: false },
        };

        const result = extractClientCertificate(req, {
          certificateSource: 'cloudflare-rfc9440',
          includeChain: true,
        });

        // Leaf still parses; chain is silently dropped.
        assert.strictEqual(result.success, true);
        assert.ok(result.certificate);
        assert.strictEqual(result.certificate.issuerCertificate, undefined);
      });

      it('should ignore chain header when its name collides with an Object.prototype member', () => {
        const leafDer = pemToDer(testPem);

        const req = {
          headers: {
            'client-cert': encodeAsRfc9440(leafDer),
          },
          socket: { authorized: false },
        };

        const result = extractClientCertificate(req, {
          certificateSource: 'cloudflare-rfc9440',
          chainHeader: 'constructor',
          includeChain: true,
        });

        // 'constructor' resolves to a function through the prototype chain
        // of the plain headers object.
        assert.strictEqual(result.success, true);
        assert.ok(result.certificate);
        assert.strictEqual(result.certificate.issuerCertificate, undefined);
      });

      it('should ignore chain header when its value is not a string', () => {
        const leafDer = pemToDer(testPem);

        const req = {
          headers: {
            'client-cert': encodeAsRfc9440(leafDer),
            'client-cert-chain': 42,
          },
          socket: { authorized: false },
        };

        const result = extractClientCertificate(req, {
          certificateSource: 'cloudflare-rfc9440',
          includeChain: true,
        });

        assert.strictEqual(result.success, true);
        assert.ok(result.certificate);
        assert.strictEqual(result.certificate.issuerCertificate, undefined);
      });

      it('should ignore chain header when its value is an empty string', () => {
        const leafDer = pemToDer(testPem);

        const req = {
          headers: {
            'client-cert': encodeAsRfc9440(leafDer),
            'client-cert-chain': '',
          },
          socket: { authorized: false },
        };

        const result = extractClientCertificate(req, {
          certificateSource: 'cloudflare-rfc9440',
          includeChain: true,
        });

        assert.strictEqual(result.success, true);
        assert.ok(result.certificate);
        assert.strictEqual(result.certificate.issuerCertificate, undefined);
      });
    });

    describe('custom header', () => {
      it('should extract from custom header with url-pem encoding', () => {
        const encodedCert = encodeURIComponent(testPem);
        const req = {
          headers: {
            'x-custom-cert': encodedCert,
          },
          socket: { authorized: false },
        };

        const result = extractClientCertificate(req, {
          certificateHeader: 'X-Custom-Cert',
          headerEncoding: 'url-pem',
        });

        assert.strictEqual(result.success, true);
        assert.ok(result.certificate);
        assert.strictEqual(result.certificate.subject.CN, 'client.example.com');
      });
    });

    describe('missing or malformed header', () => {
      it('should return error when header is missing and no fallback', () => {
        const req = {
          headers: {},
          socket: { authorized: false },
        };

        const result = extractClientCertificate(req, {
          certificateSource: 'aws-alb',
          fallbackToSocket: false,
        });

        assert.strictEqual(result.success, false);
        assert.strictEqual(result.certificate, null);
        assert.strictEqual(result.reason, 'header_missing_or_malformed');
      });

      it('should NOT fallback to socket by default when header is missing', () => {
        const mockCert = getMockPeerCertificate();
        const req = {
          headers: {},
          socket: {
            authorized: true,
            getPeerCertificate: () => mockCert,
          },
        };

        // Omit fallbackToSocket option - should default to false
        const result = extractClientCertificate(req, {
          certificateSource: 'aws-alb',
        });

        assert.strictEqual(result.success, false);
        assert.strictEqual(result.certificate, null);
        assert.strictEqual(result.reason, 'header_missing_or_malformed');
      });

      it('should fallback to socket when header is missing and fallback enabled', () => {
        const mockCert = getMockPeerCertificate();
        const req = {
          headers: {},
          socket: {
            authorized: true,
            getPeerCertificate: () => mockCert,
          },
        };

        const result = extractClientCertificate(req, {
          certificateSource: 'aws-alb',
          fallbackToSocket: true,
        });

        assert.strictEqual(result.success, true);
        assert.deepStrictEqual(result.certificate, mockCert);
      });

      it('should fallback to socket when header is malformed and fallback enabled', () => {
        const mockCert = getMockPeerCertificate();
        const req = {
          headers: {
            'x-amzn-mtls-clientcert': 'invalid-base64-data',
          },
          socket: {
            authorized: true,
            getPeerCertificate: () => mockCert,
          },
        };

        const result = extractClientCertificate(req, {
          certificateSource: 'aws-alb',
          fallbackToSocket: true,
        });

        assert.strictEqual(result.success, true);
        assert.deepStrictEqual(result.certificate, mockCert);
      });

      it('should return error when header is array (duplicate headers)', () => {
        const req = {
          headers: {
            'x-amzn-mtls-clientcert': ['cert1', 'cert2'],
          },
          socket: { authorized: false },
        };

        const result = extractClientCertificate(req, {
          certificateSource: 'aws-alb',
          fallbackToSocket: false,
        });

        assert.strictEqual(result.success, false);
        assert.strictEqual(result.reason, 'header_missing_or_malformed');
      });
    });

    describe('certificate chain handling', () => {
      it('should strip issuerCertificate by default from header-extracted cert', () => {
        const encodedCert = encodeURIComponent(testPem);
        const req = {
          headers: {
            'x-amzn-mtls-clientcert': encodedCert,
          },
          socket: { authorized: false },
        };

        const result = extractClientCertificate(req, {
          certificateSource: 'aws-alb',
        });

        assert.strictEqual(result.success, true);
        assert.ok(result.certificate);
        assert.strictEqual(result.certificate.issuerCertificate, undefined);
      });

      it('should leave issuerCertificate unset when includeChain is true and the header carries one certificate', () => {
        const encodedCert = encodeURIComponent(testPem);
        const req = {
          headers: {
            'x-amzn-mtls-clientcert': encodedCert,
          },
          socket: { authorized: false },
        };

        const result = extractClientCertificate(req, {
          certificateSource: 'aws-alb',
          includeChain: true,
        });

        assert.strictEqual(result.success, true);
        assert.ok(result.certificate);
        assert.strictEqual(result.certificate.issuerCertificate, undefined);
      });

      it('should preserve chain via issuerCertificate when aws-alb sends multi-PEM chain with includeChain', async () => {
        const selfsigned = (await import('selfsigned')).default;
        const leaf = await selfsigned.generate(
          [{ name: 'commonName', value: 'leaf.example.com' }],
          { algorithm: 'sha256', keySize: 2048, days: 1 }
        );
        const intermediate = await selfsigned.generate(
          [{ name: 'commonName', value: 'Intermediate CA' }],
          { algorithm: 'sha256', keySize: 2048, days: 1 }
        );

        // AWS sends multi-cert chains as concatenated URL-encoded PEM blocks
        // (per X-Amzn-Mtls-Clientcert format in API Gateway / ALB docs)
        const chainedPem = leaf.cert + intermediate.cert;
        const encodedCert = encodeURIComponent(chainedPem);

        const req = {
          headers: {
            'x-amzn-mtls-clientcert': encodedCert,
          },
          socket: { authorized: false },
        };

        const result = extractClientCertificate(req, {
          certificateSource: 'aws-alb',
          includeChain: true,
        });

        assert.strictEqual(result.success, true);
        assert.ok(result.certificate);
        assert.strictEqual(result.certificate.subject.CN, 'leaf.example.com');
        assert.ok(result.certificate.issuerCertificate, 'leaf should have issuerCertificate populated from intermediate');
        assert.strictEqual(result.certificate.issuerCertificate.subject.CN, 'Intermediate CA');
      });

      it('should strip issuerCertificate by default from aws-alb multi-PEM chain', async () => {
        const selfsigned = (await import('selfsigned')).default;
        const leaf = await selfsigned.generate(
          [{ name: 'commonName', value: 'leaf.example.com' }],
          { algorithm: 'sha256', keySize: 2048, days: 1 }
        );
        const intermediate = await selfsigned.generate(
          [{ name: 'commonName', value: 'Intermediate CA' }],
          { algorithm: 'sha256', keySize: 2048, days: 1 }
        );

        const chainedPem = leaf.cert + intermediate.cert;
        const encodedCert = encodeURIComponent(chainedPem);

        const req = {
          headers: {
            'x-amzn-mtls-clientcert': encodedCert,
          },
          socket: { authorized: false },
        };

        const result = extractClientCertificate(req, {
          certificateSource: 'aws-alb',
        });

        assert.strictEqual(result.success, true);
        assert.ok(result.certificate);
        assert.strictEqual(result.certificate.subject.CN, 'leaf.example.com');
        assert.strictEqual(result.certificate.issuerCertificate, undefined);
      });

      it('should strip issuerCertificate from base64-der chained cert by default', async () => {
        // Generate two certs to create a chain
        const selfsigned = (await import('selfsigned')).default;
        const cert1 = await selfsigned.generate(
          [{ name: 'commonName', value: 'Leaf Certificate' }],
          { algorithm: 'sha256', keySize: 2048, days: 1 }
        );
        const cert2 = await selfsigned.generate(
          [{ name: 'commonName', value: 'Intermediate CA' }],
          { algorithm: 'sha256', keySize: 2048, days: 1 }
        );

        // Convert PEM to DER and then to base64
        const pem1 = cert1.cert.replace(/-----BEGIN CERTIFICATE-----/, '')
          .replace(/-----END CERTIFICATE-----/, '')
          .replace(/\n/g, '');
        const pem2 = cert2.cert.replace(/-----BEGIN CERTIFICATE-----/, '')
          .replace(/-----END CERTIFICATE-----/, '')
          .replace(/\n/g, '');

        // Cloudflare/Traefik format: comma-separated base64-encoded DER certs
        const chainedCert = `${pem1},${pem2}`;

        const req = {
          headers: {
            'x-forwarded-tls-client-cert': chainedCert,
          },
          socket: { authorized: false },
        };

        const result = extractClientCertificate(req, {
          certificateSource: 'traefik',
          fallbackToSocket: false,
        });

        assert.strictEqual(result.success, true);
        assert.ok(result.certificate);
        // Should be stripped by extractor
        assert.strictEqual(result.certificate.issuerCertificate, undefined);
      });
    });
  });

  describe('verification header', () => {
    it('should reject when verification header is missing', () => {
      const encodedCert = encodeURIComponent(testPem);
      const req = {
        headers: {
          'x-ssl-client-cert': encodedCert,
        },
        socket: { authorized: false },
      };

      const result = extractClientCertificate(req, {
        certificateHeader: 'X-SSL-Client-Cert',
        headerEncoding: 'url-pem',
        verifyHeader: 'X-SSL-Client-Verify',
        verifyValue: 'SUCCESS',
      });

      assert.strictEqual(result.success, false);
      assert.strictEqual(result.certificate, null);
      assert.strictEqual(result.reason, 'verification_header_mismatch');
    });

    it('should reject when verification header value does not match', () => {
      const encodedCert = encodeURIComponent(testPem);
      const req = {
        headers: {
          'x-ssl-client-cert': encodedCert,
          'x-ssl-client-verify': 'FAILED',
        },
        socket: { authorized: false },
      };

      const result = extractClientCertificate(req, {
        certificateHeader: 'X-SSL-Client-Cert',
        headerEncoding: 'url-pem',
        verifyHeader: 'X-SSL-Client-Verify',
        verifyValue: 'SUCCESS',
      });

      assert.strictEqual(result.success, false);
      assert.strictEqual(result.certificate, null);
      assert.strictEqual(result.reason, 'verification_header_mismatch');
    });

    it('should succeed when verification header matches expected value', () => {
      const encodedCert = encodeURIComponent(testPem);
      const req = {
        headers: {
          'x-ssl-client-cert': encodedCert,
          'x-ssl-client-verify': 'SUCCESS',
        },
        socket: { authorized: false },
      };

      const result = extractClientCertificate(req, {
        certificateHeader: 'X-SSL-Client-Cert',
        headerEncoding: 'url-pem',
        verifyHeader: 'X-SSL-Client-Verify',
        verifyValue: 'SUCCESS',
      });

      assert.strictEqual(result.success, true);
      assert.ok(result.certificate);
      assert.strictEqual(result.certificate.subject.CN, 'client.example.com');
    });

    it('should reject when verification header is array (duplicate headers)', () => {
      const encodedCert = encodeURIComponent(testPem);
      const req = {
        headers: {
          'x-ssl-client-cert': encodedCert,
          'x-ssl-client-verify': ['SUCCESS', 'SUCCESS'],
        },
        socket: { authorized: false },
      };

      const result = extractClientCertificate(req, {
        certificateHeader: 'X-SSL-Client-Cert',
        headerEncoding: 'url-pem',
        verifyHeader: 'X-SSL-Client-Verify',
        verifyValue: 'SUCCESS',
      });

      assert.strictEqual(result.success, false);
      assert.strictEqual(result.reason, 'verification_header_mismatch');
    });

    it('should be case-sensitive when comparing verifyValue', () => {
      const encodedCert = encodeURIComponent(testPem);
      const req = {
        headers: {
          'x-ssl-client-cert': encodedCert,
          'x-ssl-client-verify': 'success', // lowercase
        },
        socket: { authorized: false },
      };

      const result = extractClientCertificate(req, {
        certificateHeader: 'X-SSL-Client-Cert',
        headerEncoding: 'url-pem',
        verifyHeader: 'X-SSL-Client-Verify',
        verifyValue: 'SUCCESS', // uppercase
      });

      assert.strictEqual(result.success, false);
      assert.strictEqual(result.reason, 'verification_header_mismatch');
    });

  });

  describe('AWS ALB safe characters', () => {
    it('should decode a header that leaves +, =, and / unescaped', () => {
      const encodedCert = encodeURIComponent(testPem)
        .replace(/%2B/g, '+')
        .replace(/%3D/g, '=')
        .replace(/%2F/g, '/');
      const req = {
        headers: {
          'x-amzn-mtls-clientcert': encodedCert,
        },
        socket: { authorized: false },
      };

      const result = extractClientCertificate(req, {
        certificateSource: 'aws-alb',
      });

      assert.strictEqual(result.success, true);
      assert.strictEqual(result.certificate.subject.CN, 'client.example.com');
    });
  });

  describe('case-insensitive header matching', () => {
    it('should match a mixed-case certificateHeader option against the lowercased header key', () => {
      const req = {
        headers: {
          'x-amzn-mtls-clientcert': encodeURIComponent(testPem),
        },
        socket: { authorized: false },
      };

      const result = extractClientCertificate(req, {
        certificateHeader: 'X-Amzn-Mtls-ClientCert',
        headerEncoding: 'url-pem-aws',
      });

      assert.strictEqual(result.success, true);
      assert.strictEqual(result.certificate.subject.CN, 'client.example.com');
    });
  });
});
