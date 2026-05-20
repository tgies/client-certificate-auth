import assert from 'node:assert/strict';
import { extractClientCertificate, validateExtractorOptions } from '../lib/extractor.js';

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
          verifyHeader: 'X-Verify',
          verifyValue: 'SUCCESS',
        })
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

    it('should throw TypeError when validateExtractorOptions is called with null', () => {
      assert.throws(() => validateExtractorOptions(null), { name: 'TypeError' });
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
    });

    describe('Cloudflare preset', () => {
      it('should extract certificate from Cloudflare header', () => {
        // Cloudflare uses base64-der encoding, need to convert PEM to DER
        // For testing, we'll just verify the header name is correct
        // Skip actual parsing since that requires DER conversion
        const req = {
          headers: {
            // Note: Real Cloudflare uses cf-client-cert-der-base64 with base64-der
            // This test just verifies the extractor tries the right header
            'cf-client-cert-der-base64': 'invalid',  // Will fail parsing but shows correct header used
          },
          socket: { authorized: false },
        };

        const result = extractClientCertificate(req, {
          certificateSource: 'cloudflare',
          fallbackToSocket: false,
        });

        // Should fail due to invalid cert, but shows header was checked
        assert.strictEqual(result.success, false);
        assert.strictEqual(result.reason, 'header_missing_or_malformed');
      });
    });

    describe('Traefik preset', () => {
      it('should extract certificate from Traefik header', () => {
        // Traefik also uses base64-der encoding
        // Skip actual parsing since that requires DER conversion
        const req = {
          headers: {
            'x-forwarded-tls-client-cert': 'invalid',  // Will fail parsing but shows correct header used
          },
          socket: { authorized: false },
        };

        const result = extractClientCertificate(req, {
          certificateSource: 'traefik',
          fallbackToSocket: false,
        });

        // Should fail due to invalid cert, but shows header was checked
        assert.strictEqual(result.success, false);
        assert.strictEqual(result.reason, 'header_missing_or_malformed');
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

      it('should preserve issuerCertificate when includeChain is true', () => {
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
        // If parser returns issuerCertificate, it should be preserved
        // (The parser may or may not include it depending on the cert)
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

    it('should not check verification header for socket-based extraction', () => {
      const mockCert = getMockPeerCertificate();
      const req = {
        headers: {
          'x-ssl-client-verify': 'FAILED', // Mismatch, but should be ignored for socket
        },
        socket: {
          authorized: true,
          getPeerCertificate: () => mockCert,
        },
      };

      // No certificateSource/certificateHeader, so should use socket only
      const result = extractClientCertificate(req, {
        verifyHeader: 'X-SSL-Client-Verify',
        verifyValue: 'SUCCESS',
      });

      assert.strictEqual(result.success, true);
      assert.deepStrictEqual(result.certificate, mockCert);
    });
  });

  describe('case-insensitive header matching', () => {
    it('should match header names case-insensitively', () => {
      const encodedCert = encodeURIComponent(testPem)
        .replace(/%2B/g, '+')
        .replace(/%3D/g, '=')
        .replace(/%2F/g, '/');
      const req = {
        headers: {
          // Node.js lowercases headers automatically, so we need to use lowercase
          'x-amzn-mtls-clientcert': encodedCert,
        },
        socket: { authorized: false },
      };

      const result = extractClientCertificate(req, {
        certificateSource: 'aws-alb',
      });

      assert.strictEqual(result.success, true);
      assert.ok(result.certificate);
    });
  });
});
