import assert from 'node:assert/strict';
import clientCertificateAuth from '../lib/clientCertificateAuth.js';

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

describe('clientCertificateAuth', () => {
  it(
    'should be a function taking callback and options arguments',
    () => {
      assert.equal(typeof clientCertificateAuth, 'function');
      // Note: Function.length is 1 because `options` has a default value
      assert.equal(clientCertificateAuth.length, 1);
    }
  );

  it(
    'should return a middleware function taking three arguments',
    () => {
      const middleware = clientCertificateAuth(() => true);
      assert.equal(typeof middleware, 'function');
      assert.equal(middleware.length, 3);
    }
  );

  describe('middleware(req, res, next)', () => {
    const mockGoodReq = {
      secure: true,
      socket: { authorized: true, getPeerCertificate: getMockPeerCertificate },
      headers: {}
    };


    const mockUnauthReq = {
      secure: true,
      socket: { authorized: false, authorizationError: 'CERT_UNTRUSTED', getPeerCertificate: getMockPeerCertificate },
      headers: {}
    };

    const mockRes = {
      redirect: () => { }
    };

    describe('when the request is secure and the client certificate validates', () => {
      it(
        'should call the validation callback with the certificate',
        done => {
          const middleware = clientCertificateAuth((cert) => {
            assert.equal(cert.subject.CN, 'Proctor Davenport');
            done();
            return true;
          });
          middleware(mockGoodReq, mockRes, () => { });
        }
      );

      it('should call next() if callback returns true (sync)', done => {
        const middleware = clientCertificateAuth(() => true);
        middleware(mockGoodReq, mockRes, (err) => {
          assert.equal(err, undefined);
          done();
        });
      });

      it(
        'should call next() if callback returns Promise<true> (async)',
        done => {
          const middleware = clientCertificateAuth(async () => true);
          middleware(mockGoodReq, mockRes, (err) => {
            assert.equal(err, undefined);
            done();
          });
        }
      );

      it(
        'should pass 401 error to next() if callback returns false',
        done => {
          const middleware = clientCertificateAuth(() => false);
          middleware(mockGoodReq, mockRes, (err) => {
            assert.ok(err instanceof Error);
            assert.equal(err.status, 401);
            assert.equal(err.message, 'Unauthorized');
            done();
          });
        }
      );

      it(
        'should pass 401 error to next() if async callback returns false',
        done => {
          const middleware = clientCertificateAuth(async () => false);
          middleware(mockGoodReq, mockRes, (err) => {
            assert.ok(err instanceof Error);
            assert.equal(err.status, 401);
            done();
          });
        }
      );

      it('should pass error to next() if callback throws', done => {
        const middleware = clientCertificateAuth(() => {
          throw new Error('Validation failed');
        });
        middleware(mockGoodReq, mockRes, (err) => {
          assert.ok(err instanceof Error);
          assert.equal(err.message, 'Validation failed');
          done();
        });
      });

      it('should pass error to next() if async callback rejects', done => {
        const middleware = clientCertificateAuth(async () => {
          throw new Error('Async validation failed');
        });
        middleware(mockGoodReq, mockRes, (err) => {
          assert.ok(err instanceof Error);
          assert.equal(err.message, 'Async validation failed');
          done();
        });
      });

      it('should set status = 401 on thrown sync errors', done => {
        const middleware = clientCertificateAuth(() => {
          throw new Error('Certificate revoked');
        });
        middleware(mockGoodReq, mockRes, (err) => {
          assert.ok(err instanceof Error);
          assert.equal(err.message, 'Certificate revoked');
          assert.equal(err.status, 401);
          done();
        });
      });

      it('should set status = 401 on thrown async errors', done => {
        const middleware = clientCertificateAuth(async () => {
          throw new Error('Certificate not in allowlist');
        });
        middleware(mockGoodReq, mockRes, (err) => {
          assert.ok(err instanceof Error);
          assert.equal(err.message, 'Certificate not in allowlist');
          assert.equal(err.status, 401);
          done();
        });
      });

      it('should preserve pre-set status on thrown errors', done => {
        const middleware = clientCertificateAuth(() => {
          const err = new Error('Custom forbidden');
          err.status = 403;
          throw err;
        });
        middleware(mockGoodReq, mockRes, (err) => {
          assert.ok(err instanceof Error);
          assert.equal(err.message, 'Custom forbidden');
          assert.equal(err.status, 403);
          done();
        });
      });

      it('should preserve pre-set status on async thrown errors', done => {
        const middleware = clientCertificateAuth(async () => {
          const err = new Error('Async forbidden');
          err.status = 403;
          throw err;
        });
        middleware(mockGoodReq, mockRes, (err) => {
          assert.ok(err instanceof Error);
          assert.equal(err.message, 'Async forbidden');
          assert.equal(err.status, 403);
          done();
        });
      });
    });

    describe('when the client certificate does not validate', () => {
      it(
        'should pass 401 error to next() without calling callback',
        done => {
          let callbackCalled = false;
          const middleware = clientCertificateAuth(() => {
            callbackCalled = true;
            return true;
          });
          middleware(mockUnauthReq, mockRes, (err) => {
            assert.equal(callbackCalled, false);
            assert.ok(err instanceof Error);
            assert.equal(err.status, 401);
            assert.ok(err.message.includes('CERT_UNTRUSTED'));
            done();
          });
        }
      );
    });

    describe('when req.socket.authorized is falsy', () => {
      it('should pass 401 error to next()', done => {
        const reqNoAuth = { ...mockGoodReq, socket: { authorized: undefined, getPeerCertificate: getMockPeerCertificate } };
        const middleware = clientCertificateAuth(() => true);
        middleware(reqNoAuth, mockRes, (err) => {
          assert.ok(err instanceof Error);
          assert.equal(err.status, 401);
          done();
        });
      });
    });

    describe('when certificate cannot be retrieved', () => {
      it('should pass 500 error to next()', done => {
        const reqEmptyCert = {
          ...mockGoodReq,
          socket: { authorized: true, getPeerCertificate: () => ({}) }
        };
        const middleware = clientCertificateAuth(() => true);
        middleware(reqEmptyCert, mockRes, (err) => {
          assert.ok(err instanceof Error);
          assert.equal(err.status, 500);
          done();
        });
      });
    });


    describe('header-based certificate extraction', () => {
      let testPem;

      beforeAll(async () => {
        const selfsigned = (await import('selfsigned')).default;
        const testCert = await selfsigned.generate(
          [{ name: 'commonName', value: 'Header Test Client' }],
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

      it('should extract certificate from header using certificateSource preset', done => {
        const encodedCert = encodeURIComponent(testPem)
          .replace(/%2B/g, '+')
          .replace(/%3D/g, '=')
          .replace(/%2F/g, '/');

        const req = {
          secure: false,
          socket: { authorized: false },
          headers: {
            'x-amzn-mtls-clientcert': encodedCert
          }
        };

        const middleware = clientCertificateAuth((cert) => {
          assert.ok(cert);
          assert.equal(cert.subject.CN, 'Header Test Client');
          return true;
        }, { certificateSource: 'aws-alb' });

        middleware(req, mockRes, (err) => {
          assert.equal(err, undefined);
          done();
        });
      });

      it('should return 401 if header is missing and no fallback', done => {
        const req = {
          secure: false,
          socket: { authorized: false },
          headers: {}
        };

        const middleware = clientCertificateAuth(() => true, {
          certificateSource: 'aws-alb'
        });

        middleware(req, mockRes, (err) => {
          assert.ok(err instanceof Error);
          assert.equal(err.status, 401);
          assert.ok(err.message.includes('header missing or malformed'));
          done();
        });
      });

      it('should fallback to socket if header missing and fallbackToSocket is true', done => {
        const middleware = clientCertificateAuth((cert) => {
          assert.equal(cert.subject.CN, 'Proctor Davenport');
          return true;
        }, {
          certificateSource: 'aws-alb',
          fallbackToSocket: true
        });

        middleware(mockGoodReq, mockRes, (err) => {
          assert.equal(err, undefined);
          done();
        });
      });

      it('should use custom header with custom encoding', done => {
        const encodedCert = encodeURIComponent(testPem);

        const req = {
          secure: false,
          socket: { authorized: false },
          headers: {
            'x-custom-cert': encodedCert
          }
        };

        const middleware = clientCertificateAuth((cert) => {
          assert.ok(cert);
          assert.equal(cert.subject.CN, 'Header Test Client');
          return true;
        }, {
          certificateHeader: 'X-Custom-Cert',
          headerEncoding: 'url-pem'
        });

        middleware(req, mockRes, (err) => {
          assert.equal(err, undefined);
          done();
        });
      });

      describe('verifyHeader/verifyValue options', () => {
        it('should reject if verifyHeader is set but header is missing', done => {
          const encodedCert = encodeURIComponent(testPem);
          const req = {
            secure: false,
            socket: { authorized: false },
            headers: {
              'x-ssl-client-cert': encodedCert
              // X-SSL-Client-Verify header is missing
            }
          };

          const middleware = clientCertificateAuth(() => true, {
            certificateHeader: 'X-SSL-Client-Cert',
            headerEncoding: 'url-pem',
            verifyHeader: 'X-SSL-Client-Verify',
            verifyValue: 'SUCCESS'
          });

          middleware(req, mockRes, (err) => {
            assert.ok(err instanceof Error);
            assert.equal(err.status, 401);
            assert.ok(err.message.includes('Certificate verification failed'));
            assert.ok(err.message.includes('header missing'));
            done();
          });
        });

        it('should reject if verifyHeader value does not match verifyValue', done => {
          const encodedCert = encodeURIComponent(testPem);
          const req = {
            secure: false,
            socket: { authorized: false },
            headers: {
              'x-ssl-client-cert': encodedCert,
              'x-ssl-client-verify': 'FAILED:unable to verify'
            }
          };

          const middleware = clientCertificateAuth(() => true, {
            certificateHeader: 'X-SSL-Client-Cert',
            headerEncoding: 'url-pem',
            verifyHeader: 'X-SSL-Client-Verify',
            verifyValue: 'SUCCESS'
          });

          middleware(req, mockRes, (err) => {
            assert.ok(err instanceof Error);
            assert.equal(err.status, 401);
            assert.ok(err.message.includes('Certificate verification failed'));
            assert.ok(err.message.includes('FAILED:unable to verify'));
            done();
          });
        });

        it('should allow request if verifyHeader matches verifyValue', done => {
          const encodedCert = encodeURIComponent(testPem);
          const req = {
            secure: false,
            socket: { authorized: false },
            headers: {
              'x-ssl-client-cert': encodedCert,
              'x-ssl-client-verify': 'SUCCESS'
            }
          };

          const middleware = clientCertificateAuth((cert) => {
            assert.equal(cert.subject.CN, 'Header Test Client');
            return true;
          }, {
            certificateHeader: 'X-SSL-Client-Cert',
            headerEncoding: 'url-pem',
            verifyHeader: 'X-SSL-Client-Verify',
            verifyValue: 'SUCCESS'
          });

          middleware(req, mockRes, (err) => {
            assert.equal(err, undefined);
            done();
          });
        });

        it('should not check verifyHeader for socket-based extraction', done => {
          // Socket-based auth should ignore verifyHeader
          const middleware = clientCertificateAuth((cert) => {
            assert.equal(cert.subject.CN, 'Proctor Davenport');
            return true;
          }, {
            verifyHeader: 'X-SSL-Client-Verify',
            verifyValue: 'SUCCESS'
            // No certificateSource or certificateHeader = socket-based
          });

          middleware(mockGoodReq, mockRes, (err) => {
            assert.equal(err, undefined);
            done();
          });
        });
      });
    });

    describe('req.clientCertificate', () => {
      it('should attach certificate to request on successful auth', done => {
        const req = { ...mockGoodReq };
        const middleware = clientCertificateAuth(() => true);

        middleware(req, mockRes, () => {
          assert.ok(req.clientCertificate, 'clientCertificate should be set');
          assert.equal(req.clientCertificate.subject.CN, 'Proctor Davenport');
          assert.equal(req.clientCertificate.fingerprint, 'BA:DA:DD:EA:DB:EE:FC:CC:CC:CC:07:15:19:88:C0:FF:EE:00:12:00');
          done();
        });
      });

      it('should attach certificate even when callback returns false', done => {
        const req = { ...mockGoodReq };
        const middleware = clientCertificateAuth(() => false);

        middleware(req, mockRes, (err) => {
          assert.ok(err instanceof Error);
          assert.equal(err.status, 401);
          // Certificate should still be attached for error logging purposes
          assert.ok(req.clientCertificate, 'clientCertificate should be set even on auth failure');
          assert.equal(req.clientCertificate.subject.CN, 'Proctor Davenport');
          done();
        });
      });

      it('should attach certificate even when async callback returns false', done => {
        const req = { ...mockGoodReq };
        const middleware = clientCertificateAuth(async () => false);

        middleware(req, mockRes, (err) => {
          assert.ok(err instanceof Error);
          assert.equal(err.status, 401);
          assert.ok(req.clientCertificate, 'clientCertificate should be set even on async auth failure');
          done();
        });
      });

      it('should attach certificate when callback throws', done => {
        const req = { ...mockGoodReq };
        const middleware = clientCertificateAuth(() => {
          throw new Error('Auth error');
        });

        middleware(req, mockRes, (err) => {
          assert.ok(err instanceof Error);
          assert.equal(err.message, 'Auth error');
          assert.ok(req.clientCertificate, 'clientCertificate should be set even on throw');
          done();
        });
      });

      it('should attach certificate extracted from headers', async () => {
        const selfsigned = (await import('selfsigned')).default;
        const testCert = await selfsigned.generate(
          [{ name: 'commonName', value: 'Header Cert Test' }],
          { algorithm: 'sha256', keySize: 2048, days: 1 }
        );
        const encodedCert = encodeURIComponent(testCert.cert);

        const req = {
          secure: false,
          socket: { authorized: false },
          headers: {
            'x-ssl-client-cert': encodedCert
          }
        };

        const middleware = clientCertificateAuth(() => true, {
          certificateHeader: 'X-SSL-Client-Cert',
          headerEncoding: 'url-pem'
        });

        await new Promise((resolve) => {
          middleware(req, mockRes, () => {
            assert.ok(req.clientCertificate, 'clientCertificate should be set from header');
            assert.equal(req.clientCertificate.subject.CN, 'Header Cert Test');
            resolve();
          });
        });
      });

      it('should not attach certificate if extraction fails (no fallback)', done => {
        const req = {
          secure: false,
          socket: { authorized: false },
          headers: {}
        };

        const middleware = clientCertificateAuth(() => true, {
          certificateSource: 'aws-alb'
        });

        middleware(req, mockRes, (err) => {
          assert.ok(err instanceof Error);
          assert.equal(err.status, 401);
          // Certificate should NOT be set since extraction failed
          assert.equal(req.clientCertificate, undefined);
          done();
        });
      });
    });

    describe('includeChain option', () => {
      const getMockIssuerCertificate = () => ({
        subject: { CN: 'Test CA' },
        issuer: { CN: 'Test CA' },
        fingerprint: 'CA:CA:CA:CA:CA:CA:CA:CA:CA:CA:CA:CA:CA:CA:CA:CA:CA:CA:CA:CA'
      });

      const getMockDetailedCertificate = () => {
        const cert = getMockPeerCertificate();
        cert.issuerCertificate = getMockIssuerCertificate();
        return cert;
      };

      it('should not include issuerCertificate by default (socket)', done => {
        const req = {
          secure: true,
          socket: {
            authorized: true,
            getPeerCertificate: (detailed) => {
              // Simulate Node.js behavior: getPeerCertificate(true) returns chain
              return detailed ? getMockDetailedCertificate() : getMockPeerCertificate();
            }
          },
          headers: {}
        };

        const middleware = clientCertificateAuth((cert) => {
          assert.equal(cert.issuerCertificate, undefined, 'issuerCertificate should not be present by default');
          return true;
        });

        middleware(req, mockRes, (err) => {
          assert.equal(err, undefined);
          assert.equal(req.clientCertificate.issuerCertificate, undefined);
          done();
        });
      });

      it('should include issuerCertificate when includeChain is true (socket)', done => {
        const req = {
          secure: true,
          socket: {
            authorized: true,
            getPeerCertificate: (detailed) => {
              return detailed ? getMockDetailedCertificate() : getMockPeerCertificate();
            }
          },
          headers: {}
        };

        const middleware = clientCertificateAuth((cert) => {
          assert.ok(cert.issuerCertificate, 'issuerCertificate should be present');
          assert.equal(cert.issuerCertificate.subject.CN, 'Test CA');
          return true;
        }, { includeChain: true });

        middleware(req, mockRes, (err) => {
          assert.equal(err, undefined);
          assert.ok(req.clientCertificate.issuerCertificate);
          assert.equal(req.clientCertificate.issuerCertificate.subject.CN, 'Test CA');
          done();
        });
      });

      it('should strip issuerCertificate from header-parsed certs by default', async () => {
        const selfsigned = (await import('selfsigned')).default;
        const testCert = await selfsigned.generate(
          [{ name: 'commonName', value: 'Chain Strip Test' }],
          { algorithm: 'sha256', keySize: 2048, days: 1 }
        );

        // Simulate Traefik comma-separated chain (two certs)
        const certDer = Buffer.from(testCert.cert.replace(/-----BEGIN CERTIFICATE-----/, '')
          .replace(/-----END CERTIFICATE-----/, '').replace(/\n/g, ''), 'base64');
        const base64Cert = certDer.toString('base64');
        // Create a fake chain with same cert twice
        const chainHeader = `${base64Cert},${base64Cert}`;

        const req = {
          secure: false,
          socket: { authorized: false },
          headers: {
            'x-forwarded-tls-client-cert': chainHeader
          }
        };

        const middleware = clientCertificateAuth((cert) => {
          // Without includeChain, issuerCertificate should be stripped
          assert.equal(cert.issuerCertificate, undefined, 'issuerCertificate should be stripped');
          return true;
        }, { certificateSource: 'traefik' });

        await new Promise((resolve) => {
          middleware(req, mockRes, () => {
            assert.equal(req.clientCertificate.issuerCertificate, undefined);
            resolve();
          });
        });
      });

      it('should preserve issuerCertificate in header-parsed certs when includeChain is true', async () => {
        const selfsigned = (await import('selfsigned')).default;
        const testCert = await selfsigned.generate(
          [{ name: 'commonName', value: 'Chain Preserve Test' }],
          { algorithm: 'sha256', keySize: 2048, days: 1 }
        );

        const certDer = Buffer.from(testCert.cert.replace(/-----BEGIN CERTIFICATE-----/, '')
          .replace(/-----END CERTIFICATE-----/, '').replace(/\n/g, ''), 'base64');
        const base64Cert = certDer.toString('base64');
        const chainHeader = `${base64Cert},${base64Cert}`;

        const req = {
          secure: false,
          socket: { authorized: false },
          headers: {
            'x-forwarded-tls-client-cert': chainHeader
          }
        };

        const middleware = clientCertificateAuth((cert) => {
          // With includeChain, issuerCertificate should be present
          assert.ok(cert.issuerCertificate, 'issuerCertificate should be preserved');
          return true;
        }, { certificateSource: 'traefik', includeChain: true });

        await new Promise((resolve) => {
          middleware(req, mockRes, () => {
            assert.ok(req.clientCertificate.issuerCertificate);
            resolve();
          });
        });
      });
    });
  });
});
