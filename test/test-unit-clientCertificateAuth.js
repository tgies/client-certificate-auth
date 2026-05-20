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

  it('should throw TypeError if callback is not a function', () => {
    assert.throws(() => clientCertificateAuth('not a function'), {
      name: 'TypeError',
      message: /callback must be a function/
    });
    assert.throws(() => clientCertificateAuth(null), {
      name: 'TypeError',
      message: /callback must be a function/
    });
  });

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

      it('should pass req as second argument to callback', done => {
        const middleware = clientCertificateAuth((cert, req) => {
          assert.equal(cert.subject.CN, 'Proctor Davenport');
          assert.strictEqual(req, mockGoodReq);
          done();
          return true;
        });
        middleware(mockGoodReq, mockRes, () => { });
      });

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

      it('should call next() if callback returns a truthy non-boolean value (string)', done => {
        const middleware = clientCertificateAuth(() => 'yes');
        middleware(mockGoodReq, mockRes, (err) => {
          assert.equal(err, undefined);
          done();
        });
      });

      it('should call next() if callback returns a truthy non-boolean value (number)', done => {
        const middleware = clientCertificateAuth(() => 1);
        middleware(mockGoodReq, mockRes, (err) => {
          assert.equal(err, undefined);
          done();
        });
      });

      it('should call next() if async callback resolves with a truthy non-boolean value', done => {
        const middleware = clientCertificateAuth(async () => 'authorized');
        middleware(mockGoodReq, mockRes, (err) => {
          assert.equal(err, undefined);
          done();
        });
      });

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
            assert.equal(err.message, 'Unauthorized: Client certificate required');
            assert.ok(!err.message.includes('CERT_UNTRUSTED'), 'authorizationError must not leak into client-facing message');
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

      it('should handle request with no socket property', done => {
        const reqNoSocket = { headers: {} };
        const middleware = clientCertificateAuth(() => true);
        middleware(reqNoSocket, mockRes, (err) => {
          assert.ok(err instanceof Error);
          assert.equal(err.status, 401);
          assert.equal(err.message, 'Unauthorized: Client certificate required');
          done();
        });
      });
    });

    describe('when certificate cannot be retrieved', () => {
      it('should pass 500 error to next() when getPeerCertificate returns empty object', done => {
        const reqEmptyCert = {
          ...mockGoodReq,
          socket: { authorized: true, getPeerCertificate: () => ({}) }
        };
        const middleware = clientCertificateAuth(() => true);
        middleware(reqEmptyCert, mockRes, (err) => {
          assert.ok(err instanceof Error);
          assert.equal(err.status, 500);
          assert.ok(err.message.includes('could not be retrieved'));
          done();
        });
      });

      it('should pass 500 error to next() when getPeerCertificate returns null', done => {
        const reqNullCert = {
          ...mockGoodReq,
          socket: { authorized: true, getPeerCertificate: () => null }
        };
        const middleware = clientCertificateAuth(() => true);
        middleware(reqNullCert, mockRes, (err) => {
          assert.ok(err instanceof Error);
          assert.equal(err.status, 500);
          assert.ok(err.message.includes('could not be retrieved'));
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

      it('should fallback to socket if header is present but malformed and fallbackToSocket is true', done => {
        const req = {
          secure: true,
          socket: { authorized: true, getPeerCertificate: getMockPeerCertificate },
          headers: {
            'x-amzn-mtls-clientcert': 'not-a-valid-cert!!!'
          }
        };

        const middleware = clientCertificateAuth((cert) => {
          assert.equal(cert.subject.CN, 'Proctor Davenport');
          return true;
        }, {
          certificateSource: 'aws-alb',
          fallbackToSocket: true
        });

        middleware(req, mockRes, (err) => {
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

      it('should return 401 when certificate header value is a string[] (duplicate headers)', done => {
        const encodedCert = encodeURIComponent(testPem);

        const req = {
          secure: false,
          socket: { authorized: false },
          headers: {
            'x-amzn-mtls-clientcert': [encodedCert, encodedCert]
          }
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
            assert.equal(err.message, 'Unauthorized: Certificate verification failed');
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
            done();
          });
        });

        it('should not leak the verifyHeader value into the client-facing message', done => {
          const encodedCert = encodeURIComponent(testPem);
          const req = {
            secure: false,
            socket: { authorized: false },
            headers: {
              'x-ssl-client-cert': encodedCert,
              'x-ssl-client-verify': 'FAILED:reason-an-attacker-set'
            }
          };

          const middleware = clientCertificateAuth(() => true, {
            certificateHeader: 'X-SSL-Client-Cert',
            headerEncoding: 'url-pem',
            verifyHeader: 'X-SSL-Client-Verify',
            verifyValue: 'SUCCESS'
          });

          middleware(req, mockRes, (err) => {
            assert.equal(err.message, 'Unauthorized: Certificate verification failed');
            assert.ok(!err.message.includes('FAILED:reason-an-attacker-set'));
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

        it('should reject when verify header value is a string[] (duplicate headers)', done => {
          const encodedCert = encodeURIComponent(testPem);
          const req = {
            secure: false,
            socket: { authorized: false },
            headers: {
              'x-ssl-client-cert': encodedCert,
              'x-ssl-client-verify': ['SUCCESS', 'SUCCESS']
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

        it('should throw at construction when only verifyHeader is set (no verifyValue)', () => {
          assert.throws(
            () => clientCertificateAuth(() => true, {
              certificateHeader: 'X-SSL-Client-Cert',
              headerEncoding: 'url-pem',
              verifyHeader: 'X-SSL-Client-Verify'
            }),
            {
              name: 'Error',
              message: /verifyHeader and verifyValue must both be provided together/
            }
          );
        });

        it('should throw at construction when only verifyValue is set (no verifyHeader)', () => {
          assert.throws(
            () => clientCertificateAuth(() => true, {
              certificateHeader: 'X-SSL-Client-Cert',
              headerEncoding: 'url-pem',
              verifyValue: 'SUCCESS'
            }),
            {
              name: 'Error',
              message: /verifyHeader and verifyValue must both be provided together/
            }
          );
        });

        it('should not throw when both verifyHeader and verifyValue are set', () => {
          assert.doesNotThrow(
            () => clientCertificateAuth(() => true, {
              certificateHeader: 'X-SSL-Client-Cert',
              headerEncoding: 'url-pem',
              verifyHeader: 'X-SSL-Client-Verify',
              verifyValue: 'SUCCESS'
            })
          );
        });

        it('should not throw when neither verifyHeader nor verifyValue is set', () => {
          assert.doesNotThrow(
            () => clientCertificateAuth(() => true, {
              certificateHeader: 'X-SSL-Client-Cert',
              headerEncoding: 'url-pem'
            })
          );
        });

        it('should be case-sensitive when comparing verifyValue', done => {
          const encodedCert = encodeURIComponent(testPem);
          const req = {
            secure: false,
            socket: { authorized: false },
            headers: {
              'x-ssl-client-cert': encodedCert,
              'x-ssl-client-verify': 'success'  // lowercase
            }
          };

          const middleware = clientCertificateAuth(() => true, {
            certificateHeader: 'X-SSL-Client-Cert',
            headerEncoding: 'url-pem',
            verifyHeader: 'X-SSL-Client-Verify',
            verifyValue: 'SUCCESS'  // uppercase — should not match
          });

          middleware(req, mockRes, (err) => {
            assert.ok(err instanceof Error);
            assert.equal(err.status, 401);
            assert.ok(err.message.includes('Certificate verification failed'));
            done();
          });
        });
      });
    });

    describe('client-facing error sanitization', () => {
      it('returns a generic message when authorizationError is absent', done => {
        const reqNoError = {
          secure: true,
          socket: { authorized: false, getPeerCertificate: getMockPeerCertificate },
          headers: {}
        };
        const middleware = clientCertificateAuth(() => true);
        middleware(reqNoError, mockRes, (err) => {
          assert.ok(err instanceof Error);
          assert.equal(err.message, 'Unauthorized: Client certificate required');
          done();
        });
      });

      it('does not leak authorizationError into the client message when present', done => {
        const reqWithError = {
          secure: true,
          socket: {
            authorized: false,
            authorizationError: 'CERT_REVOKED',
            getPeerCertificate: getMockPeerCertificate
          },
          headers: {}
        };
        const middleware = clientCertificateAuth(() => true);
        middleware(reqWithError, mockRes, (err) => {
          assert.ok(err instanceof Error);
          assert.equal(err.message, 'Unauthorized: Client certificate required');
          assert.ok(!err.message.includes('CERT_REVOKED'));
          done();
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

    describe('audit hooks (onAuthenticated/onRejected)', () => {
      // Guard against console.error staying monkey-patched if an assertion
      // fails before manual restoration inside a test callback.
      const savedConsoleError = console.error;
      afterEach(() => {
        console.error = savedConsoleError;
      });

      it('should call onAuthenticated with cert and req on success', done => {
        let hookArgs = null;
        const middleware = clientCertificateAuth(() => true, {
          onAuthenticated: (cert, req) => { hookArgs = { cert, req }; }
        });

        middleware(mockGoodReq, mockRes, () => {
          setImmediate(() => {
            assert.ok(hookArgs, 'onAuthenticated should have been called');
            assert.equal(hookArgs.cert.subject.CN, 'Proctor Davenport');
            assert.ok(hookArgs.req);
            done();
          });
        });
      });

      it('should call onRejected with cert, req, and reason when callback returns false', done => {
        let hookArgs = null;
        const middleware = clientCertificateAuth(() => false, {
          onRejected: (cert, req, reason) => { hookArgs = { cert, req, reason }; }
        });

        middleware(mockGoodReq, mockRes, () => {
          setImmediate(() => {
            assert.ok(hookArgs, 'onRejected should have been called');
            assert.equal(hookArgs.cert.subject.CN, 'Proctor Davenport');
            assert.ok(hookArgs.req);
            assert.equal(hookArgs.reason, 'callback_returned_false');
            done();
          });
        });
      });

      it('should call onRejected with null cert when socket is not authorized', done => {
        let hookArgs = null;
        const middleware = clientCertificateAuth(() => true, {
          onRejected: (cert, req, reason) => { hookArgs = { cert, req, reason }; }
        });

        middleware(mockUnauthReq, mockRes, () => {
          setImmediate(() => {
            assert.ok(hookArgs, 'onRejected should have been called');
            assert.equal(hookArgs.cert, null);
            assert.equal(hookArgs.reason, 'socket_not_authorized');
            assert.equal(hookArgs.req.socket.authorizationError, 'CERT_UNTRUSTED');
            done();
          });
        });
      });

      it('should call onRejected with error message when callback throws', done => {
        let hookArgs = null;
        const middleware = clientCertificateAuth(() => {
          throw new Error('Custom error message');
        }, {
          onRejected: (cert, req, reason) => { hookArgs = { cert, req, reason }; }
        });

        middleware(mockGoodReq, mockRes, () => {
          setImmediate(() => {
            assert.ok(hookArgs, 'onRejected should have been called');
            assert.equal(hookArgs.reason, 'Custom error message');
            done();
          });
        });
      });

      it('should call onRejected with error message when async callback rejects', done => {
        let hookArgs = null;
        const middleware = clientCertificateAuth(async () => {
          throw new Error('Async rejection');
        }, {
          onRejected: (cert, req, reason) => { hookArgs = { cert, req, reason }; }
        });

        middleware(mockGoodReq, mockRes, () => {
          setImmediate(() => {
            assert.ok(hookArgs, 'onRejected should have been called');
            assert.equal(hookArgs.reason, 'Async rejection');
            done();
          });
        });
      });

      it('should use fallback reason when sync error has no message', done => {
        let hookArgs = null;
        const middleware = clientCertificateAuth(() => {

          throw { status: 500 };  // Object without message property
        }, {
          onRejected: (cert, req, reason) => { hookArgs = { cert, req, reason }; }
        });

        middleware(mockGoodReq, mockRes, () => {
          setImmediate(() => {
            assert.ok(hookArgs, 'onRejected should have been called');
            assert.equal(hookArgs.reason, 'callback_threw');
            done();
          });
        });
      });

      it('should use fallback reason when async error has no message', done => {
        let hookArgs = null;
        const middleware = clientCertificateAuth(async () => {

          throw { status: 500 };  // Object without message property
        }, {
          onRejected: (cert, req, reason) => { hookArgs = { cert, req, reason }; }
        });

        middleware(mockGoodReq, mockRes, () => {
          setImmediate(() => {
            assert.ok(hookArgs, 'onRejected should have been called');
            assert.equal(hookArgs.reason, 'callback_threw');
            done();
          });
        });
      });

      it('should not block request processing when hook is async', done => {
        let hookResolved = false;
        const middleware = clientCertificateAuth(() => true, {
          onAuthenticated: async () => {
            await new Promise(resolve => setTimeout(resolve, 100));
            hookResolved = true;
          }
        });

        const startTime = Date.now();
        middleware(mockGoodReq, mockRes, () => {
          const elapsed = Date.now() - startTime;
          // Request should complete quickly, not wait 100ms for hook
          assert.ok(elapsed < 50, `Request took ${elapsed}ms, should be nearly instant`);
          assert.equal(hookResolved, false, 'Hook should not have resolved yet');
          done();
        });
      });

      it('should catch and log sync hook errors without affecting request', done => {
        let errorLogged = false;
        console.error = (...args) => {
          if (args[0]?.includes?.('hook error')) {
            errorLogged = true;
          }
        };

        const middleware = clientCertificateAuth(() => true, {
          onAuthenticated: () => {
            throw new Error('Hook explosion');
          }
        });

        middleware(mockGoodReq, mockRes, (err) => {
          assert.equal(err, undefined, 'Request should succeed despite hook error');
          setImmediate(() => {
            assert.ok(errorLogged, 'Error should have been logged');
            done();
          });
        });
      });

      it('should catch and log async hook errors without affecting request', done => {
        let errorLogged = false;
        console.error = (...args) => {
          if (args[0]?.includes?.('hook error')) {
            errorLogged = true;
          }
        };

        const middleware = clientCertificateAuth(() => true, {
          onAuthenticated: async () => {
            throw new Error('Async hook explosion');
          }
        });

        middleware(mockGoodReq, mockRes, (err) => {
          assert.equal(err, undefined, 'Request should succeed despite hook error');
          // Give async hook time to reject
          setTimeout(() => {
            assert.ok(errorLogged, 'Error should have been logged');
            done();
          }, 10);
        });
      });

      it('should not call hooks when they are not provided', done => {
        // This test just verifies no errors when hooks are undefined
        const middleware = clientCertificateAuth(() => true);
        middleware(mockGoodReq, mockRes, (err) => {
          assert.equal(err, undefined);
          done();
        });
      });

      it('should not produce console.error when no hooks are configured', done => {
        let errorCalled = false;
        console.error = (...args) => {
          errorCalled = true;
          savedConsoleError.apply(console, args);
        };

        const middleware = clientCertificateAuth(() => true);
        middleware(mockGoodReq, mockRes, (err) => {
          assert.equal(err, undefined);
          setImmediate(() => {
            assert.equal(errorCalled, false, 'console.error should not be called without hooks');
            done();
          });
        });
      });

      it('should not produce console.error for a successful sync hook', done => {
        let errorCalled = false;
        console.error = (...args) => {
          errorCalled = true;
          savedConsoleError.apply(console, args);
        };

        const middleware = clientCertificateAuth(() => true, {
          onAuthenticated: () => { /* sync hook, no error */ }
        });
        middleware(mockGoodReq, mockRes, (err) => {
          assert.equal(err, undefined);
          setImmediate(() => {
            assert.equal(errorCalled, false, 'console.error should not be called for successful sync hooks');
            done();
          });
        });
      });

      it('should call onRejected for header verification mismatch', async () => {
        const selfsigned = (await import('selfsigned')).default;
        const testCert = await selfsigned.generate(
          [{ name: 'commonName', value: 'Hook Test' }],
          { algorithm: 'sha256', keySize: 2048, days: 1 }
        );
        const encodedCert = encodeURIComponent(testCert.cert);

        let hookArgs = null;
        const req = {
          secure: false,
          socket: { authorized: false },
          headers: {
            'x-ssl-client-cert': encodedCert,
            'x-ssl-client-verify': 'FAILED'
          }
        };

        const middleware = clientCertificateAuth(() => true, {
          certificateHeader: 'X-SSL-Client-Cert',
          headerEncoding: 'url-pem',
          verifyHeader: 'X-SSL-Client-Verify',
          verifyValue: 'SUCCESS',
          onRejected: (cert, req, reason) => { hookArgs = { cert, req, reason }; }
        });

        await new Promise(resolve => {
          middleware(req, mockRes, () => {
            setImmediate(() => {
              assert.ok(hookArgs, 'onRejected should have been called');
              assert.equal(hookArgs.cert, null);
              assert.equal(hookArgs.reason, 'verification_header_mismatch');
              assert.equal(hookArgs.req.headers['x-ssl-client-verify'], 'FAILED');
              resolve();
            });
          });
        });
      });

      it('should call onRejected for missing/malformed header (no fallback)', async () => {
        let hookArgs = null;
        const req = {
          secure: false,
          socket: { authorized: false },
          headers: {}
        };

        const middleware = clientCertificateAuth(() => true, {
          certificateSource: 'aws-alb',
          onRejected: (cert, _req, reason) => { hookArgs = { cert, reason }; }
        });

        await new Promise(resolve => {
          middleware(req, mockRes, () => {
            setImmediate(() => {
              assert.ok(hookArgs, 'onRejected should have been called');
              assert.equal(hookArgs.cert, null);
              assert.equal(hookArgs.reason, 'header_missing_or_malformed');
              resolve();
            });
          });
        });
      });

      it('should call onRejected when cert cannot be retrieved', done => {
        let hookArgs = null;
        const reqEmptyCert = {
          ...mockGoodReq,
          socket: { authorized: true, getPeerCertificate: () => ({}) }
        };

        const middleware = clientCertificateAuth(() => true, {
          onRejected: (cert, _req, reason) => { hookArgs = { cert, reason }; }
        });

        middleware(reqEmptyCert, mockRes, () => {
          setImmediate(() => {
            assert.ok(hookArgs, 'onRejected should have been called');
            assert.equal(hookArgs.cert, null);
            assert.equal(hookArgs.reason, 'certificate_not_retrievable');
            done();
          });
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
