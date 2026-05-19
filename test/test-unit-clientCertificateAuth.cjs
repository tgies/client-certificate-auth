/*!
 * client-certificate-auth - CommonJS unit tests
 * Mirrors test-unit-clientCertificateAuth.js to ensure ESM/CJS parity
 */

'use strict';

const assert = require('node:assert/strict');
const clientCertificateAuth = require('../lib/clientCertificateAuth.cjs');

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

describe('clientCertificateAuth (CommonJS)', () => {
    it(
        'should be a function taking callback and options arguments',
        () => {
            assert.equal(typeof clientCertificateAuth, 'function');
            assert.equal(clientCertificateAuth.length, 1);
        }
    );

    it('should be exported as default as well for CJS/ESM interop', () => {
        assert.equal(clientCertificateAuth.default, clientCertificateAuth);
    });

    it('should expose a load() function for async ESM loading', () => {
        assert.equal(typeof clientCertificateAuth.load, 'function');
    });

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
                        assert.ok(!err.message.includes('CERT_UNTRUSTED'));
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
            it('should pass 500 error to next()', done => {
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
                    setTimeout(() => {
                        assert.ok(errorLogged, 'Error should have been logged');
                        done();
                    }, 10);
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

            it('should not include issuerCertificate by default', done => {
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
                    assert.equal(cert.issuerCertificate, undefined, 'issuerCertificate should not be present by default');
                    return true;
                });

                middleware(req, mockRes, (err) => {
                    assert.equal(err, undefined);
                    assert.equal(req.clientCertificate.issuerCertificate, undefined);
                    done();
                });
            });

            it('should include issuerCertificate when includeChain is true', done => {
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
        });
    });

    describe('unsupported options validation', () => {
        const unsupportedOptions = [
            'certificateSource',
            'certificateHeader',
            'headerEncoding',
            'fallbackToSocket',
            'verifyHeader',
            'verifyValue'
        ];

        unsupportedOptions.forEach(option => {
            it(`should throw error when ${option} option is passed`, () => {
                assert.throws(
                    () => clientCertificateAuth(() => true, { [option]: 'test' }),
                    {
                        name: 'Error',
                        message: new RegExp(`CJS sync wrapper does not support: ${option}`)
                    }
                );
            });
        });

        it('should throw error listing all unsupported options used', () => {
            assert.throws(
                () => clientCertificateAuth(() => true, {
                    certificateSource: 'aws-alb',
                    headerEncoding: 'url-pem'
                }),
                {
                    name: 'Error',
                    message: /CJS sync wrapper does not support: certificateSource, headerEncoding/
                }
            );
        });

        it('should include load() guidance in error message', () => {
            assert.throws(
                () => clientCertificateAuth(() => true, { certificateHeader: 'X-SSL-Cert' }),
                {
                    message: /Use require\(\.\.\.\)\.load\(\) for full features/
                }
            );
        });

        it('should allow includeChain option without error', () => {
            assert.doesNotThrow(
                () => clientCertificateAuth(() => true, { includeChain: true })
            );
        });
    });

    describe('load() async ESM loader', () => {
        it(
            'should return a function that works identically to the sync export',
            async () => {
                const loadedFn = await clientCertificateAuth.load();
                assert.equal(typeof loadedFn, 'function');

                // Verify it creates working middleware
                const middleware = loadedFn(() => true);
                assert.equal(typeof middleware, 'function');
                assert.equal(middleware.length, 3);
            }
        );

        it('should return the cached module on subsequent calls', async () => {
            const first = await clientCertificateAuth.load();
            const second = await clientCertificateAuth.load();
            assert.strictEqual(first, second);
        });

        it('should create working middleware with header-based options via load()', async () => {
            const selfsigned = require('selfsigned');
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
            const encodedCert = encodeURIComponent(testCert.cert)
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

            const mockRes = { redirect: () => { } };

            const loadedFn = await clientCertificateAuth.load();
            const middleware = loadedFn((cert) => {
                assert.ok(cert);
                assert.equal(cert.subject.CN, 'Header Test Client');
                return true;
            }, { certificateSource: 'aws-alb' });

            await new Promise((resolve, reject) => {
                middleware(req, mockRes, (err) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve();
                    }
                });
            });
        });

        it('should support onAuthenticated hook via load()', async () => {
            const loadedFn = await clientCertificateAuth.load();
            let hookArgs = null;

            const req = {
                secure: true,
                socket: { authorized: true, getPeerCertificate: getMockPeerCertificate },
                headers: {}
            };

            const middleware = loadedFn(() => true, {
                onAuthenticated: (cert, _req) => { hookArgs = { cert, req: _req }; }
            });

            await new Promise(resolve => {
                middleware(req, { redirect: () => {} }, () => {
                    setImmediate(() => {
                        assert.ok(hookArgs, 'onAuthenticated should have been called via load()');
                        assert.equal(hookArgs.cert.subject.CN, 'Proctor Davenport');
                        assert.ok(hookArgs.req);
                        resolve();
                    });
                });
            });
        });
    });
});
