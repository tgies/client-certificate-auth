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
    });
});
