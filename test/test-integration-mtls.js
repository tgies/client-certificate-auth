import assert from 'node:assert/strict';
import https from 'node:https';
import clientCertificateAuth from '../lib/clientCertificateAuth.js';
import {
    allowCN,
    allowFingerprints,
    allowIssuer,
    allowSubject,
    allowOU,
    allowOrganization,
    allOf,
    anyOf,
} from '../lib/helpers.js';
import { generateMtlsCertificates } from './test-helpers.js';

/**
 * Integration tests that establish real mTLS connections.
 */
describe('mTLS Integration', () => {

    let caPems;
    let serverPems;
    let clientPems;
    let server;
    let serverPort;

    beforeAll(async () => {
        const certs = await generateMtlsCertificates();
        caPems = certs.ca;
        serverPems = certs.server;
        clientPems = certs.client;
    });

    beforeEach(done => {
        // Create HTTPS server with mTLS configuration
        server = https.createServer(
            {
                key: serverPems.key,
                cert: serverPems.cert,
                // Trust the CA that signed the client certificates
                ca: [caPems.cert],
                requestCert: true,
                // We set this to false so we can test unauthorized requests too
                rejectUnauthorized: false,
            },
            (req, res) => {
                const middleware = clientCertificateAuth((cert) => {
                    // Accept clients with CN 'Test Client'
                    return cert.subject.CN === 'Test Client';
                });

                middleware(req, res, (err) => {
                    if (err) {
                        res.writeHead(err.status || 500);
                        res.end(JSON.stringify({ error: err.message }));
                    } else {
                        res.writeHead(200);
                        res.end(JSON.stringify({ success: true, cn: req.socket.getPeerCertificate().subject.CN }));
                    }
                });
            }
        );

        server.listen(0, 'localhost', () => {
            serverPort = server.address().port;
            done();
        });
    });

    afterEach(done => {
        server.close(done);
    });

    it('should accept requests with valid client certificate', done => {
        const options = {
            hostname: 'localhost',
            port: serverPort,
            path: '/',
            method: 'GET',
            key: clientPems.key,
            cert: clientPems.cert,
            ca: [caPems.cert],
            rejectUnauthorized: true,
        };

        const req = https.request(options, (res) => {
            let body = '';
            res.on('data', (chunk) => { body += chunk; });
            res.on('end', () => {
                assert.equal(res.statusCode, 200);
                const data = JSON.parse(body);
                assert.equal(data.success, true);
                assert.equal(data.cn, 'Test Client');
                done();
            });
        });

        req.on('error', done);
        req.end();
    });

    it('should reject requests without client certificate', done => {
        const options = {
            hostname: 'localhost',
            port: serverPort,
            path: '/',
            method: 'GET',
            // No client cert provided
            ca: [caPems.cert],
            rejectUnauthorized: true,
        };

        const req = https.request(options, (res) => {
            let _body = '';
            res.on('data', (chunk) => { _body += chunk; });
            res.on('end', () => {
                assert.equal(res.statusCode, 401);
                done();
            });
        });

        req.on('error', done);
        req.end();
    });

    it(
        'should reject requests with certificate that fails validation callback',
        done => {
            // Create a new server that rejects all certs in the callback
            server.close(() => {
                server = https.createServer(
                    {
                        key: serverPems.key,
                        cert: serverPems.cert,
                        ca: [caPems.cert],
                        requestCert: true,
                        rejectUnauthorized: false,
                    },
                    (req, res) => {
                        const middleware = clientCertificateAuth((cert) => {
                            // Reject all certificates
                            return cert.subject.CN === 'Some Other Client';
                        });

                        middleware(req, res, (err) => {
                            if (err) {
                                res.writeHead(err.status || 500);
                                res.end(JSON.stringify({ error: err.message }));
                            } else {
                                res.writeHead(200);
                                res.end(JSON.stringify({ success: true }));
                            }
                        });
                    }
                );

                server.listen(0, 'localhost', () => {
                    serverPort = server.address().port;

                    const options = {
                        hostname: 'localhost',
                        port: serverPort,
                        path: '/',
                        method: 'GET',
                        key: clientPems.key,
                        cert: clientPems.cert,
                        ca: [caPems.cert],
                        rejectUnauthorized: true,
                    };

                    const req = https.request(options, (res) => {
                        let body = '';
                        res.on('data', (chunk) => { body += chunk; });
                        res.on('end', () => {
                            assert.equal(res.statusCode, 401);
                            const data = JSON.parse(body);
                            assert.equal(data.error, 'Unauthorized');
                            done();
                        });
                    });

                    req.on('error', done);
                    req.end();
                });
            });
        }
    );

    it('should support async validation callbacks', done => {
        server.close(() => {
            server = https.createServer(
                {
                    key: serverPems.key,
                    cert: serverPems.cert,
                    ca: [caPems.cert],
                    requestCert: true,
                    rejectUnauthorized: false,
                },
                (req, res) => {
                    const middleware = clientCertificateAuth(async (cert) => {
                        // Simulate async lookup (e.g., database check)
                        await new Promise((resolve) => setTimeout(resolve, 10));
                        return cert.subject.CN === 'Test Client';
                    });

                    middleware(req, res, (err) => {
                        if (err) {
                            res.writeHead(err.status || 500);
                            res.end(JSON.stringify({ error: err.message }));
                        } else {
                            res.writeHead(200);
                            res.end(JSON.stringify({ success: true }));
                        }
                    });
                }
            );

            server.listen(0, 'localhost', () => {
                serverPort = server.address().port;

                const options = {
                    hostname: 'localhost',
                    port: serverPort,
                    path: '/',
                    method: 'GET',
                    key: clientPems.key,
                    cert: clientPems.cert,
                    ca: [caPems.cert],
                    rejectUnauthorized: true,
                };

                const req = https.request(options, (res) => {
                    let _body = '';
                    res.on('data', (chunk) => { _body += chunk; });
                    res.on('end', () => {
                        assert.equal(res.statusCode, 200);
                        done();
                    });
                });

                req.on('error', done);
                req.end();
            });
        });
    });
});

/**
 * Integration tests for authorization helpers over real mTLS connections.
 */
describe('Helpers mTLS Integration', () => {
    let caPems;
    let serverPems;
    let clientPems;
    let server;
    let serverPort;

    beforeAll(async () => {
        const certs = await generateMtlsCertificates();
        caPems = certs.ca;
        serverPems = certs.server;
        clientPems = certs.client;
    });

    afterEach(done => {
        if (server) {
            server.close(done);
        } else {
            done();
        }
    });

    function createServer(validationCallback) {
        return new Promise((resolve) => {
            server = https.createServer(
                {
                    key: serverPems.key,
                    cert: serverPems.cert,
                    ca: [caPems.cert],
                    requestCert: true,
                    rejectUnauthorized: false,
                },
                (req, res) => {
                    const middleware = clientCertificateAuth(validationCallback);
                    middleware(req, res, (err) => {
                        if (err) {
                            res.writeHead(err.status || 500);
                            res.end(JSON.stringify({ error: err.message }));
                        } else {
                            res.writeHead(200);
                            res.end(JSON.stringify({
                                success: true,
                                cn: req.clientCertificate?.subject?.CN,
                            }));
                        }
                    });
                }
            );
            server.listen(0, 'localhost', () => {
                serverPort = server.address().port;
                resolve(serverPort);
            });
        });
    }

    function makeRequest() {
        return new Promise((resolve, reject) => {
            const options = {
                hostname: 'localhost',
                port: serverPort,
                path: '/',
                method: 'GET',
                key: clientPems.key,
                cert: clientPems.cert,
                ca: [caPems.cert],
                rejectUnauthorized: true,
            };
            const req = https.request(options, (res) => {
                let body = '';
                res.on('data', (chunk) => { body += chunk; });
                res.on('end', () => {
                    resolve({ status: res.statusCode, body: JSON.parse(body) });
                });
            });
            req.on('error', reject);
            req.end();
        });
    }

    describe('allowCN', () => {
        it('should accept certificate with matching CN', async () => {
            await createServer(allowCN(['Test Client']));
            const result = await makeRequest();
            assert.equal(result.status, 200);
            assert.equal(result.body.success, true);
        });

        it('should reject certificate with non-matching CN', async () => {
            await createServer(allowCN(['Other Client']));
            const result = await makeRequest();
            assert.equal(result.status, 401);
        });
    });

    describe('allowFingerprints', () => {
        it('should accept certificate with matching fingerprint', async () => {
            const crypto = await import('node:crypto');
            const cert = new crypto.X509Certificate(clientPems.cert);
            const fingerprint = cert.fingerprint;
            await createServer(allowFingerprints([fingerprint]));
            const result = await makeRequest();
            assert.equal(result.status, 200);
        });

        it('should reject certificate with non-matching fingerprint', async () => {
            await createServer(allowFingerprints(['00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00']));
            const result = await makeRequest();
            assert.equal(result.status, 401);
        });
    });

    describe('allowIssuer', () => {
        it('should accept certificate with matching issuer', async () => {
            await createServer(allowIssuer({ CN: 'Test CA' }));
            const result = await makeRequest();
            assert.equal(result.status, 200);
        });

        it('should reject certificate with non-matching issuer', async () => {
            await createServer(allowIssuer({ CN: 'Other CA' }));
            const result = await makeRequest();
            assert.equal(result.status, 401);
        });
    });

    describe('allowSubject', () => {
        it('should accept certificate with matching subject', async () => {
            await createServer(allowSubject({ CN: 'Test Client' }));
            const result = await makeRequest();
            assert.equal(result.status, 200);
        });

        it('should reject certificate with non-matching subject', async () => {
            await createServer(allowSubject({ O: 'Wrong Org' }));
            const result = await makeRequest();
            assert.equal(result.status, 401);
        });
    });

    describe('allowOU', () => {
        it('should reject when OU not present', async () => {
            await createServer(allowOU(['Engineering']));
            const result = await makeRequest();
            assert.equal(result.status, 401);
        });
    });

    describe('allowOrganization', () => {
        it('should reject when O not present', async () => {
            await createServer(allowOrganization(['Test Corp']));
            const result = await makeRequest();
            assert.equal(result.status, 401);
        });
    });

    describe('allOf', () => {
        it('should accept when all conditions pass', async () => {
            await createServer(allOf(
                allowCN(['Test Client']),
                allowIssuer({ CN: 'Test CA' })
            ));
            const result = await makeRequest();
            assert.equal(result.status, 200);
        });

        it('should reject when any condition fails', async () => {
            await createServer(allOf(
                allowCN(['Test Client']),
                allowIssuer({ CN: 'Wrong CA' })
            ));
            const result = await makeRequest();
            assert.equal(result.status, 401);
        });
    });

    describe('anyOf', () => {
        it('should accept when at least one passes', async () => {
            await createServer(anyOf(
                allowCN(['Wrong Client']),
                allowCN(['Test Client'])
            ));
            const result = await makeRequest();
            assert.equal(result.status, 200);
        });

        it('should reject when all fail', async () => {
            await createServer(anyOf(
                allowCN(['Wrong Client']),
                allowIssuer({ CN: 'Wrong CA' })
            ));
            const result = await makeRequest();
            assert.equal(result.status, 401);
        });
    });
});
