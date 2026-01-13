import assert from 'node:assert/strict';
import https from 'node:https';
import clientCertificateAuth from '../lib/clientCertificateAuth.js';
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
