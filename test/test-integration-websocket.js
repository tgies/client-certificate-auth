import assert from 'node:assert/strict';
import https from 'node:https';
import { WebSocketServer, WebSocket } from 'ws';
import clientCertificateAuth from '../lib/clientCertificateAuth.js';
import { generateMtlsCertificates } from './test-helpers.js';

/**
 * Integration tests for WebSocket connections over mTLS.
 *
 * WebSocket upgrade requests are regular HTTP requests that go through middleware,
 * so client-certificate-auth works identically for WebSocket and HTTP connections.
 */
describe('WebSocket mTLS Integration', () => {
    let caPems;
    let serverPems;
    let clientPems;
    let server;
    let wss;
    let serverPort;

    beforeAll(async () => {
        const certs = await generateMtlsCertificates();
        caPems = certs.ca;
        serverPems = certs.server;
        clientPems = certs.client;
    });

    afterEach(done => {
        if (wss) {
            wss.close();
            wss = null;
        }
        if (server) {
            server.close(done);
            server = null;
        } else {
            done();
        }
    });

    /**
     * Create an HTTPS server with WebSocket support and mTLS authentication.
     * @param {Function} validationCallback - Certificate validation callback
     * @param {Object} options - Middleware options
     * @returns {Promise<number>} Server port
     */
    function createServer(validationCallback, options = {}) {
        return new Promise((resolve) => {
            server = https.createServer({
                key: serverPems.key,
                cert: serverPems.cert,
                ca: [caPems.cert],
                requestCert: true,
                rejectUnauthorized: false,
            });

            // Create WebSocket server attached to HTTPS server
            wss = new WebSocketServer({ noServer: true });

            wss.on('connection', (ws, req) => {
                // Send welcome message with client CN
                ws.send(JSON.stringify({
                    type: 'welcome',
                    cn: req.clientCertificate?.subject?.CN
                }));

                ws.on('message', (data) => {
                    // Echo messages back
                    ws.send(JSON.stringify({
                        type: 'echo',
                        data: data.toString()
                    }));
                });
            });

            // Handle upgrade requests with mTLS authentication
            server.on('upgrade', (req, socket, head) => {
                const middleware = clientCertificateAuth(validationCallback, options);

                // Create a mock response object for middleware compatibility
                const res = {
                    writeHead: () => {},
                    end: () => {},
                    redirect: () => {}
                };

                middleware(req, res, (err) => {
                    if (err) {
                        socket.write(`HTTP/1.1 ${err.status || 401} ${err.message}\r\n\r\n`);
                        socket.destroy();
                        return;
                    }

                    wss.handleUpgrade(req, socket, head, (ws) => {
                        wss.emit('connection', ws, req);
                    });
                });
            });

            server.listen(0, 'localhost', () => {
                serverPort = server.address().port;
                resolve(serverPort);
            });
        });
    }

    /**
     * Create a WebSocket client connection with mTLS.
     * @param {Object} tlsOptions - TLS options (key, cert, ca)
     * @returns {Promise<WebSocket>}
     */
    function connectWebSocket(tlsOptions = {}) {
        return new Promise((resolve, reject) => {
            const ws = new WebSocket(`wss://localhost:${serverPort}`, {
                key: tlsOptions.key,
                cert: tlsOptions.cert,
                ca: tlsOptions.ca || [caPems.cert],
                rejectUnauthorized: true,
            });

            ws.on('open', () => resolve(ws));
            ws.on('error', reject);
        });
    }

    it('should accept WebSocket connections with valid client certificate', async () => {
        await createServer((cert) => cert.subject.CN === 'Test Client');

        const ws = await connectWebSocket({
            key: clientPems.key,
            cert: clientPems.cert,
        });

        // Wait for welcome message
        const message = await new Promise((resolve) => {
            ws.on('message', (data) => resolve(JSON.parse(data.toString())));
        });

        assert.equal(message.type, 'welcome');
        assert.equal(message.cn, 'Test Client');

        ws.close();
    });

    it('should reject WebSocket connections without client certificate', async () => {
        await createServer((cert) => cert.subject.CN === 'Test Client');

        await assert.rejects(
            connectWebSocket({
                // No client cert
            }),
            (err) => {
                // Connection should fail
                assert.ok(err.message.includes('401') || err.code === 'ECONNRESET');
                return true;
            }
        );
    });

    it('should reject WebSocket connections when callback returns false', async () => {
        await createServer((cert) => cert.subject.CN === 'Wrong Client');

        await assert.rejects(
            connectWebSocket({
                key: clientPems.key,
                cert: clientPems.cert,
            }),
            (err) => {
                assert.ok(err.message.includes('401') || err.code === 'ECONNRESET');
                return true;
            }
        );
    });

    it('should support async validation callbacks with WebSocket', async () => {
        await createServer(async (cert) => {
            // Simulate async database lookup
            await new Promise((resolve) => setTimeout(resolve, 10));
            return cert.subject.CN === 'Test Client';
        });

        const ws = await connectWebSocket({
            key: clientPems.key,
            cert: clientPems.cert,
        });

        const message = await new Promise((resolve) => {
            ws.on('message', (data) => resolve(JSON.parse(data.toString())));
        });

        assert.equal(message.type, 'welcome');
        ws.close();
    });

    it('should allow bidirectional communication after authentication', async () => {
        await createServer((cert) => cert.subject.CN === 'Test Client');

        const ws = await connectWebSocket({
            key: clientPems.key,
            cert: clientPems.cert,
        });

        // Skip welcome message
        await new Promise((resolve) => {
            ws.once('message', resolve);
        });

        // Send a message and verify echo
        ws.send('Hello, server!');

        const echoMessage = await new Promise((resolve) => {
            ws.on('message', (data) => resolve(JSON.parse(data.toString())));
        });

        assert.equal(echoMessage.type, 'echo');
        assert.equal(echoMessage.data, 'Hello, server!');

        ws.close();
    });

    it('should make certificate available via req.clientCertificate', async () => {
        let capturedCert = null;

        await createServer((cert) => {
            capturedCert = cert;
            return true;
        });

        const ws = await connectWebSocket({
            key: clientPems.key,
            cert: clientPems.cert,
        });

        // Wait for connection to be fully established
        await new Promise((resolve) => {
            ws.once('message', resolve);
        });

        assert.ok(capturedCert, 'Certificate should be captured');
        assert.equal(capturedCert.subject.CN, 'Test Client');

        ws.close();
    });

    it('should call audit hooks on WebSocket authentication', async () => {
        let hookCalled = false;
        let hookCert = null;

        await createServer((cert) => cert.subject.CN === 'Test Client', {
            onAuthenticated: (cert) => {
                hookCalled = true;
                hookCert = cert;
            }
        });

        const ws = await connectWebSocket({
            key: clientPems.key,
            cert: clientPems.cert,
        });

        // Wait for connection
        await new Promise((resolve) => {
            ws.once('message', resolve);
        });

        // Give hook time to complete
        await new Promise((resolve) => setTimeout(resolve, 10));

        assert.ok(hookCalled, 'onAuthenticated hook should be called');
        assert.equal(hookCert.subject.CN, 'Test Client');

        ws.close();
    });
});
