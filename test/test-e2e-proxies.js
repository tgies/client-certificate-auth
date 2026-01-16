/**
 * Integration tests for reverse proxy certificate header forwarding.
 * 
 * These tests run real reverse proxies in Docker containers and verify
 * that our parsers correctly handle the actual header formats produced
 * by each proxy.
 * 
 * Prerequisites:
 * - Docker and Docker Compose must be installed
 * - Run with: npm run test:e2e
 * 
 * @jest-environment node
 */

import { execSync } from 'node:child_process';
import https from 'node:https';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateMtlsCertificates, generateClientCertificate } from './test-helpers.js';
import os from 'node:os';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DOCKER_DIR = path.join(__dirname, 'docker');

// Configuration
const NGINX_STRICT_PORT = 8443;   // nginx with ssl_verify_client on
const NGINX_OPTIONAL_PORT = 8444; // nginx with ssl_verify_client optional_no_ca
const ENVOY_PORT = 8445;          // Envoy with XFCC header
const TRAEFIK_PORT = 8446;        // Traefik with PassTLSClientCert
const DOCKER_TIMEOUT = 120000;

/**
 * Generate certificates and write them to disk for Docker containers.
 */
let CERTS_DIR; // Set dynamically to avoid permission issues

async function generateAndWriteCertificates() {
    // Create a fresh temp directory each run (avoids Docker root ownership issues)
    CERTS_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'client-cert-auth-e2e-'));
    // Make directory world-readable (Envoy runs as uid 101, not root)
    fs.chmodSync(CERTS_DIR, 0o755);


    const certs = await generateMtlsCertificates();

    // Write certificates to disk for Docker containers
    fs.writeFileSync(path.join(CERTS_DIR, 'ca.pem'), certs.ca.cert, { mode: 0o644 });
    fs.writeFileSync(path.join(CERTS_DIR, 'ca.key'), certs.ca.key, { mode: 0o644 });
    fs.writeFileSync(path.join(CERTS_DIR, 'server.pem'), certs.server.cert, { mode: 0o644 });
    fs.writeFileSync(path.join(CERTS_DIR, 'server.key'), certs.server.key, { mode: 0o644 });
    fs.writeFileSync(path.join(CERTS_DIR, 'client.pem'), certs.client.cert, { mode: 0o644 });
    fs.writeFileSync(path.join(CERTS_DIR, 'client.key'), certs.client.key, { mode: 0o644 });



    return certs;
}

/**
 * Make HTTPS request with client certificate.
 */
function makeRequest(url, clientCert, clientKey, caCert) {
    return new Promise((resolve, reject) => {
        const urlObj = new URL(url);

        const options = {
            hostname: urlObj.hostname,
            port: urlObj.port || 443,
            path: urlObj.pathname,
            method: 'GET',
            cert: clientCert,
            key: clientKey,
            ca: caCert,
            rejectUnauthorized: true,
        };

        const req = https.request(options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try {
                    resolve(JSON.parse(data));
                } catch {
                    resolve(data);
                }
            });
        });

        req.on('error', reject);
        req.setTimeout(10000, () => {
            req.destroy();
            reject(new Error('Request timeout'));
        });
        req.end();
    });
}

/**
 * Check if Docker is available.
 */
function isDockerAvailable() {
    try {
        execSync('docker info', { stdio: 'ignore' });
        return true;
    } catch {
        return false;
    }
}

/**
 * Wait for a service to be ready.
 */
async function waitForService(url, clientCert, clientKey, caCert, maxAttempts = 30) {
    for (let i = 0; i < maxAttempts; i++) {
        try {
            await makeRequest(url, clientCert, clientKey, caCert);
            return true;
        } catch {
            await new Promise(resolve => setTimeout(resolve, 1000));
        }
    }
    return false;
}

// Skip all tests if Docker is not available
const describeIfDocker = isDockerAvailable() ? describe : describe.skip;

describeIfDocker('Reverse Proxy Integration Tests', () => {
    let certs;

    beforeAll(async () => {
        // Generate certificates
        certs = await generateAndWriteCertificates();

        // Build and start Docker Compose
        console.log('Starting Docker Compose...');

        const dockerEnv = { ...process.env, CERTS_DIR };
        execSync('docker compose build', {
            cwd: DOCKER_DIR,
            stdio: 'inherit',
            timeout: DOCKER_TIMEOUT,
            env: dockerEnv,
        });
        execSync('docker compose up -d', {
            cwd: DOCKER_DIR,
            stdio: 'inherit',
            timeout: DOCKER_TIMEOUT,
            env: dockerEnv,
        });

        // Wait for nginx-strict to be ready
        console.log('Waiting for nginx-strict to be ready...');
        const strictReady = await waitForService(
            `https://localhost:${NGINX_STRICT_PORT}/`,
            certs.client.cert,
            certs.client.key,
            certs.ca.cert
        );

        if (!strictReady) {
            throw new Error('nginx-strict failed to start within timeout');
        }
        console.log('nginx-strict is ready!');

        // Wait for nginx-optional to be ready
        console.log('Waiting for nginx-optional to be ready...');
        const optionalReady = await waitForService(
            `https://localhost:${NGINX_OPTIONAL_PORT}/`,
            certs.client.cert,
            certs.client.key,
            certs.ca.cert
        );

        if (!optionalReady) {
            throw new Error('nginx-optional failed to start within timeout');
        }
        console.log('nginx-optional is ready!');

        // Wait for Envoy to be ready
        console.log('Waiting for Envoy to be ready...');
        const envoyReady = await waitForService(
            `https://localhost:${ENVOY_PORT}/`,
            certs.client.cert,
            certs.client.key,
            certs.ca.cert
        );

        if (!envoyReady) {
            throw new Error('Envoy failed to start within timeout');
        }
        console.log('Envoy is ready!');

        // Wait for Traefik to be ready
        console.log('Waiting for Traefik to be ready...');
        const traefikReady = await waitForService(
            `https://localhost:${TRAEFIK_PORT}/`,
            certs.client.cert,
            certs.client.key,
            certs.ca.cert
        );

        if (!traefikReady) {
            throw new Error('Traefik failed to start within timeout');
        }
        console.log('Traefik is ready!');
    }, DOCKER_TIMEOUT);

    afterAll(() => {
        // Stop and remove containers
        console.log('Stopping Docker Compose...');
        try {
            execSync('docker compose down -v', {
                cwd: DOCKER_DIR,
                stdio: 'inherit',
                timeout: 30000,
                env: { ...process.env, CERTS_DIR },
            });
        } catch (err) {
            console.error('Failed to stop Docker Compose:', err.message);
        }

        // Clean up certificates
        try {
            fs.rmSync(CERTS_DIR, { recursive: true, force: true });
        } catch {
            // Ignore cleanup errors
        }
    });

    // Tests with nginx-strict: proxy verifies client cert (ssl_verify_client on)
    describe('nginx-strict (proxy verifies cert)', () => {
        it('should authenticate valid certificate through middleware', async () => {
            const response = await makeRequest(
                `https://localhost:${NGINX_STRICT_PORT}/`,
                certs.client.cert,
                certs.client.key,
                certs.ca.cert
            );

            expect(response.success).toBe(true);
            expect(response.clientCN).toBe('Test Client');
            expect(response.headerUsed).toBe('x-ssl-client-cert');
        });

        it('should reject request without client certificate (nginx 400)', async () => {
            const response = await makeRequestWithoutCert(
                `https://localhost:${NGINX_STRICT_PORT}/`,
                certs.ca.cert
            );

            // nginx returns HTML error page
            expect(response).toContain('No required SSL certificate was sent');
        });

        it('should reject request with untrusted certificate (nginx 400)', async () => {
            const untrustedCert = await generateClientCertificate('Untrusted Client');

            const response = await makeRequest(
                `https://localhost:${NGINX_STRICT_PORT}/`,
                untrustedCert.cert,
                untrustedCert.key,
                certs.ca.cert
            );

            // nginx returns HTML error page
            expect(response).toContain('SSL certificate error');
        });
    });

    // Tests with nginx-optional: middleware verifies cert (ssl_verify_client optional)
    describe('nginx-optional (middleware verifies cert)', () => {
        it('should authenticate valid certificate through middleware', async () => {
            const response = await makeRequest(
                `https://localhost:${NGINX_OPTIONAL_PORT}/`,
                certs.client.cert,
                certs.client.key,
                certs.ca.cert
            );

            expect(response.success).toBe(true);
            expect(response.clientCN).toBe('Test Client');
            expect(response.headerUsed).toBe('x-ssl-client-cert');
        });

        it('should reject request without certificate (middleware 401)', async () => {
            const response = await makeRequestWithoutCert(
                `https://localhost:${NGINX_OPTIONAL_PORT}/`,
                certs.ca.cert
            );

            // Middleware returns 401 JSON response
            expect(response.success).toBe(false);
            expect(response.status).toBe(401);
        });

        it('should parse untrusted certificate when nginx does not verify CA', async () => {
            // With ssl_verify_client optional, nginx passes ANY cert to middleware
            // The middleware successfully parses it (CA trust is nginx's responsibility)
            const untrustedCert = await generateClientCertificate('Untrusted Client');

            const response = await makeRequest(
                `https://localhost:${NGINX_OPTIONAL_PORT}/`,
                untrustedCert.cert,
                untrustedCert.key,
                certs.ca.cert
            );

            // Middleware parses the cert successfully (even though it's not CA-signed)
            // This is expected: CA verification is nginx's job, not middleware's
            expect(response.success).toBe(true);
            expect(response.clientCN).toBe('Untrusted Client');
        });

        it('should handle multiple consecutive requests', async () => {
            for (let i = 0; i < 3; i++) {
                const response = await makeRequest(
                    `https://localhost:${NGINX_OPTIONAL_PORT}/`,
                    certs.client.cert,
                    certs.client.key,
                    certs.ca.cert
                );

                expect(response.success).toBe(true);
                expect(response.clientCN).toBe('Test Client');
            }
        });
    });

    // Tests with Envoy proxy (uses XFCC header)
    describe('Envoy (XFCC header)', () => {
        it('should authenticate valid certificate through middleware', async () => {
            const response = await makeRequest(
                `https://localhost:${ENVOY_PORT}/`,
                certs.client.cert,
                certs.client.key,
                certs.ca.cert
            );

            expect(response.success).toBe(true);
            expect(response.clientCN).toBe('Test Client');
            expect(response.headerUsed).toBe('x-forwarded-client-cert');
        });

        it('should reject request without client certificate', async () => {
            // Envoy with require_client_certificate: true rejects at TLS level
            await expect(
                makeRequestWithoutCert(`https://localhost:${ENVOY_PORT}/`, certs.ca.cert)
            ).rejects.toThrow();
        });

        it('should reject request with untrusted certificate', async () => {
            const untrustedCert = await generateClientCertificate('Untrusted Client');

            await expect(
                makeRequest(
                    `https://localhost:${ENVOY_PORT}/`,
                    untrustedCert.cert,
                    untrustedCert.key,
                    certs.ca.cert
                )
            ).rejects.toThrow();
        });
    });

    // Tests with Traefik proxy (uses PassTLSClientCert middleware)
    describe('Traefik (PassTLSClientCert)', () => {
        it('should authenticate valid certificate through middleware', async () => {
            const response = await makeRequest(
                `https://localhost:${TRAEFIK_PORT}/`,
                certs.client.cert,
                certs.client.key,
                certs.ca.cert
            );


            expect(response.success).toBe(true);
            expect(response.clientCN).toBe('Test Client');
            expect(response.headerUsed).toBe('x-forwarded-tls-client-cert');
        });

        it('should reject request without client certificate', async () => {
            // Traefik with RequireAndVerifyClientCert rejects at TLS level
            await expect(
                makeRequestWithoutCert(`https://localhost:${TRAEFIK_PORT}/`, certs.ca.cert)
            ).rejects.toThrow();
        });

        it('should reject request with untrusted certificate', async () => {
            const untrustedCert = await generateClientCertificate('Untrusted Client');

            await expect(
                makeRequest(
                    `https://localhost:${TRAEFIK_PORT}/`,
                    untrustedCert.cert,
                    untrustedCert.key,
                    certs.ca.cert
                )
            ).rejects.toThrow();
        });
    });

    // Authorization Helpers E2E Tests (using nginx-strict)
    describe('Authorization Helpers', () => {
        describe('allowCN', () => {
            it('should accept matching CN via real proxy', async () => {
                const response = await makeRequest(
                    `https://localhost:${NGINX_STRICT_PORT}/helpers/allow-cn`,
                    certs.client.cert,
                    certs.client.key,
                    certs.ca.cert
                );

                expect(response.success).toBe(true);
                expect(response.clientCN).toBe('Test Client');
                expect(response.helperPath).toBe('/helpers/allow-cn');
            });

            it('should reject non-matching CN via real proxy', async () => {
                const response = await makeRequest(
                    `https://localhost:${NGINX_STRICT_PORT}/helpers/allow-cn-reject`,
                    certs.client.cert,
                    certs.client.key,
                    certs.ca.cert
                );

                expect(response.success).toBe(false);
                expect(response.status).toBe(401);
            });
        });

        describe('allowIssuer', () => {
            it('should accept matching issuer via real proxy', async () => {
                const response = await makeRequest(
                    `https://localhost:${NGINX_STRICT_PORT}/helpers/allow-issuer`,
                    certs.client.cert,
                    certs.client.key,
                    certs.ca.cert
                );

                expect(response.success).toBe(true);
                expect(response.clientCN).toBe('Test Client');
            });
        });

        describe('allOf', () => {
            it('should accept when all conditions pass via real proxy', async () => {
                const response = await makeRequest(
                    `https://localhost:${NGINX_STRICT_PORT}/helpers/all-of`,
                    certs.client.cert,
                    certs.client.key,
                    certs.ca.cert
                );

                expect(response.success).toBe(true);
                expect(response.clientCN).toBe('Test Client');
            });
        });

        describe('anyOf', () => {
            it('should accept when at least one condition passes via real proxy', async () => {
                const response = await makeRequest(
                    `https://localhost:${NGINX_STRICT_PORT}/helpers/any-of`,
                    certs.client.cert,
                    certs.client.key,
                    certs.ca.cert
                );

                expect(response.success).toBe(true);
                expect(response.clientCN).toBe('Test Client');
            });
        });
    });

    // Verification Header E2E Tests (using nginx-optional which sends X-SSL-Client-Verify)
    describe('Verification Header', () => {
        it('should accept request when verifyHeader matches verifyValue', async () => {
            const response = await makeRequest(
                `https://localhost:${NGINX_OPTIONAL_PORT}/helpers/verify-header`,
                certs.client.cert,
                certs.client.key,
                certs.ca.cert
            );

            expect(response.success).toBe(true);
            expect(response.clientCN).toBe('Test Client');
            expect(response.helperPath).toBe('/helpers/verify-header');
        });

        it('should reject request when verifyValue does not match', async () => {
            const response = await makeRequest(
                `https://localhost:${NGINX_OPTIONAL_PORT}/helpers/verify-header-wrong-value`,
                certs.client.cert,
                certs.client.key,
                certs.ca.cert
            );

            expect(response.success).toBe(false);
            expect(response.status).toBe(401);
            expect(response.error).toContain('Certificate verification failed');
        });
    });
});

function makeRequestWithoutCert(url, caCert) {
    return new Promise((resolve, reject) => {
        const urlObj = new URL(url);

        const options = {
            hostname: urlObj.hostname,
            port: urlObj.port || 443,
            path: urlObj.pathname,
            method: 'GET',
            ca: caCert,
            rejectUnauthorized: true,
            // No cert/key provided
        };

        const req = https.request(options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try {
                    resolve(JSON.parse(data));
                } catch {
                    resolve(data);
                }
            });
        });

        req.on('error', reject);
        req.setTimeout(10000, () => {
            req.destroy();
            reject(new Error('Request timeout'));
        });
        req.end();
    });
}


