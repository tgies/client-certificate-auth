/**
 * Shared test utilities for certificate generation and mTLS testing.
 */

import selfsigned from 'selfsigned';

/**
 * Generate a complete mTLS certificate chain: CA, server, and client certificates.
 * 
 * @param {Object} options - Optional overrides
 * @param {string} options.caCommonName - CA common name (default: 'Test CA')
 * @param {string} options.serverCommonName - Server common name (default: 'localhost')
 * @param {string} options.clientCommonName - Client common name (default: 'Test Client')
 * @returns {Promise<{ca: {cert: string, key: string}, server: {cert: string, key: string}, client: {cert: string, key: string}}>}
 */
export async function generateMtlsCertificates(options = {}) {
    const {
        caCommonName = 'Test CA',
        serverCommonName = 'localhost',
        clientCommonName = 'Test Client',
    } = options;

    // Generate CA certificate
    const ca = await selfsigned.generate(
        [{ name: 'commonName', value: caCommonName }],
        {
            algorithm: 'sha256',
            keySize: 2048,
            days: 1,
            extensions: [
                { name: 'basicConstraints', cA: true, critical: true },
                { name: 'keyUsage', keyCertSign: true, cRLSign: true, critical: true },
            ],
        }
    );

    // Generate server certificate signed by CA
    const server = await selfsigned.generate(
        [{ name: 'commonName', value: serverCommonName }],
        {
            algorithm: 'sha256',
            keySize: 2048,
            days: 1,
            ca: { key: ca.private, cert: ca.cert },
            extensions: [
                { name: 'basicConstraints', cA: false, critical: true },
                { name: 'keyUsage', digitalSignature: true, keyEncipherment: true, critical: true },
                { name: 'extKeyUsage', serverAuth: true },
                {
                    name: 'subjectAltName',
                    altNames: [
                        { type: 2, value: 'localhost' },
                        { type: 7, ip: '127.0.0.1' },
                    ],
                },
            ],
        }
    );

    // Generate client certificate signed by CA
    const client = await selfsigned.generate(
        [{ name: 'commonName', value: clientCommonName }],
        {
            algorithm: 'sha256',
            keySize: 2048,
            days: 1,
            ca: { key: ca.private, cert: ca.cert },
            extensions: [
                { name: 'basicConstraints', cA: false, critical: true },
                { name: 'keyUsage', digitalSignature: true, critical: true },
                { name: 'extKeyUsage', clientAuth: true },
            ],
        }
    );

    return {
        ca: { cert: ca.cert, key: ca.private },
        server: { cert: server.cert, key: server.private },
        client: { cert: client.cert, key: client.private },
    };
}

/**
 * Generate a single self-signed client certificate (for simple unit tests).
 * 
 * @param {string} commonName - Certificate common name
 * @returns {Promise<{cert: string, key: string}>}
 */
export async function generateClientCertificate(commonName = 'Test Client') {
    const result = await selfsigned.generate(
        [{ name: 'commonName', value: commonName }],
        {
            algorithm: 'sha256',
            keySize: 2048,
            days: 1,
            extensions: [
                { name: 'basicConstraints', cA: false, critical: true },
                { name: 'keyUsage', digitalSignature: true, critical: true },
                { name: 'extKeyUsage', clientAuth: true },
            ],
        }
    );

    return { cert: result.cert, key: result.private };
}

/**
 * Convert PEM certificate to DER buffer.
 * 
 * @param {string} pem - PEM-encoded certificate
 * @returns {Buffer} DER-encoded certificate
 */
export function pemToDer(pem) {
    const lines = pem.split('\n');
    const base64 = lines
        .filter(line => !line.startsWith('-----'))
        .join('');
    return Buffer.from(base64, 'base64');
}
