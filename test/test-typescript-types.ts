/**
 * Type-check only test file - verifies TypeScript consumer experience.
 * This file is not executed, only type-checked by `npm run typecheck`.
 */
import clientCertificateAuth from '../lib/clientCertificateAuth.js';
import type { ClientCertRequest, HttpError, ClientCertificateAuthOptions } from '../lib/clientCertificateAuth.js';

// Test 1: Error.status augmentation works on plain Error objects
const plainError = new Error('test');
plainError.status = 401; // Should compile without error

// Test 2: HttpError interface is usable
const httpError: HttpError = Object.assign(new Error('Unauthorized'), { status: 401 });
const _statusCode: number = httpError.status;

// Test 3: Middleware creation with sync callback
const _syncMiddleware = clientCertificateAuth((cert) => {
    return cert.subject.CN === 'admin';
});

// Test 4: Middleware creation with async callback
const _asyncMiddleware = clientCertificateAuth(async (cert) => {
    return cert.subject.CN === 'admin';
});

// Test 5: Options are properly typed
const options: ClientCertificateAuthOptions = {
    certificateSource: 'aws-alb',
    certificateHeader: 'X-SSL-Client-Cert',
    headerEncoding: 'url-pem',
    fallbackToSocket: true,
    includeChain: true,
    verifyHeader: 'X-SSL-Verify',
    verifyValue: 'SUCCESS',
};
const _withOptions = clientCertificateAuth(() => true, options);

// Test 6: ClientCertRequest has clientCertificate property
function checkRequest(req: ClientCertRequest): void {
    if (req.clientCertificate) {
        const _cn: string | undefined = req.clientCertificate.subject?.CN;
    }
}

// Test 7: callback with (cert, req) signature
const _reqMiddleware = clientCertificateAuth((cert, req) => {
    if (req) {
        const _path: string | undefined = req.url;
        void _path;
    }
    return cert.subject.CN === 'admin';
});

// Test 8: CJS load() returns function with full ESM options
import type cjsAuth from '../lib/clientCertificateAuth.cjs';
async function testCjsLoad() {
    const auth = await (null as unknown as typeof cjsAuth).load();
    const _mw = auth((cert) => cert.subject.CN === 'admin', {
        certificateSource: 'aws-alb',
        fallbackToSocket: true,
    });
}

// Suppress unused variable warnings - this file is for type-checking only
void _statusCode;
void _syncMiddleware;
void _asyncMiddleware;
void _withOptions;
void checkRequest;
void _reqMiddleware;
void testCjsLoad;
