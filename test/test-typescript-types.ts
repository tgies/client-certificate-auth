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

// Negative type tests
// These use @ts-expect-error to verify that invalid code is rejected.

// Test 9: clientCertificateAuth() requires a callback argument
// @ts-expect-error - no arguments
const _noArgs = clientCertificateAuth();

// Test 10: callback must be a function, not a string
// @ts-expect-error - string is not a ValidationCallback
const _stringArg = clientCertificateAuth('not a function');

// Test 11: certificateSource must be a valid preset, not arbitrary string
const _badSource = clientCertificateAuth(() => true, {
    // @ts-expect-error - 'invalid-source' is not a valid CertificateSource
    certificateSource: 'invalid-source',
});

// Test 12: fallbackToSocket must be boolean, not string
const _badFallback = clientCertificateAuth(() => true, {
    // @ts-expect-error - 'yes' is not assignable to boolean
    fallbackToSocket: 'yes',
});

// Test 13: ClientCertRequest does not have arbitrary properties
function checkInvalidProperty(req: ClientCertRequest): void {
    // @ts-expect-error - nonExistentProperty does not exist on ClientCertRequest
    const _bad = req.nonExistentProperty;
    void _bad;
}

// Test 14: CJS helpers load() returns the helpers module
import type cjsHelpers from '../lib/helpers.cjs';
async function testCjsHelpersLoad() {
    const helpers = await (null as unknown as typeof cjsHelpers).load();
    const _validator = helpers.allowCN(['admin']);
    const _combined = helpers.allOf(
        helpers.allowCN(['admin']),
        helpers.allowOU(['Engineering'])
    );
}

// Test 15: CJS parsers load() returns the parsers module
import type cjsParsers from '../lib/parsers.cjs';
async function testCjsParsersLoad() {
    const parsers = await (null as unknown as typeof cjsParsers).load();
    const _cert = parsers.parseUrlPem('test');
    const _presets = parsers.PRESETS;
    const _headerCert = parsers.getCertificateFromHeaders({}, {
        certificateSource: 'aws-alb',
    });
}

// Test 16: CJS extractor load() returns the extractor module
import type cjsExtractor from '../lib/extractor.cjs';
async function testCjsExtractorLoad() {
    const extractor = await (null as unknown as typeof cjsExtractor).load();
    const _result = extractor.extractClientCertificate(
        { headers: {} },
        { certificateSource: 'aws-alb' }
    );
}

// Suppress unused variable warnings - this file is for type-checking only
void _statusCode;
void _syncMiddleware;
void _asyncMiddleware;
void _withOptions;
void checkRequest;
void _reqMiddleware;
void testCjsLoad;
void _noArgs;
void _stringArg;
void _badSource;
void _badFallback;
void checkInvalidProperty;
void testCjsHelpersLoad;
void testCjsParsersLoad;
void testCjsExtractorLoad;
