/**
 * Type-check only test file - verifies TypeScript consumer experience.
 * This file is not executed, only type-checked by `npm run typecheck`.
 */
import clientCertificateAuth from '../lib/clientCertificateAuth.js';
import type { ClientCertRequest, HttpError, ClientCertificateAuthOptions, Middleware, ValidationCallback } from '../lib/clientCertificateAuth.js';

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
    chainHeader: 'X-SSL-Client-Cert-Chain',
    headerEncoding: 'url-pem',
    fallbackToSocket: true,
    includeChain: true,
    verifyHeader: 'X-SSL-Verify',
    verifyValue: 'SUCCESS',
};
const _withOptions = clientCertificateAuth(() => true, options);

// Test 5a: All shipped preset names are accepted by certificateSource
const _awsAlbVerify = clientCertificateAuth(() => true, { certificateSource: 'aws-alb-verify' });
const _azureAppService = clientCertificateAuth(() => true, { certificateSource: 'azure-app-service' });
const _cloudflareRfc9440 = clientCertificateAuth(() => true, { certificateSource: 'cloudflare-rfc9440' });
const _envoy = clientCertificateAuth(() => true, { certificateSource: 'envoy' });
const _traefik = clientCertificateAuth(() => true, { certificateSource: 'traefik' });

// Test 6: ClientCertRequest has clientCertificate property
function checkRequest(req: ClientCertRequest): void {
    if (req.clientCertificate) {
        const _cn: string | string[] | undefined = req.clientCertificate.subject?.CN;
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

// Test 7a: callback may return a PromiseLike<boolean> (any thenable, not just native Promise)
const _promiseLikeCallback: ValidationCallback = (cert) => {
    const thenable: PromiseLike<boolean> = {
        then(onfulfilled) {
            return onfulfilled
                ? (onfulfilled(cert.subject.CN === 'admin') as PromiseLike<never>)
                : (undefined as unknown as PromiseLike<never>);
        },
    };
    return thenable;
};
const _promiseLikeMiddleware = clientCertificateAuth(_promiseLikeCallback);

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

// Test 17: Express integration - app.use() accepts the middleware, and
// ClientCertRequest is usable as a route handler request type.
// Regression coverage for the v2.0.0 type compatibility gap where
// ClientCertRequest required a TLSSocket and Express's Socket-typed
// req.socket failed overload resolution.
import express from 'express';
function testExpressIntegration() {
    const app = express();

    app.use(clientCertificateAuth((cert) => cert.subject.CN === 'admin'));

    app.use(clientCertificateAuth((cert) => cert.subject.CN === 'admin', {
        certificateSource: 'aws-alb',
    }));

    app.get('/whoami', (req: ClientCertRequest, res) => {
        const _cn = req.clientCertificate?.subject?.CN;
        void _cn;
        res.json({});
    });
}

// Test 18: Express integration via the CJS sync default export.
function testExpressIntegrationCjsSync() {
    const app = express();
    const cjs = null as unknown as typeof cjsAuth;
    app.use(cjs((cert) => cert.subject.CN === 'admin'));
}

// Test 19: Express integration via the CJS async load() entry.
async function testExpressIntegrationCjsLoad() {
    const app = express();
    const cjs = await (null as unknown as typeof cjsAuth).load();
    app.use(cjs((cert) => cert.subject.CN === 'admin'));
}

// Test 20: Lambda subpath - extractClientCertificateFromLambdaEvent
import { extractClientCertificateFromLambdaEvent } from '../lib/lambda.js';
import type { LambdaEventWithClientCert, LambdaExtractionFailureReason, LambdaExtractionResult } from '../lib/lambda.js';
function testLambdaExtractor() {
    const event: LambdaEventWithClientCert = {
        requestContext: {
            authentication: {
                clientCert: { clientCertPem: '-----BEGIN CERTIFICATE-----...' },
            },
        },
    };
    const result: LambdaExtractionResult = extractClientCertificateFromLambdaEvent(event);
    if (result.success) {
        const _cn: string | string[] | undefined = result.certificate.subject.CN;
        void _cn;
        // Exactly null, not merely nullable.
        const _reasonIsNull: null = result.reason;
        void _reasonIsNull;
    } else {
        const _reason: 'lambda_event_missing_clientcert' | 'lambda_event_clientcert_malformed' = result.reason;
        void _reason;
        const _certIsNull: null = result.certificate;
        void _certIsNull;
    }
}

// Test 21: Lambda CJS load() returns the lambda module
import type cjsLambda from '../lib/lambda.cjs';
async function testCjsLambdaLoad() {
    const lambda = await (null as unknown as typeof cjsLambda).load();
    const _r = lambda.extractClientCertificateFromLambdaEvent({
        requestContext: { authentication: { clientCert: { clientCertPem: '...' } } },
    });
    void _r;
}

// Test 22: Fetch subpath - extractClientCertificateFromRequest accepts a Web Request
import { extractClientCertificateFromRequest } from '../lib/fetch.js';
import type { RequestLike } from '../lib/fetch.js';
function testFetchExtractor() {
    const request = new Request('https://example.com', {
        headers: { 'Client-Cert': ':base64:' },
    });
    const result = extractClientCertificateFromRequest(request, {
        certificateSource: 'cloudflare-rfc9440',
        includeChain: true,
    });
    if (result.success) {
        const _cn: string | string[] | undefined = result.certificate.subject.CN;
        void _cn;
    }
}

// Test 22a: Fetch subpath also accepts any iterable-headers object
function testFetchExtractorPlainObject() {
    const headers: RequestLike['headers'] = new Map([['client-cert', ':base64:']]);
    const _r = extractClientCertificateFromRequest({ headers }, {
        certificateSource: 'cloudflare-rfc9440',
    });
    void _r;
}

// Test 22b: ExtractionResult narrows on success in both directions
import type { ExtractionFailureReason, ExtractionResult } from '../lib/extractor.js';
function testExtractionResultNarrowing(req: { headers: Record<string, string | undefined> }) {
    const result: ExtractionResult = extractClientCertificate(req, { certificateSource: 'aws-alb' });
    if (!result.success) {
        const _upper: string = result.reason.toUpperCase();
        void _upper;
        // @ts-expect-error - certificate is null on failure
        const _never = result.certificate.subject;
        void _never;
        // Exactly null, not merely nullable: the line above still errors if the
        // arm is widened, so it does not pin this on its own.
        const _certificateIsNull: null = result.certificate;
        void _certificateIsNull;
        return;
    }
    const _cn: string | string[] | undefined = result.certificate.subject.CN;
    void _cn;
    // @ts-expect-error - reason is null on success
    const _noReason: string = result.reason;
    void _noReason;
    // Exactly null, not merely nullable.
    const _reasonIsNull: null = result.reason;
    void _reasonIsNull;
}

// Test 22c: ExtractionFailureReason is exhaustive over the documented codes
function describeFailure(reason: ExtractionFailureReason): string {
    switch (reason) {
        case 'verification_header_mismatch':
            return 'verify';
        case 'header_missing_or_malformed':
            return 'header';
        case 'socket_not_authorized':
            return 'socket';
        case 'certificate_not_retrievable':
            return 'retrieve';
    }
}
void describeFailure;

// Test 23: Fetch CJS load() returns the fetch module
import type cjsFetch from '../lib/fetch.cjs';
async function testCjsFetchLoad() {
    const fetchAdapter = await (null as unknown as typeof cjsFetch).load();
    const request = new Request('https://example.com', { headers: {} });
    const _r = fetchAdapter.extractClientCertificateFromRequest(request, {
        certificateSource: 'aws-alb',
    });
    void _r;
}

// Test 24: chainHeader option is typed as optional string
const _chainHeaderOption = clientCertificateAuth(() => true, {
    certificateSource: 'cloudflare-rfc9440',
    chainHeader: 'X-Custom-Chain',
});

// Test 25: Negative - invalid preset name still rejected after the new presets land
const _badNewSource = clientCertificateAuth(() => true, {
    // @ts-expect-error - 'azure-application-gateway' is not (yet) a valid CertificateSource
    certificateSource: 'azure-application-gateway',
});

// Test 26: chain access on an extraction result needs no narrowing, and the
// chain terminates rather than recursing forever like DetailedPeerCertificate
import { extractClientCertificate } from '../lib/extractor.js';
import type { ChainedPeerCertificate } from '../lib/parsers.js';

function testChainAccess(req: Parameters<typeof extractClientCertificate>[0]): string | string[] | undefined {
    const result = extractClientCertificate(req, { certificateSource: 'aws-alb', includeChain: true });
    return result.certificate?.issuerCertificate?.issuerCertificate?.subject?.CN;
}

const _terminatingChain: ChainedPeerCertificate = {
    ...({} as ChainedPeerCertificate),
    issuerCertificate: undefined,
};

// Test 27: chain access inside a validation callback and off req.clientCertificate
// needs no narrowing when includeChain is set
const _chainInCallback = clientCertificateAuth(
    (cert) => cert.issuerCertificate?.subject?.CN === 'Intermediate CA',
    { includeChain: true }
);

function readChainOffRequest(req: ClientCertRequest): string | string[] | undefined {
    return req.clientCertificate?.issuerCertificate?.subject?.CN;
}

const _chainInHooks = clientCertificateAuth(() => true, {
    includeChain: true,
    onAuthenticated: (cert) => void cert.issuerCertificate?.subject,
    onRejected: (cert) => void cert?.issuerCertificate?.subject,
});

// Test 28: allowCA accepts PEM strings, DER buffers, and arrays of either
import { allowCA } from '../lib/helpers.js';
declare const caPem: string;
declare const caDer: Buffer;
const _allowCaPem = clientCertificateAuth(allowCA(caPem), { includeChain: true });
const _allowCaMixed = clientCertificateAuth(allowCA([caDer, caPem], { maxDepth: 3 }));
void _allowCaPem;
void _allowCaMixed;

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
void testExpressIntegration;
void testExpressIntegrationCjsSync;
void testExpressIntegrationCjsLoad;
void _awsAlbVerify;
void _azureAppService;
void _cloudflareRfc9440;
void _envoy;
void _traefik;
// Test 20a: LambdaExtractionFailureReason is exhaustive over the documented codes
function describeLambdaFailure(reason: LambdaExtractionFailureReason): string {
    switch (reason) {
        case 'lambda_event_missing_clientcert':
            return 'missing';
        case 'lambda_event_clientcert_malformed':
            return 'malformed';
    }
}
void describeLambdaFailure;

void testLambdaExtractor;
void testCjsLambdaLoad;
void testFetchExtractor;
void testFetchExtractorPlainObject;
void testCjsFetchLoad;
void _chainHeaderOption;
void _badNewSource;
void testChainAccess;
void _terminatingChain;
void _chainInCallback;
void readChainOffRequest;
void _chainInHooks;

// Test 23: the middleware returns the promise from an async callback, so
// Express 5 can await it and surface a downstream throw.
type Assert<T extends true> = T;
type _MiddlewareMayReturnPromise = Assert<Promise<void> extends ReturnType<Middleware> ? true : false>;
