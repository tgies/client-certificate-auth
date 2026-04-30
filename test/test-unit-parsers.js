import assert from 'node:assert/strict';
import {
    parseUrlPem,
    parseUrlPemAws,
    parseXfcc,
    parseBase64Der,
    parseRfc9440,
    pemToCertificate,
    derToCertificate,
    parseHeaderValue,
    getCertificateFromHeaders,
    PRESETS,
} from '../lib/parsers.js';
import { generateClientCertificate, pemToDer } from './test-helpers.js';

/**
 * Test Fixture Generator
 * 
 * These encoding functions match what real proxies produce according to
 * their official documentation. Each function cites its authoritative source.
 */

/**
 * Encode PEM certificate as nginx would via $ssl_client_escaped_cert.
 * @see https://nginx.org/en/docs/http/ngx_http_ssl_module.html#var_ssl_client_escaped_cert
 */
function encodeAsNginx(pem) {
    return encodeURIComponent(pem);
}

/**
 * Encode PEM certificate as AWS ALB would via X-Amzn-Mtls-Clientcert.
 * @see https://docs.aws.amazon.com/elasticloadbalancing/latest/application/mutual-authentication.html
 * URL encoding with +, =, / as safe characters (not encoded).
 */
function encodeAsAwsAlb(pem) {
    return encodeURIComponent(pem)
        .replace(/%2B/g, '+')
        .replace(/%3D/g, '=')
        .replace(/%2F/g, '/');
}

/**
 * Encode certificate in XFCC format as Envoy would.
 * @see https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers#x-forwarded-client-cert
 */
function encodeAsEnvoy(pem, hash = 'abc123') {
    const encodedPem = encodeURIComponent(pem);
    return `Hash=${hash};Cert="${encodedPem}"`;
}

/**
 * Encode certificate in RFC 9440 format (used by GCP).
 * @see https://datatracker.ietf.org/doc/html/rfc9440#section-2.1
 * Base64-encoded DER with colon delimiters.
 */
function encodeAsRfc9440(derBuffer) {
    return ':' + derBuffer.toString('base64') + ':';
}

/**
 * Encode certificate as Cloudflare Cf-Client-Cert-Der-Base64.
 * @see https://developers.cloudflare.com/api-shield/security/mtls/configure/
 * Standard base64-encoded DER (no colons).
 */
function encodeAsCloudflare(derBuffer) {
    return derBuffer.toString('base64');
}

/**
 * Encode certificate as Traefik PassTLSClientCert middleware (pem: true).
 * @see https://doc.traefik.io/traefik/middlewares/http/passtlsclientcert/
 * Raw base64-encoded DER (no PEM delimiters, no URL encoding).
 */
function encodeAsTraefik(derBuffer) {
    return derBuffer.toString('base64');
}

describe('parsers module', () => {
    let testPem;
    let testDer;

    beforeAll(async () => {
        // Generate a test certificate using shared helper
        const testCert = await generateClientCertificate('Test Parser Client');
        testPem = testCert.cert;
        testDer = pemToDer(testPem);
    });

    describe('PRESETS', () => {
        it('should have aws-alb preset', () => {
            assert.ok(PRESETS['aws-alb']);
            assert.equal(PRESETS['aws-alb'].header, 'x-amzn-mtls-clientcert');
            assert.equal(PRESETS['aws-alb'].encoding, 'url-pem-aws');
        });

        it('should have envoy preset', () => {
            assert.ok(PRESETS['envoy']);
            assert.equal(PRESETS['envoy'].header, 'x-forwarded-client-cert');
            assert.equal(PRESETS['envoy'].encoding, 'xfcc');
        });

        it('should have cloudflare preset', () => {
            assert.ok(PRESETS['cloudflare']);
            assert.equal(PRESETS['cloudflare'].header, 'cf-client-cert-der-base64');
            assert.equal(PRESETS['cloudflare'].encoding, 'base64-der');
        });

        it('should have traefik preset', () => {
            assert.ok(PRESETS['traefik']);
            assert.equal(PRESETS['traefik'].header, 'x-forwarded-tls-client-cert');
            assert.equal(PRESETS['traefik'].encoding, 'base64-der');
        });
    });

    describe('parseUrlPem (nginx/Traefik format)', () => {
        it('should parse URL-encoded PEM certificate', () => {
            const encoded = encodeAsNginx(testPem);
            const cert = parseUrlPem(encoded);

            assert.ok(cert);
            assert.equal(cert.subject.CN, 'Test Parser Client');
        });

        it('should return null for empty input', () => {
            assert.equal(parseUrlPem(''), null);
            assert.equal(parseUrlPem(null), null);
            assert.equal(parseUrlPem(undefined), null);
        });

        it('should return null for malformed URL encoding', () => {
            assert.equal(parseUrlPem('%ZZ%invalid'), null);
        });

        it('should return null for invalid certificate data', () => {
            const encoded = encodeURIComponent('not a certificate');
            assert.equal(parseUrlPem(encoded), null);
        });
    });

    describe('parseUrlPemAws (AWS ALB format)', () => {
        it('should parse AWS ALB URL-encoded PEM certificate', () => {
            const encoded = encodeAsAwsAlb(testPem);
            const cert = parseUrlPemAws(encoded);

            assert.ok(cert);
            assert.equal(cert.subject.CN, 'Test Parser Client');
        });

        it('should correctly handle + characters (safe in AWS encoding)', () => {
            // Verify that our encoder produces + characters
            const encoded = encodeAsAwsAlb(testPem);
            // The base64 encoded cert likely contains + characters
            // AWS keeps them as +, not %2B

            const cert = parseUrlPemAws(encoded);
            assert.ok(cert);
            assert.equal(cert.subject.CN, 'Test Parser Client');
        });

        it('should return null for empty input', () => {
            assert.equal(parseUrlPemAws(''), null);
        });

        it('should return null for invalid certificate data', () => {
            // Valid URL-encoded but invalid cert content
            const encoded = encodeURIComponent('not a certificate')
                .replace(/%2B/g, '+')
                .replace(/%3D/g, '=')
                .replace(/%2F/g, '/');
            assert.equal(parseUrlPemAws(encoded), null);
        });

        it('should skip a malformed PEM block in a chain and return the valid leaf', () => {
            // Valid leaf followed by a syntactically-correct PEM frame containing invalid base64.
            // The leaf should still parse; the bad block is silently dropped.
            const invalidBlock = '-----BEGIN CERTIFICATE-----\nNOT_VALID_BASE64\n-----END CERTIFICATE-----\n';
            const encoded = encodeAsAwsAlb(testPem + invalidBlock);
            const cert = parseUrlPemAws(encoded);

            assert.ok(cert);
            assert.equal(cert.subject.CN, 'Test Parser Client');
        });

        it('should return null when every PEM block in a chain is malformed', () => {
            const invalidBlock1 = '-----BEGIN CERTIFICATE-----\nNOT_VALID_BASE64_1\n-----END CERTIFICATE-----\n';
            const invalidBlock2 = '-----BEGIN CERTIFICATE-----\nNOT_VALID_BASE64_2\n-----END CERTIFICATE-----\n';
            const encoded = encodeAsAwsAlb(invalidBlock1 + invalidBlock2);

            assert.equal(parseUrlPemAws(encoded), null);
        });

        it('should return null when URL encoding is malformed', () => {
            // %G0 is not a valid percent-encoded sequence; decodeURIComponent throws.
            assert.equal(parseUrlPemAws('%G0'), null);
        });

        it('should stop scanning at a BEGIN marker with no matching END marker', () => {
            // A valid leaf cert followed by a truncated BEGIN with no END.
            // The scanner should return the leaf and silently ignore the trailing
            // unterminated block rather than scanning forever.
            const truncated = '-----BEGIN CERTIFICATE-----\nMIIBkTCCATug==\n';
            const encoded = encodeAsAwsAlb(testPem + truncated);
            const cert = parseUrlPemAws(encoded);

            assert.ok(cert);
            assert.equal(cert.subject.CN, 'Test Parser Client');
        });
    });

    describe('parseXfcc (Envoy format)', () => {
        it('should parse XFCC header with Cert field', () => {
            const encoded = encodeAsEnvoy(testPem);
            const cert = parseXfcc(encoded);

            assert.ok(cert);
            assert.equal(cert.subject.CN, 'Test Parser Client');
        });

        it('should parse XFCC header with Chain field', () => {
            const encodedPem = encodeURIComponent(testPem);
            const xfcc = `Hash=abc123;Chain="${encodedPem}"`;
            const cert = parseXfcc(xfcc);

            assert.ok(cert);
            assert.equal(cert.subject.CN, 'Test Parser Client');
        });

        it('should handle quoted values', () => {
            const encodedPem = encodeURIComponent(testPem);
            const xfcc = `Hash=abc;Cert="${encodedPem}";Subject="CN=Test"`;
            const cert = parseXfcc(xfcc);

            assert.ok(cert);
        });

        it('should handle unquoted values', () => {
            // XFCC with unquoted Cert value
            const encodedPem = encodeURIComponent(testPem);
            const xfcc = `Hash=abc;Cert=${encodedPem}`;
            const cert = parseXfcc(xfcc);

            assert.ok(cert);
            assert.equal(cert.subject.CN, 'Test Parser Client');
        });

        it('should return null if no Cert or Chain field', () => {
            const xfcc = 'Hash=abc123;Subject="CN=Test"';
            assert.equal(parseXfcc(xfcc), null);
        });

        it('should return null for empty input', () => {
            assert.equal(parseXfcc(''), null);
        });

        it('should skip XFCC segments without equals sign', () => {
            // XFCC with a segment that has no = (should be skipped)
            const encodedPem = encodeURIComponent(testPem);
            const xfcc = `invalidpair;Cert="${encodedPem}"`;
            const cert = parseXfcc(xfcc);
            assert.ok(cert);
            assert.equal(cert.subject.CN, 'Test Parser Client');
        });

        it('should return null for malformed certificate in XFCC', () => {
            // Valid XFCC structure but invalid cert content
            const xfcc = 'Hash=abc;Cert="invalid%20certificate"';
            assert.equal(parseXfcc(xfcc), null);
        });

        it('should return null when value has only starting quote (malformed)', () => {
            // Tests: value.startsWith('"') && value.endsWith('"')
            // If only one quote is present, the quote becomes part of the value
            // and breaks URL decoding or certificate parsing
            const encodedPem = encodeURIComponent(testPem);
            const xfcc = `Hash=abc;Cert="${encodedPem}`;  // Missing end quote
            const cert = parseXfcc(xfcc);
            // Fails because leading quote becomes part of value
            assert.equal(cert, null);
        });

        it('should return null when value has only ending quote (malformed)', () => {
            // Tests: value.startsWith('"') && value.endsWith('"')
            const encodedPem = encodeURIComponent(testPem);
            const xfcc = `Hash=abc;Cert=${encodedPem}"`;  // Only end quote
            const cert = parseXfcc(xfcc);
            // Fails because trailing quote becomes part of value
            assert.equal(cert, null);
        });

        it('should properly strip both quotes when present', () => {
            // Tests that slice(1, -1) actually removes quotes
            const encodedPem = encodeURIComponent(testPem);
            const xfcc = `Cert="${encodedPem}"`;
            const cert = parseXfcc(xfcc);
            assert.ok(cert);
            assert.equal(cert.subject.CN, 'Test Parser Client');
        });

        it('should handle empty segments gracefully', () => {
            // Tests the continue statement when eqIndex === -1
            const encodedPem = encodeURIComponent(testPem);
            const xfcc = `;;Cert="${encodedPem}";;`;
            const cert = parseXfcc(xfcc);
            assert.ok(cert);
        });

        it('should parse first element from multi-hop XFCC header', async () => {
            const secondCert = await generateClientCertificate('Second Hop Client');
            const firstEncoded = encodeAsEnvoy(testPem, 'first');
            const secondEncoded = encodeAsEnvoy(secondCert.cert, 'second');
            const multiHop = `${firstEncoded},${secondEncoded}`;
            const cert = parseXfcc(multiHop);

            assert.ok(cert);
            assert.equal(cert.subject.CN, 'Test Parser Client');
        });

        it('should return first element cert when multi-hop has different CNs', async () => {
            const secondCert = await generateClientCertificate('Different CN');
            const firstEncoded = encodeAsEnvoy(testPem, 'abc');
            const secondEncoded = encodeAsEnvoy(secondCert.cert, 'def');
            const multiHop = `${firstEncoded},${secondEncoded}`;
            const cert = parseXfcc(multiHop);

            assert.ok(cert);
            assert.equal(cert.subject.CN, 'Test Parser Client',
                'Should return the first hop cert, not the second');
        });

        it('should handle quoted Subject fields containing commas', () => {
            const encodedPem = encodeURIComponent(testPem);
            // Subject with commas (typical DN) placed before Cert
            const xfcc = `Subject="CN=client,OU=team,O=company";Cert="${encodedPem}"`;
            const cert = parseXfcc(xfcc);

            assert.ok(cert, 'Should not be broken by commas inside quoted Subject');
            assert.equal(cert.subject.CN, 'Test Parser Client');
        });

        it('should handle escaped quotes inside quoted values', () => {
            const encodedPem = encodeURIComponent(testPem);
            // Escaped quote (\") inside a quoted Subject value, followed by a comma
            // that should NOT be treated as an element separator
            const xfcc = `Subject="CN=foo\\"bar,OU=team";Cert="${encodedPem}"`;
            const cert = parseXfcc(xfcc);

            assert.ok(cert, 'Should not break on escaped quotes inside quoted values');
            assert.equal(cert.subject.CN, 'Test Parser Client');
        });

        it('should handle quoted Subject with commas in multi-hop', async () => {
            const secondCert = await generateClientCertificate('Second Hop');
            const encodedFirst = encodeURIComponent(testPem);
            const encodedSecond = encodeURIComponent(secondCert.cert);
            // First element has Subject with commas, second element follows
            const xfcc = `Subject="CN=client,OU=team";Cert="${encodedFirst}",Subject="CN=proxy";Cert="${encodedSecond}"`;
            const cert = parseXfcc(xfcc);

            assert.ok(cert, 'Should parse first element despite commas in quoted Subject');
            assert.equal(cert.subject.CN, 'Test Parser Client');
        });

        it('should chain multi-block PEM in Chain field via issuerCertificate', async () => {
            // Envoy with `chain: true` only emits Chain= as a single field
            // containing the full chain as URL-encoded multi-block PEM. Pre-fix,
            // pemToCertificate(multiBlockPem) returned the leaf without
            // issuerCertificate (toLegacyObject drops it). Post-fix, parseXfcc
            // splits the multi-block input and links via issuerCertificate.
            const intermediateCert = await generateClientCertificate('Test Intermediate');
            const multiBlock = testPem + intermediateCert.cert;
            const xfcc = `Hash=abc;Chain="${encodeURIComponent(multiBlock)}"`;

            const cert = parseXfcc(xfcc);
            assert.ok(cert, 'Should parse multi-block Chain field');
            assert.equal(cert.subject.CN, 'Test Parser Client');
            assert.ok(cert.issuerCertificate, 'Chain should be linked via issuerCertificate');
            assert.equal(cert.issuerCertificate.subject.CN, 'Test Intermediate');
        });

        it('should prefer Chain over Cert when both fields are present', async () => {
            // Envoy with both `cert: true` and `chain: true` emits Cert= (leaf)
            // and Chain= (full chain). The Chain field carries strictly more
            // information than Cert, so we prefer Chain.
            const intermediateCert = await generateClientCertificate('Test Intermediate');
            const multiBlock = testPem + intermediateCert.cert;
            // Cert appears AFTER Chain. This ordering matters: it ensures the
            // parser routes each key to its own variable. If the parser routed
            // both to the same variable (e.g. last-write-wins), the late Cert
            // would overwrite Chain and we'd silently lose the chain info.
            const xfcc = `Hash=abc;Chain="${encodeURIComponent(multiBlock)}";Cert="${encodeURIComponent(testPem)}"`;

            const cert = parseXfcc(xfcc);
            assert.ok(cert);
            assert.equal(cert.subject.CN, 'Test Parser Client');
            // If we'd picked Cert (leaf-only), issuerCertificate would be undefined.
            assert.ok(cert.issuerCertificate, 'Should pick Chain so chain info is preserved');
            assert.equal(cert.issuerCertificate.subject.CN, 'Test Intermediate');
        });

        it('should still prefer Chain when Cert appears before Chain', async () => {
            // Same prefer-Chain semantic, opposite key order. Pinning that the
            // preference is not order-dependent (i.e. parser collects all keys
            // first, then chooses, rather than first-or-last-match).
            const intermediateCert = await generateClientCertificate('Test Intermediate');
            const multiBlock = testPem + intermediateCert.cert;
            const xfcc = `Hash=abc;Cert="${encodeURIComponent(testPem)}";Chain="${encodeURIComponent(multiBlock)}"`;

            const cert = parseXfcc(xfcc);
            assert.ok(cert);
            assert.equal(cert.subject.CN, 'Test Parser Client');
            assert.ok(cert.issuerCertificate);
            assert.equal(cert.issuerCertificate.subject.CN, 'Test Intermediate');
        });

        it('should drop a bad block in multi-block Chain and return the valid leaf', () => {
            const invalidBlock = '-----BEGIN CERTIFICATE-----\nNOT_VALID_BASE64\n-----END CERTIFICATE-----\n';
            const xfcc = `Hash=abc;Chain="${encodeURIComponent(testPem + invalidBlock)}"`;

            const cert = parseXfcc(xfcc);
            assert.ok(cert, 'Bad block dropped, valid leaf returned');
            assert.equal(cert.subject.CN, 'Test Parser Client');
        });

        it('should drop a mid-chain bad block and chain around it cleanly', async () => {
            // Three blocks: valid leaf, invalid intermediate, valid second cert.
            // Without the .filter(Boolean), the leaf's issuerCertificate would
            // get set to null instead of pointing past the bad block.
            const intermediateCert = await generateClientCertificate('Test Intermediate');
            const invalidBlock = '-----BEGIN CERTIFICATE-----\nNOT_VALID_BASE64\n-----END CERTIFICATE-----\n';
            const blob = testPem + invalidBlock + intermediateCert.cert;
            const xfcc = `Hash=abc;Chain="${encodeURIComponent(blob)}"`;

            const cert = parseXfcc(xfcc);
            assert.ok(cert);
            assert.equal(cert.subject.CN, 'Test Parser Client');
            // Bad block was dropped, so the leaf's issuerCertificate should
            // point to the intermediate cert (the next valid block) rather
            // than null/undefined.
            assert.ok(cert.issuerCertificate, 'leaf must chain to next valid cert, not null from dropped block');
            assert.equal(cert.issuerCertificate.subject.CN, 'Test Intermediate');
        });

        it('should return null when every block in multi-block Chain is invalid', () => {
            const invalidBlock1 = '-----BEGIN CERTIFICATE-----\nNOT_VALID_BASE64_1\n-----END CERTIFICATE-----\n';
            const invalidBlock2 = '-----BEGIN CERTIFICATE-----\nNOT_VALID_BASE64_2\n-----END CERTIFICATE-----\n';
            const xfcc = `Hash=abc;Chain="${encodeURIComponent(invalidBlock1 + invalidBlock2)}"`;

            assert.equal(parseXfcc(xfcc), null);
        });

        it('should ignore an unterminated trailing PEM block in Chain', () => {
            // Valid leaf followed by BEGIN with no END - scanner should stop
            // there rather than hang or include junk in the leaf.
            const truncated = '-----BEGIN CERTIFICATE-----\nMIIBkTCCATug==\n';
            const xfcc = `Hash=abc;Chain="${encodeURIComponent(testPem + truncated)}"`;

            const cert = parseXfcc(xfcc);
            assert.ok(cert);
            assert.equal(cert.subject.CN, 'Test Parser Client');
        });

        it('should return null when Chain value has malformed URL encoding', () => {
            // %G0 is not a valid percent-encoded sequence; decodeURIComponent
            // throws URIError, which the outer try/catch turns into null.
            assert.equal(parseXfcc('Hash=abc;Chain=%G0'), null);
        });
    });

    describe('parseBase64Der (Cloudflare format)', () => {
        it('should parse base64-encoded DER certificate', () => {
            const encoded = encodeAsCloudflare(testDer);
            const cert = parseBase64Der(encoded);

            assert.ok(cert);
            assert.equal(cert.subject.CN, 'Test Parser Client');
        });

        it('should return null for empty input', () => {
            assert.equal(parseBase64Der(''), null);
        });

        it('should return null for invalid base64', () => {
            assert.equal(parseBase64Der('not valid base64!!!'), null);
        });

        it('should return null for valid base64 but invalid DER', () => {
            const invalid = Buffer.from('not a certificate').toString('base64');
            assert.equal(parseBase64Der(invalid), null);
        });

        it('should return null for empty parts after splitting (comma-only)', () => {
            assert.equal(parseBase64Der(',,,'), null);
        });

        it('should return null when all certs in chain are invalid', () => {
            const invalidCert = Buffer.from('invalid').toString('base64');
            assert.equal(parseBase64Der(`${invalidCert},${invalidCert}`), null);
        });

        it('should link cert chain via issuerCertificate for multiple valid certs', () => {
            // Create two different encodings of the same cert (simulating a chain)
            const cert1 = encodeAsCloudflare(testDer);
            const cert2 = encodeAsCloudflare(testDer);

            const result = parseBase64Der(`${cert1},${cert2}`);
            assert.ok(result);
            assert.ok(result.issuerCertificate);
            assert.equal(result.subject.CN, 'Test Parser Client');
            assert.equal(result.issuerCertificate.subject.CN, 'Test Parser Client');
        });

        it('should not set issuerCertificate on the last cert in chain', () => {
            // Verifies the chain linking loop (i < certs.length - 1) stops correctly
            const cert1 = encodeAsCloudflare(testDer);
            const cert2 = encodeAsCloudflare(testDer);

            const result = parseBase64Der(`${cert1},${cert2}`);
            assert.ok(result);
            assert.ok(result.issuerCertificate, 'first cert should have issuerCertificate');
            assert.equal(result.issuerCertificate.issuerCertificate, undefined,
                'last cert in chain should not have issuerCertificate set by parser');
        });

        it('should drop invalid certs and chain remaining valid certs', () => {
            const validBase64 = encodeAsCloudflare(testDer);
            const invalidBase64 = Buffer.from('invalid-cert-data').toString('base64');

            const result = parseBase64Der(`${validBase64},${invalidBase64},${validBase64}`);
            assert.ok(result);
            assert.ok(result.issuerCertificate, 'two valid certs should be chained');
            assert.equal(result.issuerCertificate.issuerCertificate, undefined,
                'only two valid certs in chain, not three');
        });

        it('should return single valid cert when others in chain are invalid', () => {
            const validBase64 = encodeAsCloudflare(testDer);
            const invalidBase64 = Buffer.from('invalid-cert-data').toString('base64');

            const result = parseBase64Der(`${invalidBase64},${validBase64},${invalidBase64}`);
            assert.ok(result);
            assert.equal(result.subject.CN, 'Test Parser Client');
            assert.equal(result.issuerCertificate, undefined,
                'single surviving cert should not have issuerCertificate');
        });
    });

    describe('parseRfc9440 (GCP format)', () => {
        it('should parse RFC 9440 format certificate with colon delimiters', () => {
            const encoded = encodeAsRfc9440(testDer);
            const cert = parseRfc9440(encoded);

            assert.ok(cert);
            assert.equal(cert.subject.CN, 'Test Parser Client');
        });

        it('should handle input without colon delimiters', () => {
            // Some implementations might strip the colons
            const encoded = testDer.toString('base64');
            const cert = parseRfc9440(encoded);

            assert.ok(cert);
            assert.equal(cert.subject.CN, 'Test Parser Client');
        });

        it('should return null for empty input', () => {
            assert.equal(parseRfc9440(''), null);
        });

        it('should return null for invalid DER in RFC 9440 format', () => {
            // Valid RFC 9440 structure but invalid DER content
            const invalid = ':' + Buffer.from('not a certificate').toString('base64') + ':';
            assert.equal(parseRfc9440(invalid), null);
        });
    });

    describe('pemToCertificate', () => {
        it('should convert PEM to PeerCertificate-like object', () => {
            const cert = pemToCertificate(testPem);

            assert.ok(cert);
            assert.ok(cert.subject);
            assert.equal(cert.subject.CN, 'Test Parser Client');
            assert.ok(cert.issuer);
            assert.ok(cert.valid_from);
            assert.ok(cert.valid_to);
        });

        it('should throw for invalid PEM', () => {
            assert.throws(() => pemToCertificate('not a certificate'));
        });
    });

    describe('derToCertificate', () => {
        it('should convert DER buffer to PeerCertificate-like object', () => {
            const cert = derToCertificate(testDer);

            assert.ok(cert);
            assert.equal(cert.subject.CN, 'Test Parser Client');
        });

        it('should throw for invalid DER', () => {
            assert.throws(() => derToCertificate(Buffer.from('not a certificate')));
        });
    });

    describe('parseHeaderValue', () => {
        it('should dispatch to correct parser based on encoding', () => {
            const urlPemEncoded = encodeAsNginx(testPem);
            assert.equal(parseHeaderValue(urlPemEncoded, 'url-pem').subject.CN, 'Test Parser Client');

            const awsEncoded = encodeAsAwsAlb(testPem);
            assert.equal(parseHeaderValue(awsEncoded, 'url-pem-aws').subject.CN, 'Test Parser Client');

            const xfccEncoded = encodeAsEnvoy(testPem);
            assert.equal(parseHeaderValue(xfccEncoded, 'xfcc').subject.CN, 'Test Parser Client');

            const base64DerEncoded = encodeAsCloudflare(testDer);
            assert.equal(parseHeaderValue(base64DerEncoded, 'base64-der').subject.CN, 'Test Parser Client');

            const rfc9440Encoded = encodeAsRfc9440(testDer);
            assert.equal(parseHeaderValue(rfc9440Encoded, 'rfc9440').subject.CN, 'Test Parser Client');
        });

        it('should return null for unknown encoding', () => {
            assert.equal(parseHeaderValue('test', 'unknown-encoding'), null);
        });

        it('should return null for url-pem with empty input', () => {
            // Explicitly tests url-pem case in switch (kills switch body mutation)
            assert.equal(parseHeaderValue('', 'url-pem'), null);
        });

        it('should return null for url-pem-aws with empty input', () => {
            assert.equal(parseHeaderValue('', 'url-pem-aws'), null);
        });

        it('should return null for xfcc with empty input', () => {
            assert.equal(parseHeaderValue('', 'xfcc'), null);
        });

        it('should return null for base64-der with empty input', () => {
            assert.equal(parseHeaderValue('', 'base64-der'), null);
        });

        it('should return null for rfc9440 with empty input', () => {
            assert.equal(parseHeaderValue('', 'rfc9440'), null);
        });
    });

    describe('getCertificateFromHeaders', () => {
        it('should extract certificate using aws-alb preset', () => {
            const encoded = encodeAsAwsAlb(testPem);
            const headers = { 'x-amzn-mtls-clientcert': encoded };

            const cert = getCertificateFromHeaders(headers, { certificateSource: 'aws-alb' });
            assert.ok(cert);
            assert.equal(cert.subject.CN, 'Test Parser Client');
        });

        it('should extract certificate using envoy preset', () => {
            const encoded = encodeAsEnvoy(testPem);
            const headers = { 'x-forwarded-client-cert': encoded };

            const cert = getCertificateFromHeaders(headers, { certificateSource: 'envoy' });
            assert.ok(cert);
            assert.equal(cert.subject.CN, 'Test Parser Client');
        });

        it('should extract certificate using cloudflare preset', () => {
            const encoded = encodeAsCloudflare(testDer);
            const headers = { 'cf-client-cert-der-base64': encoded };

            const cert = getCertificateFromHeaders(headers, { certificateSource: 'cloudflare' });
            assert.ok(cert);
            assert.equal(cert.subject.CN, 'Test Parser Client');
        });

        it('should extract certificate using traefik preset', () => {
            const encoded = encodeAsTraefik(testDer);
            const headers = { 'x-forwarded-tls-client-cert': encoded };

            const cert = getCertificateFromHeaders(headers, { certificateSource: 'traefik' });
            assert.ok(cert);
            assert.equal(cert.subject.CN, 'Test Parser Client');
        });

        it('should extract certificate using custom header and encoding', () => {
            const encoded = encodeAsNginx(testPem);
            const headers = { 'x-custom-cert': encoded };

            const cert = getCertificateFromHeaders(headers, {
                certificateHeader: 'X-Custom-Cert',
                headerEncoding: 'url-pem',
            });
            assert.ok(cert);
            assert.equal(cert.subject.CN, 'Test Parser Client');
        });

        it('should return null if header is missing', () => {
            const cert = getCertificateFromHeaders({}, { certificateSource: 'aws-alb' });
            assert.equal(cert, null);
        });

        it('should return null for invalid preset', () => {
            const cert = getCertificateFromHeaders({}, { certificateSource: 'invalid-preset' });
            assert.equal(cert, null);
        });

        it('should return null if no configuration provided', () => {
            const cert = getCertificateFromHeaders({ 'x-amzn-mtls-clientcert': 'test' }, {});
            assert.equal(cert, null);
        });

        it('should allow certificateHeader to override preset header name', () => {
            const encoded = encodeAsAwsAlb(testPem);
            // Use aws-alb encoding but custom header name
            const headers = { 'my-custom-header': encoded };

            const cert = getCertificateFromHeaders(headers, {
                certificateSource: 'aws-alb',
                certificateHeader: 'my-custom-header',
            });
            assert.ok(cert);
            assert.equal(cert.subject.CN, 'Test Parser Client');
        });

        it('should return null when only headerName is set (no encoding)', () => {
            const cert = getCertificateFromHeaders(
                { 'x-custom': 'data' },
                { certificateHeader: 'X-Custom' } // No headerEncoding
            );
            assert.equal(cert, null);
        });

        it('should return null when only encoding is set (no header)', () => {
            const cert = getCertificateFromHeaders(
                { 'x-custom': 'data' },
                { headerEncoding: 'url-pem' } // No certificateHeader
            );
            assert.equal(cert, null);
        });

        it('should allow headerEncoding to override preset encoding', () => {
            // aws-alb preset uses url-pem-aws encoding, but we override to url-pem
            const encoded = encodeAsNginx(testPem);
            const headers = { 'x-amzn-mtls-clientcert': encoded };

            const cert = getCertificateFromHeaders(headers, {
                certificateSource: 'aws-alb',
                headerEncoding: 'url-pem',
            });
            assert.ok(cert);
            assert.equal(cert.subject.CN, 'Test Parser Client');
        });

        it('should return null for empty string header value', () => {
            const headers = { 'x-amzn-mtls-clientcert': '' };
            const cert = getCertificateFromHeaders(headers, { certificateSource: 'aws-alb' });
            assert.equal(cert, null);
        });

        it('should return null when header value is a string[] (duplicate headers)', () => {
            const encoded = encodeAsAwsAlb(testPem);
            const headers = { 'x-amzn-mtls-clientcert': [encoded, encoded] };
            const cert = getCertificateFromHeaders(headers, { certificateSource: 'aws-alb' });
            assert.equal(cert, null);
        });
    });

    describe('round-trip verification', () => {
        it('should successfully round-trip through nginx encoding', () => {
            const encoded = encodeAsNginx(testPem);
            const decoded = decodeURIComponent(encoded);
            assert.equal(decoded, testPem);

            const cert = parseUrlPem(encoded);
            assert.equal(cert.subject.CN, 'Test Parser Client');
        });

        it('should successfully round-trip through AWS ALB encoding', () => {
            const encoded = encodeAsAwsAlb(testPem);
            const cert = parseUrlPemAws(encoded);
            assert.equal(cert.subject.CN, 'Test Parser Client');
        });

        it('should successfully round-trip through Envoy XFCC encoding', () => {
            const encoded = encodeAsEnvoy(testPem);
            const cert = parseXfcc(encoded);
            assert.equal(cert.subject.CN, 'Test Parser Client');
        });

        it('should successfully round-trip through RFC 9440 encoding', () => {
            const encoded = encodeAsRfc9440(testDer);
            const cert = parseRfc9440(encoded);
            assert.equal(cert.subject.CN, 'Test Parser Client');
        });

        it('should successfully round-trip through Cloudflare encoding', () => {
            const encoded = encodeAsCloudflare(testDer);
            const cert = parseBase64Der(encoded);
            assert.equal(cert.subject.CN, 'Test Parser Client');
        });
    });
});
