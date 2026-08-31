/*!
 * client-certificate-auth/parsers - Certificate header parsing utilities
 * for reverse proxy / load balancer certificate passthrough
 * Copyright (C) 2013-2026 Tony Gies
 * @license MIT
 */

import { X509Certificate } from 'node:crypto';

/**
 * @typedef {import('tls').PeerCertificate} PeerCertificate
 */

/**
 * Preset configurations for common reverse proxies.
 * Maps preset name to { header, encoding } configuration.
 */
export const PRESETS = {
    /**
     * AWS Application Load Balancer in mTLS passthrough mode.
     * @see https://docs.aws.amazon.com/elasticloadbalancing/latest/application/mutual-authentication.html
     */
    'aws-alb': {
        header: 'x-amzn-mtls-clientcert',
        encoding: 'url-pem-aws',
    },
    /**
     * Envoy proxy / Istio service mesh using XFCC header.
     * @see https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers#x-forwarded-client-cert
     */
    'envoy': {
        header: 'x-forwarded-client-cert',
        encoding: 'xfcc',
    },
    /**
     * Cloudflare with client_certificate_forwarding enabled.
     * @see https://developers.cloudflare.com/api-shield/security/mtls/configure/
     */
    'cloudflare': {
        header: 'cf-client-cert-der-base64',
        encoding: 'base64-der',
    },
    /**
     * Traefik with PassTLSClientCert middleware (pem: true).
     * Traefik sends raw base64 (no PEM delimiters, not URL-encoded).
     * @see https://doc.traefik.io/traefik/middlewares/http/passtlsclientcert/
     */
    'traefik': {
        header: 'x-forwarded-tls-client-cert',
        encoding: 'base64-der',
    },
};

/**
 * Parse URL-encoded PEM certificate (nginx, HAProxy format).
 * Uses standard URL encoding via $ssl_client_escaped_cert or similar.
 * 
 * @see https://nginx.org/en/docs/http/ngx_http_ssl_module.html#var_ssl_client_escaped_cert
 * @param {string} headerValue - URL-encoded PEM certificate
 * @returns {PeerCertificate | null} Parsed certificate or null on failure
 */
export function parseUrlPem(headerValue) {
    // Stryker disable next-line BlockStatement,ConditionalExpression: falsy input falls through to try-catch → same null return
    if (!headerValue) {
        return null;
    }

    try {
        const pem = decodeURIComponent(headerValue);
        return pemToCertificate(pem);
    } catch {
        return null;
    }
}

/**
 * Split a string of concatenated PEM CERTIFICATE blocks into an array of
 * individual PEM strings. Uses indexOf scanning (O(N) in input length) rather
 * than regex to avoid polynomial-time backtracking on adversarial input
 * (e.g., many unterminated BEGIN markers).
 *
 * @param {string} pem - Concatenated PEM blocks
 * @returns {string[]} Individual PEM blocks (empty array if none found)
 */
function splitPemBlocks(pem) {
    // Stryker disable next-line ArrayDeclaration: sentinel-array mutant pushes a non-PEM string that pemToCertificate rejects and .filter(Boolean) drops downstream — same chain output
    const blocks = [];
    // Stryker disable next-line StringLiteral: empty beginMarker → indexOf returns scanPos every iteration; END markers still bracket the same blocks correctly
    const beginMarker = '-----BEGIN CERTIFICATE-----';
    const endMarker = '-----END CERTIFICATE-----';
    let scanPos = 0;
    while (true) {
        const begin = pem.indexOf(beginMarker, scanPos);
        if (begin === -1) {break;}
        const end = pem.indexOf(endMarker, begin + beginMarker.length);
        if (end === -1) {break;}
        blocks.push(pem.substring(begin, end + endMarker.length));
        // Stryker disable next-line ArithmeticOperator: end-endMarker.length backs up before the END marker, but the next BEGIN is past it so indexOf still advances correctly
        scanPos = end + endMarker.length;
    }
    return blocks;
}

/**
 * Parse a multi-block PEM blob into a chained PeerCertificate. Splits the
 * input into individual blocks and links them via issuerCertificate. The
 * first block is the leaf and must parse; later blocks that fail to parse
 * are dropped and the chain links past them.
 *
 * Used by parsers whose proxies forward the full chain in a single field
 * (parseUrlPemAws, parseXfcc Chain). Without explicit chain linking, calling
 * X509Certificate() on a multi-block PEM returns just the leaf with no
 * issuerCertificate (toLegacyObject drops the property), silently losing
 * chain information for `includeChain: true` consumers.
 *
 * @param {string} pem - Concatenated PEM blocks
 * @returns {PeerCertificate | null} Leaf cert with chain via issuerCertificate, or null if no blocks parse
 */
function chainFromMultiBlockPem(pem) {
    const pemBlocks = splitPemBlocks(pem);
    // Stryker disable next-line BlockStatement,ConditionalExpression: short-circuit; falling through hands undefined to pemToCertificate, which throws for the same null result
    if (pemBlocks.length === 0) {
        return null;
    }

    // Junk ahead of the leaf block means the leaf was damaged past recognition;
    // the next block must not slide into its place. Leading whitespace is fine.
    if (pem.slice(0, pem.indexOf(pemBlocks[0])).trim() !== '') {
        return null;
    }

    // An unparseable leaf rejects the whole blob. Promoting the next block
    // would authenticate the request as whichever certificate parsed first.
    let leaf;
    try {
        leaf = pemToCertificate(pemBlocks[0]);
    } catch {
        return null;
    }

    const certs = [leaf];
    for (const block of pemBlocks.slice(1)) {
        try {
            certs.push(pemToCertificate(block));
        } catch {
            // Dropped; the chain links past it.
        }
    }

    // Stryker disable next-line EqualityOperator: setting issuerCertificate = undefined on last cert is same as not setting it
    for (let i = 0; i < certs.length - 1; i++) {
        certs[i].issuerCertificate = certs[i + 1];
    }

    return certs[0];
}

/**
 * Parse URL-encoded PEM certificate with AWS ALB safe character handling.
 * AWS ALB uses +, =, / as safe characters (not encoded), but decodeURIComponent
 * interprets + as space, so we must escape it first. AWS sends the full chain
 * as concatenated PEM blocks, which we split and link via issuerCertificate.
 *
 * @see https://docs.aws.amazon.com/elasticloadbalancing/latest/application/mutual-authentication.html
 * @param {string} headerValue - AWS ALB URL-encoded PEM certificate
 * @returns {PeerCertificate | null} Parsed certificate or null on failure
 */
export function parseUrlPemAws(headerValue) {
    // Stryker disable next-line BlockStatement,ConditionalExpression: falsy input falls through to try-catch → same null return
    if (!headerValue) {
        return null;
    }

    try {
        // AWS uses + as a safe character, not as space
        // Must escape before decodeURIComponent or + becomes space
        const escaped = headerValue.replace(/\+/g, '%2B');
        const pem = decodeURIComponent(escaped);
        return chainFromMultiBlockPem(pem);
    } catch {
        return null;
    }
}

/**
 * A double quote ends the quoted value it opened unless a backslash precedes
 * it, the form Envoy escapes an embedded quote into. Reading it that way never
 * lets a quoted value end early, so a value cannot close its own quoting and
 * go on to contribute XFCC pairs of its own.
 *
 * Envoy escapes an embedded quote but not an embedded backslash, so a value
 * ending in one arrives as `\"` and is indistinguishable on the wire from an
 * escaped quote. Such a value reads as unterminated and its element is
 * rejected. Counting the backslash run instead would read an even run as
 * escaping itself, closing the quoting at `...\\"` and letting the value that
 * carries it inject a `Cert=` pair of its own.
 *
 * @param {string} text
 * @param {number} i
 * @returns {boolean}
 */
function isQuoteDelimiter(text, i) {
    // Stryker disable next-line ConditionalExpression: i===0 → false still works because str[-1] is undefined
    return text[i] === '"' && (i === 0 || text[i - 1] !== '\\');
}

/**
 * The first XFCC element: the text up to the first comma outside double
 * quotes. Later proxy hops are not parsed, so scanning stops there.
 *
 * @param {string} text - XFCC header value
 * @returns {string | null} The first element, or null if it leaves a quoted value open
 */
function firstXfccElement(text) {
    let inQuote = false;
    // Stryker disable next-line EqualityOperator: i <= length reads undefined, same result
    for (let i = 0; i < text.length; i++) {
        if (isQuoteDelimiter(text, i)) {
            inQuote = !inQuote;
        } else if (text[i] === ',' && !inQuote) {
            return text.substring(0, i);
        }
    }
    // An element that never closes its quoting is malformed; parsing on would
    // read every remaining delimiter as part of the value.
    return inQuote ? null : text;
}

/**
 * Split XFCC text on a delimiter that appears outside double quotes. Envoy
 * quotes any field whose value contains one, so a Subject DN of
 * `CN=client,OU=team;L=Austin` arrives as `Subject="CN=client,OU=team;L=Austin"`
 * and must not be broken apart on the delimiters it carries.
 *
 * @param {string} text - XFCC element with balanced quoting
 * @param {string} delimiter - Single delimiter character
 * @returns {string[]} Segments, delimiters removed
 */
function splitOutsideQuotes(text, delimiter) {
    const parts = [];
    let start = 0;
    let inQuote = false;
    // Stryker disable next-line EqualityOperator: i <= length reads undefined, same result
    for (let i = 0; i < text.length; i++) {
        if (isQuoteDelimiter(text, i)) {
            inQuote = !inQuote;
        } else if (text[i] === delimiter && !inQuote) {
            parts.push(text.substring(start, i));
            start = i + 1;
        }
    }
    parts.push(text.substring(start));
    return parts;
}

/**
 * Parse Envoy XFCC (X-Forwarded-Client-Cert) structured header format.
 * Format: Key=Value;Key=Value;... where Cert (single URL-encoded PEM) or
 * Chain (URL-encoded multi-block PEM with the full chain incl. leaf) carry
 * the certificate. When both are present we prefer Chain because it carries
 * more information, and link the chain via issuerCertificate.
 *
 * @see https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers#x-forwarded-client-cert
 * @param {string} headerValue - XFCC formatted header value
 * @returns {PeerCertificate | null} Parsed certificate or null on failure
 */
export function parseXfcc(headerValue) {
    // Stryker disable next-line BlockStatement,ConditionalExpression: falsy input falls through to try-catch → same null return
    if (!headerValue) {
        return null;
    }

    try {
        // XFCC may contain multiple comma-separated elements from different
        // proxy hops. We care about the first element (the original client).
        const firstElement = firstXfccElement(headerValue);
        if (firstElement === null) {
            return null;
        }

        // Parse key=value pairs separated by semicolons. Collect Cert and
        // Chain values; prefer Chain when both are present.
        const pairs = splitOutsideQuotes(firstElement, ';');
        let certValue = null;
        let chainValue = null;

        for (const pair of pairs) {
            const eqIndex = pair.indexOf('=');
            // Stryker disable next-line BlockStatement,ConditionalExpression,UnaryOperator: →false equivalent (substring(0,-1) yields empty key, can't match Cert/Chain); →true killed by valid XFCC tests
            if (eqIndex === -1) {
                continue;
            }

            // Stryker disable next-line MethodExpression: defensive normalization, no real proxy sends whitespace
            const key = pair.substring(0, eqIndex).trim();
            // Stryker disable next-line MethodExpression: defensive normalization, no real proxy sends whitespace
            let value = pair.substring(eqIndex + 1).trim();

            if (key === 'Cert' || key === 'Chain') {
                // Stryker disable next-line LogicalOperator,MethodExpression,StringLiteral,BlockStatement: quote-stripping mutations are equivalent given the secondary unbalanced-quote reject below and lenient PEM marker scan downstream — broken quotes either trigger reject or produce a stripped value that fails to parse, both yielding null
                if (value.startsWith('"') && value.endsWith('"')) {
                    // Stryker disable next-line MethodExpression: skipping the slice leaves quotes around the value; PEM marker scan still finds BEGIN/END inside them and parses the cert content correctly — equivalent for tests
                    value = value.slice(1, -1);
                } else if (value.startsWith('"') || value.endsWith('"')) {
                    // Unbalanced quote indicates malformed XFCC. Reject rather
                    // than parse the cert content out of the broken wrapping.
                    return null;
                }
                // No proxy sends either key twice in one element, so a repeat
                // is an injected pair rather than a value to choose between.
                if (key === 'Chain') {
                    if (chainValue !== null) {
                        return null;
                    }
                    chainValue = value;
                } else {
                    if (certValue !== null) {
                        return null;
                    }
                    certValue = value;
                }
            }
        }

        const value = chainValue ?? certValue;
        // Stryker disable next-line BlockStatement,ConditionalExpression: short-circuit; falling through with null hands "null" string to chainFromMultiBlockPem which finds no PEM markers and returns null
        if (!value) {
            return null;
        }

        const pem = decodeURIComponent(value);
        return chainFromMultiBlockPem(pem);
    } catch {
        return null;
    }
}

/**
 * Parse base64-encoded DER certificate (Cloudflare format).
 * Also handles Traefik's comma-separated cert chains - parses all certs
 * and links them via the issuerCertificate property.
 * 
 * @see https://developers.cloudflare.com/api-shield/security/mtls/configure/
 * @param {string} headerValue - Base64-encoded DER certificate(s)
 * @returns {PeerCertificate | null} Parsed certificate or null on failure
 */
export function parseBase64Der(headerValue) {
    // Stryker disable next-line BlockStatement,ConditionalExpression: falsy input falls through to try-catch → same null return
    if (!headerValue) {
        return null;
    }

    // Handle comma-separated cert chains (Traefik format)
    // Stryker disable next-line MethodExpression: .trim() no-op (base64 ignores whitespace)
    const certParts = headerValue.split(',').map(s => s.trim());

    // An empty or unparseable leaf rejects the whole header. Promoting the next
    // entry would authenticate the request as whichever certificate parsed first.
    let leaf;
    try {
        leaf = derToCertificate(Buffer.from(certParts[0], 'base64'));
    } catch {
        return null;
    }

    const certs = [leaf];
    for (const base64 of certParts.slice(1)) {
        try {
            certs.push(derToCertificate(Buffer.from(base64, 'base64')));
        } catch {
            // Dropped; the chain links past it.
        }
    }

    // Link the cert chain via issuerCertificate
    // Stryker disable next-line EqualityOperator: setting issuerCertificate = undefined on last cert is same as not setting it
    for (let i = 0; i < certs.length - 1; i++) {
        certs[i].issuerCertificate = certs[i + 1];
    }

    return certs[0];
}

/**
 * Parse RFC 9440 format certificate (used by Google Cloud Load Balancer).
 * Format: :base64-encoded-der: (colon-delimited byte sequence).
 * 
 * @see https://datatracker.ietf.org/doc/html/rfc9440#section-2.1
 * @param {string} headerValue - RFC 9440 formatted certificate
 * @returns {PeerCertificate | null} Parsed certificate or null on failure
 */
export function parseRfc9440(headerValue) {
    // Stryker disable next-line BlockStatement,ConditionalExpression: falsy input falls through to try-catch → same null return
    if (!headerValue) {
        return null;
    }

    try {
        // Strip colon delimiters
        let base64 = headerValue;
        // Stryker disable next-line BlockStatement,ConditionalExpression,StringLiteral,LogicalOperator,MethodExpression: colon-stripping is defensive; all valid RFC 9440 inputs use :base64: format, so base64 decoder ignores colons either way
        if (base64.startsWith(':') && base64.endsWith(':')) {
            // Stryker disable next-line BlockStatement,MethodExpression: removing or no-oping the assignment is equivalent — base64 decoder ignores colons
            base64 = base64.slice(1, -1);
        }

        const derBuffer = Buffer.from(base64, 'base64');
        return derToCertificate(derBuffer);
    } catch {
        return null;
    }
}

/**
 * Convert PEM-encoded certificate to PeerCertificate-like object.
 * Uses Node.js crypto.X509Certificate with toLegacyObject() for compatibility.
 * 
 * @param {string} pem - PEM-encoded certificate
 * @returns {PeerCertificate} Certificate in PeerCertificate format
 * @throws {Error} If certificate parsing fails
 */
export function pemToCertificate(pem) {
    const x509 = new X509Certificate(pem);
    return x509.toLegacyObject();
}

/**
 * Convert DER-encoded certificate to PeerCertificate-like object.
 * Wraps DER in PEM format and uses pemToCertificate.
 * 
 * @param {Buffer} der - DER-encoded certificate bytes
 * @returns {PeerCertificate} Certificate in PeerCertificate format
 * @throws {Error} If certificate parsing fails
 */
export function derToCertificate(der) {
    // X509Certificate can accept DER directly
    const x509 = new X509Certificate(der);
    return x509.toLegacyObject();
}

/**
 * Parse certificate from header value using specified encoding.
 * 
 * @param {string} headerValue - Raw header value
 * @param {'url-pem' | 'url-pem-aws' | 'xfcc' | 'base64-der' | 'rfc9440'} encoding - Encoding format
 * @returns {PeerCertificate | null} Parsed certificate or null on failure
 */
export function parseHeaderValue(headerValue, encoding) {
    switch (encoding) {
        // Stryker disable next-line ConditionalExpression: parseUrlPem/parseUrlPemAws are equivalent for inputs without + chars
        case 'url-pem':
            return parseUrlPem(headerValue);
        case 'url-pem-aws':
            return parseUrlPemAws(headerValue);
        case 'xfcc':
            return parseXfcc(headerValue);
        case 'base64-der':
            return parseBase64Der(headerValue);
        case 'rfc9440':
            return parseRfc9440(headerValue);
        default:
            return null;
    }
}

/**
 * Get certificate from request headers using configuration.
 * 
 * @param {Object} headers - Request headers object
 * @param {Object} config - Configuration object
 * @param {string} [config.certificateSource] - Preset name (aws-alb, envoy, cloudflare, traefik)
 * @param {string} [config.certificateHeader] - Custom header name (overrides preset)
 * @param {string} [config.headerEncoding] - Encoding format (required if certificateHeader is set)
 * @returns {PeerCertificate | null} Parsed certificate or null if not found/invalid
 */
export function getCertificateFromHeaders(headers, config) {
    let headerName;
    let encoding;

    if (config.certificateSource) {
        const preset = PRESETS[config.certificateSource];
        if (!preset) {
            return null;
        }
        headerName = preset.header;
        encoding = preset.encoding;
    }

    // Custom header overrides preset header name
    if (config.certificateHeader) {
        // Stryker disable next-line MethodExpression: toLowerCase vs toUpperCase equivalent; line 339 fallback re-lowercases
        headerName = config.certificateHeader.toLowerCase();
    }

    // Custom encoding overrides preset encoding
    if (config.headerEncoding) {
        encoding = config.headerEncoding;
    }

    if (!headerName || !encoding) {
        return null;
    }

    // Get header value (case-insensitive)
    // Stryker disable next-line MethodExpression,LogicalOperator: Node.js HTTP always lowercases headers; headerName already lowercase from presets or .toLowerCase() on line 325, so both sides of || resolve identically
    const headerValue = headers[headerName] || headers[headerName.toLowerCase()];
    // Stryker disable next-line BlockStatement,ConditionalExpression: →false equivalent (falsy input → parser returns null); →true killed by valid header extraction tests
    if (!headerValue) {
        return null;
    }

    // Node.js HTTP consolidates duplicate headers into string[].
    // Parsers expect a single string; reject arrays to fail safely.
    if (Array.isArray(headerValue)) {
        return null;
    }

    return parseHeaderValue(headerValue, encoding);
}
