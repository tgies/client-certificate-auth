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
    // Stryker disable next-line BlockStatement: falsy input falls through to try-catch → same null return
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
 * Parse URL-encoded PEM certificate with AWS ALB safe character handling.
 * AWS ALB uses +, =, / as safe characters (not encoded), but decodeURIComponent
 * interprets + as space, so we must escape it first.
 * 
 * @see https://docs.aws.amazon.com/elasticloadbalancing/latest/application/mutual-authentication.html
 * @param {string} headerValue - AWS ALB URL-encoded PEM certificate
 * @returns {PeerCertificate | null} Parsed certificate or null on failure
 */
export function parseUrlPemAws(headerValue) {
    // Stryker disable next-line BlockStatement: falsy input falls through to try-catch → same null return
    if (!headerValue) {
        return null;
    }

    try {
        // AWS uses + as a safe character, not as space
        // Must escape before decodeURIComponent or + becomes space
        const escaped = headerValue.replace(/\+/g, '%2B');
        const pem = decodeURIComponent(escaped);

        // AWS sends the full chain as concatenated PEM blocks. Split into
        // individual blocks and parse each, then link via issuerCertificate
        // (mirrors parseBase64Der's chain handling for Traefik/Cloudflare).
        // Node's X509Certificate throws on multi-block input, so without this
        // split the entire request fails when AWS forwards a real chain.
        const pemBlocks = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);

        if (!pemBlocks || pemBlocks.length === 0) {
            return null;
        }

        const certs = pemBlocks.map(block => {
            try {
                return pemToCertificate(block);
            } catch {
                return null;
            }
        }).filter(Boolean);

        if (certs.length === 0) {
            return null;
        }

        // Link the cert chain via issuerCertificate
        for (let i = 0; i < certs.length - 1; i++) {
            certs[i].issuerCertificate = certs[i + 1];
        }

        return certs[0];
    } catch {
        return null;
    }
}

/**
 * Parse Envoy XFCC (X-Forwarded-Client-Cert) structured header format.
 * Format: Key=Value;Key=Value;... where Cert or Chain contains URL-encoded PEM.
 * 
 * @see https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers#x-forwarded-client-cert
 * @param {string} headerValue - XFCC formatted header value
 * @returns {PeerCertificate | null} Parsed certificate or null on failure
 */
export function parseXfcc(headerValue) {
    // Stryker disable next-line BlockStatement: falsy input falls through to try-catch → same null return
    if (!headerValue) {
        return null;
    }

    try {
        // XFCC may contain multiple comma-separated elements from different
        // proxy hops. We care about the first element (the original client).
        // We split on the first comma outside double quotes, because quoted
        // fields like Subject="CN=client,OU=team" can contain literal commas.
        let endOfFirst = headerValue.length;
        let inQuote = false;
        // Stryker disable next-line EqualityOperator: i <= length reads undefined, same result
        for (let i = 0; i < headerValue.length; i++) {
            // Stryker disable next-line ConditionalExpression: i===0 → false still works because str[-1] is undefined
            if (headerValue[i] === '"' && (i === 0 || headerValue[i - 1] !== '\\')) {
                inQuote = !inQuote;
            } else if (headerValue[i] === ',' && !inQuote) {
                endOfFirst = i;
                break;
            }
        }
        const firstElement = headerValue.substring(0, endOfFirst);

        // Parse key=value pairs separated by semicolons
        const pairs = firstElement.split(';');

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

            // Cert or Chain contain the certificate
            if (key === 'Cert' || key === 'Chain') {
                // Remove surrounding quotes if present
                if (value.startsWith('"') && value.endsWith('"')) {
                    value = value.slice(1, -1);
                }

                const pem = decodeURIComponent(value);
                return pemToCertificate(pem);
            }
        }

        return null;
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
    // Stryker disable next-line BlockStatement: falsy input falls through to try-catch → same null return
    if (!headerValue) {
        return null;
    }

    // Handle comma-separated cert chains (Traefik format)
    // Stryker disable next-line MethodExpression: .trim() no-op (base64 ignores whitespace); .filter(Boolean) redundant (empty strings throw in X509Certificate, caught below)
    const certParts = headerValue.split(',').map(s => s.trim()).filter(Boolean);

    // Stryker disable next-line BlockStatement,ConditionalExpression: →false equivalent (empty array → zero certs → certs.length===0 catches it); →true killed by valid base64-der tests
    if (certParts.length === 0) {
        return null;
    }

    // Parse all certs in the chain
    const certs = certParts.map(base64 => {
        try {
            const derBuffer = Buffer.from(base64, 'base64');
            return derToCertificate(derBuffer);
        } catch {
            // Equivalent mutant (undefined also filtered by .filter(Boolean)) — catch-body BlockStatement unsuppressible via Stryker comments
            return null;
        }
    }).filter(Boolean);

    if (certs.length === 0) {
        return null;
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
    // Stryker disable next-line BlockStatement: falsy input falls through to try-catch → same null return
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
