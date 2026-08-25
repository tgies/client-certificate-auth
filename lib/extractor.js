/*!
 * client-certificate-auth - Certificate extraction module
 * Copyright (C) 2013-2026 Tony Gies
 * @license MIT
 */

import { getCertificateFromHeaders, parseHeaderValue, MAX_CHAIN_CERTS, PRESETS } from './parsers.js';

const VALID_ENCODINGS = ['url-pem', 'url-pem-aws', 'xfcc', 'base64-der', 'rfc9440'];

/**
 * Count a certificate and the issuerCertificate chain linked below it. The
 * chain is always a finite list built during parsing.
 * @param {unknown} cert
 * @returns {number}
 */
function countChain(cert) {
  let count = 0;
  for (let c = cert; c; c = /** @type {any} */ (c).issuerCertificate) {
    count++;
  }
  return count;
}

/**
 * Count the occurrences of a header name in Node's rawHeaders list
 * (alternating name/value entries, original casing).
 * @param {unknown} rawHeaders
 * @param {string} name - Lowercase header name
 * @returns {number}
 */
function countRawHeader(rawHeaders, name) {
  if (!Array.isArray(rawHeaders)) {
    return 0;
  }
  let count = 0;
  for (let i = 0; i < rawHeaders.length; i += 2) {
    if (typeof rawHeaders[i] === 'string' && rawHeaders[i].toLowerCase() === name) {
      count++;
    }
  }
  return count;
}

/**
 * Validate options shared by `extractClientCertificate` and the middleware
 * constructor. Throws on misconfiguration: an unknown preset or encoding, a
 * header-name option that is not a non-empty string, a flag that is not a
 * boolean, `certificateHeader` without an encoding source, `chainHeader` or
 * `verifyHeader` without a leaf header source, or only one of
 * `verifyHeader`/`verifyValue`. Omitted or `undefined` options are treated
 * as the empty object; any other non-object value, `null` and arrays among
 * them, throws a `TypeError`.
 *
 * @param {ExtractorOptions} [options]
 * @throws {Error} when options are malformed
 */
export function validateExtractorOptions(options = {}) {
  if (options === null || typeof options !== 'object' || Array.isArray(options)) {
    throw new TypeError('client-certificate-auth: options must be an object');
  }

  const {
    certificateSource,
    certificateHeader,
    chainHeader,
    headerEncoding,
    fallbackToSocket,
    includeChain,
    verifyHeader,
    verifyValue,
  } = options;

  for (const [name, value] of Object.entries({ certificateHeader, chainHeader, verifyHeader, verifyValue })) {
    if (value !== undefined && (typeof value !== 'string' || value === '')) {
      throw new Error(`client-certificate-auth: ${name} must be a non-empty string`);
    }
  }

  for (const [name, value] of Object.entries({ fallbackToSocket, includeChain })) {
    if (value !== undefined && typeof value !== 'boolean') {
      throw new Error(`client-certificate-auth: ${name} must be a boolean`);
    }
  }

  if ((verifyHeader === undefined) !== (verifyValue === undefined)) {
    throw new Error(
      'client-certificate-auth: verifyHeader and verifyValue must both be provided together, or both omitted'
    );
  }

  if (certificateSource !== undefined && !Object.hasOwn(PRESETS, certificateSource)) {
    throw new Error(
      `client-certificate-auth: unknown certificateSource '${certificateSource}'. Valid values: ${Object.keys(PRESETS).join(', ')}`
    );
  }

  if (headerEncoding !== undefined && !VALID_ENCODINGS.includes(headerEncoding)) {
    throw new Error(
      `client-certificate-auth: unknown headerEncoding '${headerEncoding}'. Valid values: ${VALID_ENCODINGS.join(', ')}`
    );
  }

  if (certificateHeader !== undefined && certificateSource === undefined && headerEncoding === undefined) {
    throw new Error(
      'client-certificate-auth: certificateHeader requires headerEncoding (or a certificateSource preset that supplies one)'
    );
  }

  if (chainHeader !== undefined && certificateSource === undefined && certificateHeader === undefined) {
    throw new Error(
      'client-certificate-auth: chainHeader requires certificateSource or certificateHeader (chain header must accompany a leaf header configuration)'
    );
  }

  if (verifyHeader !== undefined && certificateSource === undefined && certificateHeader === undefined) {
    throw new Error(
      'client-certificate-auth: verifyHeader requires certificateSource or certificateHeader (verification applies to header-based extraction only)'
    );
  }
}

/**
 * Rejection reason codes:
 * - 'verification_header_mismatch' - Proxy verify header didn't match expected value
 * - 'header_missing_or_malformed' - Header extraction failed and no fallback configured
 * - 'socket_not_authorized' - Socket not authorized for TLS client cert, or unreadable
 * - 'certificate_not_retrievable' - Socket authorized but getPeerCertificate() is missing, returned empty, or threw
 * @typedef {'verification_header_mismatch' | 'header_missing_or_malformed' | 'socket_not_authorized' | 'certificate_not_retrievable'} ExtractionFailureReason
 */

/**
 * @typedef {Object} ExtractionSuccess
 * @property {true} success - Always true on this arm of the union
 * @property {import('./parsers.js').ChainedPeerCertificate} certificate - Extracted certificate
 * @property {null} reason - Always null on this arm of the union
 */

/**
 * @typedef {Object} ExtractionFailure
 * @property {false} success - Always false on this arm of the union
 * @property {null} certificate - Always null on this arm of the union
 * @property {ExtractionFailureReason} reason - Rejection reason code
 *
 * Rejection reasons:
 * - 'verification_header_mismatch' - Proxy verify header didn't match expected value
 * - 'header_missing_or_malformed' - Header extraction failed and no fallback configured
 * - 'socket_not_authorized' - Socket not authorized for TLS client cert, or unreadable
 * - 'certificate_not_retrievable' - Socket authorized but getPeerCertificate() is missing, returned empty, or threw
 */

/**
 * Discriminated on `success`: narrowing on it exposes `certificate` on
 * success and `reason` on failure without null checks.
 * @typedef {ExtractionSuccess | ExtractionFailure} ExtractionResult
 */

/**
 * @typedef {Object} ExtractorOptions
 * @property {'aws-alb' | 'aws-alb-verify' | 'azure-app-service' | 'cloudflare' | 'cloudflare-rfc9440' | 'envoy' | 'traefik'} [certificateSource] - Preset
 *   configuration. Trust boundary: the proxy must strip the preset's header from external
 *   requests; any source that can set it is trusted to assert client identity.
 * @property {string} [certificateHeader] - Custom header name. Trust boundary: the proxy must
 *   strip this header from external requests; any source that can set it is trusted to assert
 *   client identity.
 * @property {string} [chainHeader] - Optional second header carrying the certificate chain
 *   alongside the leaf. Split on commas per RFC 9440, each item parsed with the same
 *   `headerEncoding`, results linked via `issuerCertificate`. Leaf and chain together may
 *   not exceed MAX_CHAIN_CERTS certificates; a longer chain header rejects the request.
 *   For non-RFC-9440 encodings the comma split may not match the encoding's list convention.
 * @property {'url-pem' | 'url-pem-aws' | 'xfcc' | 'base64-der' | 'rfc9440'} [headerEncoding] - Header encoding
 * @property {boolean} [fallbackToSocket=false] - Try socket if header extraction fails
 * @property {boolean} [includeChain=false] - Include issuerCertificate chain
 * @property {string} [verifyHeader] - Header name for upstream verification status. Pairs
 *   with `verifyValue`, and requires `certificateSource` or `certificateHeader`:
 *   verification applies to header-based extraction only.
 * @property {string} [verifyValue] - Expected value for successful verification. Pairs
 *   with `verifyHeader`.
 */

/**
 * Extract client certificate from request.
 *
 * Works with both header-based extraction (reverse proxy scenarios) and socket-based
 * extraction (direct TLS connections). Returns a structured result object instead of
 * throwing or using callbacks, making it suitable for any framework adapter.
 *
 * @param {Object} req - Request object with headers and optional socket. A missing or
 *   non-object `headers` field, one whose accessor throws, and one holding a
 *   property whose accessor throws are all treated as having no headers.
 * @param {Record<string, string | string[] | undefined>} [req.headers] - HTTP headers object
 * @param {string[]} [req.rawHeaders] - Node's raw header list; a certificate or
 *   verification header that appears more than once is rejected
 * @param {Object} [req.socket] - TLS socket with getPeerCertificate() method
 * @param {boolean} [req.socket.authorized] - Whether socket was authorized
 * @param {(detailed: boolean) => import('tls').PeerCertificate} [req.socket.getPeerCertificate] - Get peer certificate
 * @param {ExtractorOptions} [options={}] - Extraction options
 * @returns {ExtractionResult}
 *
 * @example
 * // AWS ALB header extraction
 * const result = extractClientCertificate(req, { certificateSource: 'aws-alb' });
 * if (result.success) {
 *   console.log('Certificate CN:', result.certificate.subject.CN);
 * } else {
 *   console.error('Extraction failed:', result.reason);
 * }
 *
 * @example
 * // Socket extraction with fallback
 * const result = extractClientCertificate(req, {
 *   certificateSource: 'envoy',
 *   fallbackToSocket: true
 * });
 */
export function extractClientCertificate(req, options = {}) {
  validateExtractorOptions(options);

  const {
    certificateSource,
    certificateHeader,
    chainHeader,
    headerEncoding,
    fallbackToSocket = false,
    includeChain = false,
    verifyHeader,
    verifyValue,
  } = options;

  const useHeaders = Boolean(certificateSource || certificateHeader);
  let cert = null;

  // Try header-based extraction first if configured
  if (useHeaders) {
    // Read once into a null-prototype map: a throwing accessor fails here
    // rather than at whichever lookup reaches it.
    /** @type {Record<string, string | string[] | undefined>} */
    let headers = Object.create(null);
    /** @type {unknown} */
    let rawHeaders;
    try {
      // Copied for the same reason as the headers below: countRawHeader walks
      // it later, well outside this block.
      const suppliedRaw = req?.rawHeaders;
      rawHeaders = Array.isArray(suppliedRaw) ? Array.prototype.slice.call(suppliedRaw) : undefined;
      const supplied = req?.headers;
      if (supplied !== null && typeof supplied === 'object') {
        for (const name of Object.keys(supplied)) {
          headers[name] = supplied[name];
        }
      }
    } catch {
      // Unreadable headers count as none, rawHeaders with them; a partial read
      // is discarded.
      headers = Object.create(null);
      rawHeaders = undefined;
    }

    // Resolve: explicit certificateHeader/chainHeader > preset; explicit encoding > preset.
    const preset = certificateSource ? PRESETS[certificateSource] : null;
    const leafHeaderName = certificateHeader ? certificateHeader.toLowerCase() : preset?.header;
    const chainHeaderName = (chainHeader ?? preset?.chainHeader)?.toLowerCase();
    const chainEncoding = headerEncoding ?? preset?.encoding;

    // Verify upstream proxy's certificate validation if configured. Node joins
    // repeated header lines with ", ", so a repeated verification header is a mismatch.
    // Stryker disable next-line LogicalOperator: construction-time validation ensures both set or neither, single-side check is redundant but clearer
    if (verifyHeader && verifyValue) {
      const verifyName = verifyHeader.toLowerCase();
      const verifyStatus = headers[verifyName];
      if (Array.isArray(verifyStatus) || verifyStatus !== verifyValue || countRawHeader(rawHeaders, verifyName) > 1) {
        return {
          success: false,
          certificate: null,
          reason: 'verification_header_mismatch',
        };
      }
    }

    // A repeated certificate header line is ambiguous: every encoding would read
    // the first value. Treat it as malformed. Chain headers are RFC 9440 lists
    // and may legitimately repeat; Node joins the lines with commas.
    const repeated = countRawHeader(rawHeaders, /** @type {string} */ (leafHeaderName)) > 1;

    if (!repeated) {
      cert = getCertificateFromHeaders(headers, {
        certificateSource,
        certificateHeader,
        headerEncoding,
      });
    }

    // Append chain from a separate chain header if configured.
    // Split on commas per RFC 9440, parse each item, link via issuerCertificate.
    if (cert && chainHeaderName && chainEncoding) {
      const chainHeaderValue = headers[chainHeaderName];
      // Only a non-empty string is parseable; anything else leaves the leaf unchained.
      if (typeof chainHeaderValue === 'string' && chainHeaderValue) {
        const chainItems = chainHeaderValue
          .split(',')
          .map(item => item.trim())
          .filter(Boolean);
        if (chainItems.length + 1 > MAX_CHAIN_CERTS) {
          cert = null;
        } else {
          const chainCerts = chainItems
            .map(item => parseHeaderValue(item, chainEncoding, { chainInLeafHeader: false }))
            .filter(Boolean);
          // A single item can expand into several certificates (e.g. a
          // multi-block url-pem), so bound the leaf plus every parsed
          // certificate, not the item count.
          const totalCerts = chainCerts.reduce((sum, c) => sum + countChain(c), 1);
          if (totalCerts > MAX_CHAIN_CERTS) {
            cert = null;
          } else if (chainCerts.length > 0) {
            cert.issuerCertificate = chainCerts[0];
            for (let i = 0; i < chainCerts.length - 1; i++) {
              chainCerts[i].issuerCertificate = chainCerts[i + 1];
            }
          }
        }
      }
    }

    // Normalize: strip chain unless includeChain is true
    if (cert && !includeChain && 'issuerCertificate' in cert) {
      delete cert.issuerCertificate;
    }

    if (!cert) {
      // If no fallback, return error immediately
      if (!fallbackToSocket) {
        return {
          success: false,
          certificate: null,
          reason: 'header_missing_or_malformed',
        };
      }
    }
  }

  // Fallback to socket-based extraction (original behavior)
  if (!cert) {
    /** @type {any} */
    let socket;
    let authorized = false;
    /** @type {any} */
    let getPeerCertificate;
    try {
      socket = req?.socket;
      authorized = Boolean(socket?.authorized);
      getPeerCertificate = socket?.getPeerCertificate;
    } catch {
      // Whatever threw was not assigned, so an unreadable socket or authorized
      // flag leaves authorized false, while one that reports authorized before
      // its getPeerCertificate accessor throws keeps it and falls through to
      // certificate_not_retrievable.
    }

    // Ensure that the certificate was validated at the protocol level
    if (!authorized) {
      return {
        success: false,
        certificate: null,
        reason: 'socket_not_authorized',
      };
    }

    // Obtain certificate details from socket
    if (typeof getPeerCertificate !== 'function') {
      return {
        success: false,
        certificate: null,
        reason: 'certificate_not_retrievable',
      };
    }

    try {
      cert = getPeerCertificate.call(socket, includeChain);
    } catch {
      cert = null;
    }
    if (!cert || Object.keys(cert).length === 0) {
      // Handle the case where a certificate was validated but we can't inspect it
      return {
        success: false,
        certificate: null,
        reason: 'certificate_not_retrievable',
      };
    }
  }

  return {
    success: true,
    certificate: cert,
    reason: null,
  };
}
