/*!
 * client-certificate-auth - Certificate extraction module
 * Copyright (C) 2013-2026 Tony Gies
 * @license MIT
 */

import { getCertificateFromHeaders, parseHeaderValue, PRESETS } from './parsers.js';

const VALID_ENCODINGS = ['url-pem', 'url-pem-aws', 'xfcc', 'base64-der', 'rfc9440'];

/**
 * Validate options shared by `extractClientCertificate` and the middleware
 * constructor. Throws on misconfiguration (unknown preset, unknown encoding,
 * `certificateHeader` without an encoding source, `chainHeader` without a
 * leaf header source, or only one of `verifyHeader`/`verifyValue`). Omitted
 * or `undefined` options are treated as the empty object; explicit `null`
 * will throw a `TypeError`.
 *
 * @param {ExtractorOptions} [options]
 * @throws {Error} when options are malformed
 */
export function validateExtractorOptions(options = {}) {
  const { certificateSource, certificateHeader, chainHeader, headerEncoding, verifyHeader, verifyValue } = options;

  if ((verifyHeader && !verifyValue) || (!verifyHeader && verifyValue)) {
    throw new Error(
      'client-certificate-auth: verifyHeader and verifyValue must both be provided together, or both omitted'
    );
  }

  if (certificateSource && !Object.hasOwn(PRESETS, certificateSource)) {
    throw new Error(
      `client-certificate-auth: unknown certificateSource '${certificateSource}'. Valid values: ${Object.keys(PRESETS).join(', ')}`
    );
  }

  if (headerEncoding && !VALID_ENCODINGS.includes(headerEncoding)) {
    throw new Error(
      `client-certificate-auth: unknown headerEncoding '${headerEncoding}'. Valid values: ${VALID_ENCODINGS.join(', ')}`
    );
  }

  if (certificateHeader && !certificateSource && !headerEncoding) {
    throw new Error(
      'client-certificate-auth: certificateHeader requires headerEncoding (or a certificateSource preset that supplies one)'
    );
  }

  if (chainHeader && !certificateSource && !certificateHeader) {
    throw new Error(
      'client-certificate-auth: chainHeader requires certificateSource or certificateHeader (chain header must accompany a leaf header configuration)'
    );
  }
}

/**
 * @typedef {Object} ExtractionResult
 * @property {boolean} success - Whether extraction succeeded
 * @property {import('tls').PeerCertificate | null} certificate - Extracted certificate (null on failure)
 * @property {string | null} reason - Rejection reason code (null on success)
 *
 * Rejection reasons:
 * - 'verification_header_mismatch' - Proxy verify header didn't match expected value
 * - 'header_missing_or_malformed' - Header extraction failed and no fallback configured
 * - 'socket_not_authorized' - Socket not authorized for TLS client cert
 * - 'certificate_not_retrievable' - Socket authorized but getPeerCertificate() returned empty
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
 *   `headerEncoding`, results linked via `issuerCertificate`. For non-RFC-9440 encodings
 *   the comma split may not match the encoding's list convention.
 * @property {'url-pem' | 'url-pem-aws' | 'xfcc' | 'base64-der' | 'rfc9440'} [headerEncoding] - Header encoding
 * @property {boolean} [fallbackToSocket=false] - Try socket if header extraction fails
 * @property {boolean} [includeChain=false] - Include issuerCertificate chain
 * @property {string} [verifyHeader] - Header name for upstream verification status
 * @property {string} [verifyValue] - Expected value for successful verification
 */

/**
 * Extract client certificate from request.
 *
 * Works with both header-based extraction (reverse proxy scenarios) and socket-based
 * extraction (direct TLS connections). Returns a structured result object instead of
 * throwing or using callbacks, making it suitable for any framework adapter.
 *
 * @param {Object} req - Request object with headers and optional socket
 * @param {Record<string, string | string[] | undefined>} req.headers - HTTP headers object
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
    // Verify upstream proxy's certificate validation if configured
    // Stryker disable next-line LogicalOperator: construction-time validation ensures both set or neither, single-side check is redundant but clearer
    if (verifyHeader && verifyValue) {
      const verifyStatus = req.headers[verifyHeader.toLowerCase()];
      if (Array.isArray(verifyStatus) || verifyStatus !== verifyValue) {
        return {
          success: false,
          certificate: null,
          reason: 'verification_header_mismatch',
        };
      }
    }

    cert = getCertificateFromHeaders(req.headers, {
      certificateSource,
      certificateHeader,
      headerEncoding,
    });

    // Append chain from a separate chain header if configured.
    // Resolve: explicit chainHeader > preset.chainHeader; explicit encoding > preset.encoding.
    // Split on commas per RFC 9440, parse each item, link via issuerCertificate.
    if (cert) {
      const preset = certificateSource ? PRESETS[certificateSource] : null;
      const chainHeaderName = (chainHeader ?? preset?.chainHeader)?.toLowerCase();
      const chainEncoding = headerEncoding ?? preset?.encoding;
      if (chainHeaderName && chainEncoding) {
        const chainHeaderValue = req.headers[chainHeaderName];
        if (chainHeaderValue && !Array.isArray(chainHeaderValue)) {
          const chainCerts = chainHeaderValue
            .split(',')
            .map(item => item.trim())
            .filter(Boolean)
            .map(item => parseHeaderValue(item, chainEncoding))
            .filter(Boolean);
          if (chainCerts.length > 0) {
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
    // Ensure that the certificate was validated at the protocol level
    if (!req.socket?.authorized) {
      return {
        success: false,
        certificate: null,
        reason: 'socket_not_authorized',
      };
    }

    // Obtain certificate details from socket
    // TypeScript: cast to TLSSocket since we've validated this is a TLS connection
    if (typeof req.socket.getPeerCertificate !== 'function') {
      return {
        success: false,
        certificate: null,
        reason: 'certificate_not_retrievable',
      };
    }

    cert = /** @type {import('tls').TLSSocket} */ (req.socket).getPeerCertificate(includeChain);
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
