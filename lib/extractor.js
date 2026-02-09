/*!
 * client-certificate-auth - Certificate extraction module
 * Copyright (C) 2013-2026 Tony Gies
 * @license MIT
 */

import { getCertificateFromHeaders } from './parsers.js';

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
 * @property {'aws-alb' | 'envoy' | 'cloudflare' | 'traefik'} [certificateSource] - Preset configuration
 * @property {string} [certificateHeader] - Custom header name
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
  const {
    certificateSource,
    certificateHeader,
    headerEncoding,
    fallbackToSocket = false,
    includeChain = false,
    verifyHeader,
    verifyValue,
  } = options;

  // Validate verifyHeader/verifyValue pairing
  if ((verifyHeader && !verifyValue) || (!verifyHeader && verifyValue)) {
    throw new Error(
      'extractClientCertificate: verifyHeader and verifyValue must both be provided together, or both omitted'
    );
  }

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
