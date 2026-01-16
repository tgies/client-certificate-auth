/*!
 * client-certificate-auth - Node.js Connect/Express middleware for
 * authentication based on a client SSL certificate
 * Copyright (C) 2013-2026 Tony Gies
 * @license MIT
 */

import { getCertificateFromHeaders } from './parsers.js';

/**
 * @typedef {import('http').IncomingMessage & { secure?: boolean; socket: import('tls').TLSSocket & { authorized?: boolean; authorizationError?: string }; clientCertificate?: import('tls').PeerCertificate }} ClientCertRequest
 * @typedef {import('http').ServerResponse & { redirect: (statusOrUrl: number | string, url?: string) => void }} ClientCertResponse
 * @typedef {(req: ClientCertRequest, res: ClientCertResponse, next: (err?: Error) => void) => void} Middleware
 */

/**
 * @typedef {Object} ClientCertificateAuthOptions
 * @property {'aws-alb' | 'envoy' | 'cloudflare' | 'traefik'} [certificateSource] - Use a preset 
 *   configuration for a known reverse proxy. Header-based certs are only checked if this or
 *   certificateHeader is set.
 * @property {string} [certificateHeader] - Custom header name to read certificate from.
 *   Overrides preset header name if also using certificateSource.
 * @property {'url-pem' | 'url-pem-aws' | 'xfcc' | 'base64-der' | 'rfc9440'} [headerEncoding] - 
 *   How to decode the header value. Required when using certificateHeader without certificateSource.
 * @property {boolean} [fallbackToSocket=false] - If header-based extraction is configured but 
 *   fails (header absent or malformed), try socket.getPeerCertificate() instead of returning 401.
 * @property {boolean} [includeChain=false] - If true, include the full certificate chain via
 *   cert.issuerCertificate. Applies to both socket and header-based extraction.
 * @property {string} [verifyHeader] - Header name containing certificate verification status from
 *   upstream proxy (e.g., 'X-SSL-Client-Verify'). Must be used with verifyValue.
 * @property {string} [verifyValue] - Expected value indicating successful verification (e.g., 'SUCCESS').
 *   If verifyHeader is set, requests are rejected unless the header matches this value.
 */

/**
 * Enforce SSL client authorization and provide a callback which will be
 * passed the client certificate information for additional validation.
 *
 * The callback receives the certificate (as obtained through
 * `req.socket.getPeerCertificate()` or extracted from headers) and must 
 * return `true` (or a Promise resolving to `true`) for the request to proceed.
 *
 * @param {(cert: import('tls').PeerCertificate) => boolean | Promise<boolean>} callback
 *   Validation function that receives the client certificate and returns
 *   true/false (sync) or a Promise<boolean> (async) to allow/deny access.
 * @param {ClientCertificateAuthOptions} [options={}]
 * @returns {Middleware}
 * 
 * @example
 * // Synchronous validation (socket-based)
 * app.use(clientCertificateAuth((cert) => cert.subject.CN === 'admin'));
 * 
 * @example
 * // AWS ALB mTLS passthrough
 * app.use(clientCertificateAuth((cert) => cert.subject.CN === 'admin', {
 *   certificateSource: 'aws-alb'
 * }));
 *
 * @example
 * // Custom header configuration
 * app.use(clientCertificateAuth((cert) => cert.subject.CN === 'admin', {
 *   certificateHeader: 'X-SSL-Client-Cert',
 *   headerEncoding: 'url-pem'
 * }));
 */
export default function clientCertificateAuth(callback, options = {}) {
  const {
    certificateSource,
    certificateHeader,
    headerEncoding,
    fallbackToSocket = false,
    includeChain = false,
    verifyHeader,
    verifyValue,
  } = options;

  // Determine if header-based extraction is configured
  const useHeaders = Boolean(certificateSource || certificateHeader);

  return function middleware(req, res, next) {
    let cert = null;

    // Try header-based extraction first if configured
    if (useHeaders) {
      // Verify upstream proxy's certificate validation if configured
      if (verifyHeader && verifyValue) {
        const verifyStatus = req.headers[verifyHeader.toLowerCase()];
        if (verifyStatus !== verifyValue) {
          const e = new Error(`Unauthorized: Certificate verification failed (${verifyStatus || 'header missing'})`);
          e.status = 401;
          return next(e);
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
        // If no fallback, return 401 immediately
        if (!fallbackToSocket) {
          const e = new Error('Unauthorized: Client certificate header missing or malformed');
          e.status = 401;
          return next(e);
        }
      }
    }

    // Fallback to socket-based extraction (original behavior)
    if (!cert) {
      // Ensure that the certificate was validated at the protocol level
      if (!req.socket?.authorized) {
        const authError = req.socket?.authorizationError || 'unknown';
        const e = new Error(`Unauthorized: Client certificate required (${authError})`);
        e.status = 401;
        return next(e);
      }

      // Obtain certificate details from socket
      cert = req.socket.getPeerCertificate(includeChain);
      if (!cert || Object.keys(cert).length === 0) {
        // Handle the bizarre case where a certificate was validated but we can't inspect it
        const e = new Error(
          'Client certificate was authenticated but certificate information could not be retrieved.'
        );
        e.status = 500;
        return next(e);
      }
    }

    // Attach certificate to request for downstream access
    req.clientCertificate = cert;

    /**
     * @param {boolean} authorized
     */
    function doneAuthorizing(authorized) {
      if (authorized) {
        return next();
      } else {
        const e = new Error('Unauthorized');
        e.status = 401;
        return next(e);
      }
    }

    try {
      const result = callback(cert);
      if (result instanceof Promise) {
        result.then(doneAuthorizing).catch((err) => {
          if (err.status === undefined) {
            err.status = 401;
          }
          next(err);
        });
      } else {
        doneAuthorizing(result);
      }
    } catch (err) {
      if (err.status === undefined) {
        err.status = 401;
      }
      next(err);
    }
  };
}
