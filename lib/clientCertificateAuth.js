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
 * @property {boolean} [redirectInsecure=false] - If true, redirect HTTP requests to HTTPS. 
 *   WARNING: This can expose the initial request to MITM attacks.
 * @property {'aws-alb' | 'envoy' | 'cloudflare' | 'traefik'} [certificateSource] - Use a preset 
 *   configuration for a known reverse proxy. Header-based certs are only checked if this or
 *   certificateHeader is set.
 * @property {string} [certificateHeader] - Custom header name to read certificate from.
 *   Overrides preset header name if also using certificateSource.
 * @property {'url-pem' | 'url-pem-aws' | 'xfcc' | 'base64-der' | 'rfc9440'} [headerEncoding] - 
 *   How to decode the header value. Required when using certificateHeader without certificateSource.
 * @property {boolean} [fallbackToSocket=false] - If header-based extraction is configured but 
 *   fails (header absent or malformed), try socket.getPeerCertificate() instead of returning 401.
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
    redirectInsecure = false,
    certificateSource,
    certificateHeader,
    headerEncoding,
    fallbackToSocket = false,
  } = options;

  // Determine if header-based extraction is configured
  const useHeaders = Boolean(certificateSource || certificateHeader);

  return function middleware(req, res, next) {
    // Optional HTTPS redirect (opt-in only due to security concerns)
    if (redirectInsecure && !req.secure && req.headers['x-forwarded-proto'] !== 'https') {
      return res.redirect(301, 'https://' + req.headers['host'] + req.url);
    }

    let cert = null;

    // Try header-based extraction first if configured
    if (useHeaders) {
      cert = getCertificateFromHeaders(req.headers, {
        certificateSource,
        certificateHeader,
        headerEncoding,
      });

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
      cert = req.socket.getPeerCertificate();
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
        result.then(doneAuthorizing).catch(next);
      } else {
        doneAuthorizing(result);
      }
    } catch (err) {
      next(err);
    }
  };
}
