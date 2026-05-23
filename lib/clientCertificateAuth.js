/*!
 * client-certificate-auth - Node.js Connect/Express middleware for
 * authentication based on a client SSL certificate
 * Copyright (C) 2013-2026 Tony Gies
 * @license MIT
 */

import { extractClientCertificate, validateExtractorOptions } from './extractor.js';

/**
 * Duck-typed thenable check per Promises/A+: an object or function with
 * a callable `.then` method. Matches the set of values `Promise.resolve`
 * natively adopts as thenables.
 * @param {unknown} value
 * @returns {boolean}
 */
function isThenable(value) {
  return value !== null
    && (typeof value === 'object' || typeof value === 'function')
    && typeof /** @type {{then?: unknown}} */ (value).then === 'function';
}

/**
 * @typedef {import('http').IncomingMessage & { secure?: boolean; socket: import('net').Socket & { authorized?: boolean; authorizationError?: Error | string; getPeerCertificate?: (detailed?: boolean) => import('tls').PeerCertificate | import('tls').DetailedPeerCertificate }; clientCertificate?: import('tls').PeerCertificate }} ClientCertRequest
 * @typedef {import('http').ServerResponse & { redirect: (statusOrUrl: number | string, url?: string) => void }} ClientCertResponse
 * @typedef {(req: ClientCertRequest, res: ClientCertResponse, next: (err?: Error) => void) => void} Middleware
 */

/**
 * @typedef {Object} ClientCertificateAuthOptions
 * @property {'aws-alb' | 'envoy' | 'cloudflare' | 'traefik'} [certificateSource] - Use a preset
 *   configuration for a known reverse proxy. Header-based certs are only checked if this or
 *   certificateHeader is set. Trust boundary: the proxy must strip the preset's header from
 *   external requests; any source that can set it is trusted to assert client identity.
 * @property {string} [certificateHeader] - Custom header name to read certificate from.
 *   Overrides preset header name if also using certificateSource. Trust boundary: the proxy
 *   must strip this header from external requests; any source that can set it is trusted to
 *   assert client identity.
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
 *   Comparison is exact (case-sensitive, no whitespace trimming); set this to the exact string your proxy emits.
 * @property {(cert: import('tls').PeerCertificate, req: ClientCertRequest) => void | Promise<void>} [onAuthenticated] -
 *   Called when a client is successfully authenticated. Fire-and-forget.
 * @property {(cert: import('tls').PeerCertificate | null, req: ClientCertRequest, reason: string) => void | Promise<void>} [onRejected] -
 *   Called when authentication is rejected. Fire-and-forget.
 */

/**
 * Enforce SSL client authorization and provide a callback which will be
 * passed the client certificate information for additional validation.
 *
 * The callback receives the certificate (as obtained through
 * `req.socket.getPeerCertificate()` or extracted from headers) and must
 * return `true` (or a thenable resolving to `true`) for the request to proceed.
 *
 * @param {(cert: import('tls').PeerCertificate, req: ClientCertRequest) => boolean | PromiseLike<boolean>} callback
 *   Validation function that receives the client certificate and the request
 *   object. Returns true/false (sync) or a `PromiseLike<boolean>` (async,
 *   including native Promises and any thenable resolving to a boolean) to
 *   allow/deny access.
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
  if (typeof callback !== 'function') {
    throw new TypeError('client-certificate-auth: callback must be a function');
  }

  validateExtractorOptions(options);

  const {
    certificateSource,
    certificateHeader,
    headerEncoding,
    fallbackToSocket = false,
    includeChain = false,
    verifyHeader,
    verifyValue,
    onAuthenticated,
    onRejected,
  } = options;

  /**
   * Safely call a hook function without blocking or throwing.
   * Deferred via queueMicrotask to ensure truly non-blocking behavior.
   * @param {Function|undefined} hook
   * @param  {...any} args
   */
  function safeCallHook(hook, ...args) {
    if (typeof hook !== 'function') {
      return;
    }
    queueMicrotask(() => {
      try {
        const result = hook(...args);
        if (isThenable(result)) {
          Promise.resolve(result).catch(err => console.error('client-certificate-auth: hook error:', err));
        }
      } catch (err) {
        console.error('client-certificate-auth: hook error:', err);
      }
    });
  }

  return function middleware(req, res, next) {
    // Extract certificate using shared extractor logic
    const result = extractClientCertificate(req, {
      certificateSource,
      certificateHeader,
      headerEncoding,
      fallbackToSocket,
      includeChain,
      verifyHeader,
      verifyValue,
    });

    if (!result.success) {
      safeCallHook(onRejected, null, req, result.reason);

      // Map rejection reasons to user-friendly error messages
      let errorMessage;
      let statusCode = 401;

      switch (result.reason) {
        case 'verification_header_mismatch':
          errorMessage = 'Unauthorized: Certificate verification failed';
          break;
        case 'header_missing_or_malformed':
          errorMessage = 'Unauthorized: Client certificate header missing or malformed';
          break;
        case 'socket_not_authorized':
          errorMessage = 'Unauthorized: Client certificate required';
          break;
        case 'certificate_not_retrievable':
          errorMessage = 'Client certificate was authenticated but certificate information could not be retrieved.';
          statusCode = 500;
          break;
      }

      const e = new Error(errorMessage);
      e.status = statusCode;
      return next(e);
    }

    // Attach certificate to request for downstream access
    const cert = result.certificate;
    req.clientCertificate = cert;

    /**
     * @param {unknown} authorized
     */
    function doneAuthorizing(authorized) {
      if (authorized === true) {
        safeCallHook(onAuthenticated, cert, req);
        return next();
      } else {
        safeCallHook(onRejected, cert, req, 'callback_returned_false');
        const e = new Error('Unauthorized');
        e.status = 401;
        return next(e);
      }
    }

    try {
      const callbackResult = callback(cert, req);
      if (isThenable(callbackResult)) {
        Promise.resolve(callbackResult).then(doneAuthorizing).catch((err) => {
          safeCallHook(onRejected, cert, req, err.message || 'callback_threw');
          if (err.status === undefined) {
            err.status = 401;
          }
          next(err);
        });
      } else {
        doneAuthorizing(callbackResult);
      }
    } catch (err) {
      safeCallHook(onRejected, cert, req, err.message || 'callback_threw');
      if (err.status === undefined) {
        err.status = 401;
      }
      next(err);
    }
  };
}
