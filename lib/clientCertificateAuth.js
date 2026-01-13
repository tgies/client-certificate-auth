/*!
 * client-certificate-auth - Node.js Connect/Express middleware for
 * authentication based on a client SSL certificate
 * Copyright (C) 2013-2024 Tony Gies
 * @license MIT
 */

/**
 * @typedef {import('http').IncomingMessage & { secure?: boolean; socket: import('tls').TLSSocket & { authorized?: boolean; authorizationError?: string } }} ClientCertRequest
 * @typedef {import('http').ServerResponse & { redirect: (statusOrUrl: number | string, url?: string) => void }} ClientCertResponse
 * @typedef {(req: ClientCertRequest, res: ClientCertResponse, next: (err?: Error) => void) => void} Middleware
 */

/**
 * @typedef {Object} ClientCertificateAuthOptions
 * @property {boolean} [redirectInsecure=false] - If true, redirect HTTP requests to HTTPS. 
 *   WARNING: This can expose the initial request to MITM attacks.
 */

/**
 * Enforce SSL client authorization and provide a callback which will be
 * passed the client certificate information for additional validation.
 *
 * The callback receives the certificate (as obtained through
 * `req.socket.getPeerCertificate()`) and must return `true` (or a Promise
 * resolving to `true`) for the request to proceed.
 *
 * @param {(cert: import('tls').PeerCertificate) => boolean | Promise<boolean>} callback
 *   Validation function that receives the client certificate and returns
 *   true/false (sync) or a Promise<boolean> (async) to allow/deny access.
 * @param {ClientCertificateAuthOptions} [options={}]
 * @returns {Middleware}
 * 
 * @example
 * // Synchronous validation
 * app.use(clientCertificateAuth((cert) => cert.subject.CN === 'admin'));
 * 
 * @example
 * // Async validation  
 * app.use(clientCertificateAuth(async (cert) => {
 *   const user = await db.findByCertFingerprint(cert.fingerprint);
 *   return user !== null;
 * }));
 * 
 * @example
 * // Per-route protection
 * app.get('/admin', clientCertificateAuth(checkAdmin), (req, res) => {
 *   res.send('Welcome, admin!');
 * });
 */
export default function clientCertificateAuth(callback, options = {}) {
  const { redirectInsecure = false } = options;

  return function middleware(req, res, next) {
    // Optional HTTPS redirect (opt-in only due to security concerns)
    if (redirectInsecure && !req.secure && req.headers['x-forwarded-proto'] !== 'https') {
      return res.redirect(301, 'https://' + req.headers['host'] + req.url);
    }

    // Ensure that the certificate was validated at the protocol level
    if (!req.socket?.authorized) {
      const authError = req.socket?.authorizationError || 'unknown';
      const e = new Error(`Unauthorized: Client certificate required (${authError})`);
      e.status = 401;
      return next(e);
    }

    // Obtain certificate details
    const cert = req.socket.getPeerCertificate();
    if (!cert || Object.keys(cert).length === 0) {
      // Handle the bizarre case where a certificate was validated but we can't inspect it
      const e = new Error(
        'Client certificate was authenticated but certificate information could not be retrieved.'
      );
      e.status = 500;
      return next(e);
    }

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
