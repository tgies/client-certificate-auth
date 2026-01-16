/*!
 * client-certificate-auth - CommonJS wrapper
 * Copyright (C) 2013-2026 Tony Gies
 * @license MIT
 */

'use strict';

// Dynamic import of the ES module
let _default;

async function loadModule() {
    if (!_default) {
        const mod = await import('./clientCertificateAuth.js');
        _default = mod.default;
    }
    return _default;
}

/**
 * CommonJS wrapper for client-certificate-auth.
 * 
 * This sync wrapper supports socket-based certificate extraction only.
 * For full features (header-based extraction, reverse proxy support),
 * use the async loader: `const auth = await require('client-certificate-auth').load();`
 * 
 * @param {Function} callback - Validation callback
 * @param {Object} [options] - Options
 * @returns {Function} Express middleware
 */
function clientCertificateAuth(callback, options = {}) {
    const { includeChain = false } = options;

    return function middleware(req, res, next) {
        // Ensure that the certificate was validated at the protocol level
        if (!req.socket?.authorized) {
            const authError = req.socket?.authorizationError || 'unknown';
            const e = new Error(`Unauthorized: Client certificate required (${authError})`);
            e.status = 401;
            return next(e);
        }

        // Obtain certificate details
        const cert = req.socket.getPeerCertificate(includeChain);
        if (!cert || Object.keys(cert).length === 0) {
            const e = new Error(
                'Client certificate was authenticated but certificate information could not be retrieved.'
            );
            e.status = 500;
            return next(e);
        }

        // Attach certificate to request for downstream access
        req.clientCertificate = cert;

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

module.exports = clientCertificateAuth;
module.exports.default = clientCertificateAuth;

// Also expose async loader for those who want the ES module (full features)
module.exports.load = loadModule;
