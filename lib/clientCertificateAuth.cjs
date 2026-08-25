/*!
 * client-certificate-auth - CommonJS wrapper
 * Copyright (C) 2013-2026 Tony Gies
 * @license MIT
 */

'use strict';

// Dynamic import of the ES module
let _default;

async function loadModule() {
    // Stryker disable next-line ConditionalExpression: test ordering caches _default from prior test; ConditionalExpression→true (always re-import) re-imports same module successfully
    if (!_default) {
        // Stryker disable next-line StringLiteral: test ordering caches _default; StringLiteral→"" fails import but cached value masks it
        const mod = await import('./clientCertificateAuth.js');
        _default = mod.default;
    }
    return _default;
}

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
        && typeof value.then === 'function';
}

/**
 * Read `.message` without trusting the object: accessor traps and
 * non-string values yield an empty string.
 * @param {any} error
 * @returns {string}
 */
function errorMessage(error) {
    try {
        const message = error.message;
        return typeof message === 'string' ? message : '';
    } catch {
        return '';
    }
}

/**
 * Wrap primitives thrown by the validation callback in an Error and default
 * `status` to 401. Objects that refuse the assignment or throw from their
 * accessors (frozen, sealed, getter-only or trapped `status`) are replaced
 * by a new Error carrying them as `cause`.
 * @param {unknown} err
 * @returns {any}
 */
function normalizeCallbackError(err) {
    const error = err !== null && (typeof err === 'object' || typeof err === 'function')
        ? err
        : new Error(err === null || err === undefined ? '' : String(err));
    let usable;
    try {
        if (error.status === undefined) {
            error.status = 401;
        }
        usable = error.status !== undefined;
    } catch {
        usable = false;
    }
    if (usable) {
        return error;
    }
    const wrapped = new Error(errorMessage(error), { cause: error });
    wrapped.status = 401;
    return wrapped;
}

/**
 * Options not supported by the sync CJS wrapper.
 * These require the ESM module's async header parsing.
 */
const UNSUPPORTED_OPTIONS = [
    'certificateSource',
    'certificateHeader',
    'chainHeader',
    'headerEncoding',
    'fallbackToSocket',
    'verifyHeader',
    'verifyValue'
];

/**
 * CommonJS wrapper for client-certificate-auth.
 * 
 * This sync wrapper supports socket-based certificate extraction only.
 * For full features (header-based extraction, reverse proxy support),
 * use the async loader: `const auth = await require('client-certificate-auth').load();`
 * 
 * @param {Function} callback - Validation callback
 * @param {Object} [options] - Options
 * @param {boolean} [options.includeChain=false] - Include certificate chain
 * @returns {Function} Express middleware
 * @throws {Error} If unsupported options are passed
 */
function clientCertificateAuth(callback, options = {}) {
    if (typeof callback !== 'function') {
        throw new TypeError('client-certificate-auth: callback must be a function');
    }

    // Validate that no unsupported options are passed
    const used = UNSUPPORTED_OPTIONS.filter(k => k in options);
    if (used.length) {
        throw new Error(
            `CJS sync wrapper does not support: ${used.join(', ')}. ` +
            'Use require(...).load() for full features.'
        );
    }

    const { includeChain = false, onAuthenticated, onRejected } = options;

    /**
     * Safely call a hook function without blocking or throwing.
     * Deferred via queueMicrotask to ensure truly non-blocking behavior.
     * @param {Function|undefined} hook
     * @param  {...any} args
     */
    function safeCallHook(hook, ...args) {
        if (typeof hook !== 'function') return;
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
        // Ensure that the certificate was validated at the protocol level
        if (!req.socket?.authorized) {
            safeCallHook(onRejected, null, req, 'socket_not_authorized');
            const e = new Error('Unauthorized: Client certificate required');
            e.status = 401;
            return next(e);
        }

        // Socket may report authorized: true without exposing TLS methods (mocks,
        // misconfigured non-TLS path that nonetheless sets authorized). Mirrors the
        // guard in the ESM extractor (lib/extractor.js).
        if (typeof req.socket.getPeerCertificate !== 'function') {
            safeCallHook(onRejected, null, req, 'certificate_not_retrievable');
            const e = new Error(
                'Client certificate was authenticated but certificate information could not be retrieved.'
            );
            e.status = 500;
            return next(e);
        }

        // Obtain certificate details
        const cert = req.socket.getPeerCertificate(includeChain);
        if (!cert || Object.keys(cert).length === 0) {
            safeCallHook(onRejected, null, req, 'certificate_not_retrievable');
            const e = new Error(
                'Client certificate was authenticated but certificate information could not be retrieved.'
            );
            e.status = 500;
            return next(e);
        }

        // Attach certificate to request for downstream access
        req.clientCertificate = cert;

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
            const result = callback(cert, req);
            if (isThenable(result)) {
                Promise.resolve(result).then(doneAuthorizing).catch((rejection) => {
                    const err = normalizeCallbackError(rejection);
                    safeCallHook(onRejected, cert, req, errorMessage(err) || 'callback_threw');
                    next(err);
                });
            } else {
                doneAuthorizing(result);
            }
        } catch (thrown) {
            const err = normalizeCallbackError(thrown);
            safeCallHook(onRejected, cert, req, errorMessage(err) || 'callback_threw');
            next(err);
        }
    };
}

module.exports = clientCertificateAuth;
module.exports.default = clientCertificateAuth;

// Also expose async loader for those who want the ES module (full features)
module.exports.load = loadModule;
