/*!
 * client-certificate-auth - CommonJS type declarations
 * Copyright (C) 2013-2026 Tony Gies
 * @license MIT
 */

import type { IncomingMessage, ServerResponse } from 'http';
import type { Socket } from 'net';
import type { PeerCertificate, DetailedPeerCertificate } from 'tls';
import type { ChainedPeerCertificate } from './parsers.js';
import type {
    ClientCertificateAuthOptions as EsmOptions,
    ValidationCallback as EsmValidationCallback,
    Middleware as EsmMiddleware,
} from './clientCertificateAuth.js';

/**
 * Augment the global Error interface for Express/Connect middleware conventions.
 */
declare global {
    interface Error {
        /** HTTP status code for error responses */
        status?: number;
    }
}

/**
 * HTTP Error with status code for Express error handling middleware.
 */
export interface HttpError extends Error {
    status: number;
}

/**
 * Extended request object compatible with Node's `http.IncomingMessage`,
 * Express's `Request`, and Connect-style request objects.
 *
 * The socket is typed as the broader `net.Socket` with TLS-specific fields
 * marked optional so the middleware accepts requests from any of those
 * frameworks without a framework-specific type dependency. The runtime
 * guards in the middleware check for `getPeerCertificate` before calling it.
 */
export interface ClientCertRequest extends IncomingMessage {
    /** True if connection is over HTTPS (Express-specific, optional). */
    secure?: boolean;
    /**
     * Underlying socket. Typed as the broader `net.Socket` so this interface
     * is satisfied by both Node's `IncomingMessage.socket` and Express's
     * `Request.socket`. TLS-specific fields (`authorized`, `authorizationError`,
     * `getPeerCertificate`) are present at runtime when the request arrived
     * over TLS and are detected by the middleware via runtime feature checks.
     */
    socket: Socket & {
        /** Whether the client certificate was authorized at the TLS layer. */
        authorized?: boolean;
        /** Error from TLS authorization, if any. */
        authorizationError?: Error | string;
        /** TLS getPeerCertificate, present on TLSSocket only. */
        getPeerCertificate?: (detailed?: boolean) => PeerCertificate | DetailedPeerCertificate;
    };
    /**
     * Client certificate attached by clientCertificateAuth middleware.
     * Available after successful certificate extraction.
     * Contains issuerCertificate chain if includeChain option is true.
     */
    clientCertificate?: ChainedPeerCertificate;
}

/**
 * Response object for client certificate auth middleware.
 */
export type ClientCertResponse = ServerResponse;

/**
 * Options for the synchronous CommonJS wrapper.
 *
 * @remarks
 * The sync wrapper only supports socket-based certificate extraction.
 * For header-based extraction (reverse proxy support), use the async loader:
 * ```javascript
 * const auth = await require('client-certificate-auth').load();
 * ```
 */
export interface ClientCertificateAuthOptions {
    /**
     * If true, include the full certificate chain via cert.issuerCertificate.
     * @default false
     */
    includeChain?: boolean;

    /**
     * Called when a client is successfully authenticated.
     * Fire-and-forget: does not block the request, errors are logged to console.error.
     * @param cert - The validated client certificate
     * @param req - The HTTP request object
     */
    onAuthenticated?: (
        cert: ChainedPeerCertificate,
        req: ClientCertRequest
    ) => void | Promise<void>;

    /**
     * Called when authentication is rejected.
     * Fire-and-forget: does not block the request, errors are logged to console.error.
     * @param cert - The client certificate (null if extraction failed)
     * @param req - The HTTP request object
     * @param reason - Why authentication was rejected
     */
    onRejected?: (
        cert: ChainedPeerCertificate | null,
        req: ClientCertRequest,
        reason: string
    ) => void | Promise<void>;
}

export type ValidationCallback = (
    cert: ChainedPeerCertificate,
    req?: ClientCertRequest
) => boolean | PromiseLike<boolean>;

export type Middleware = (
    req: ClientCertRequest,
    res: ClientCertResponse,
    next: (err?: Error | HttpError) => void
) => void | Promise<void>;

/**
 * Express/Connect middleware for client SSL certificate authentication.
 */
declare function clientCertificateAuth(
    callback: ValidationCallback,
    options?: ClientCertificateAuthOptions
): Middleware;

declare namespace clientCertificateAuth {
    export { clientCertificateAuth as default };
    export function load(): Promise<
        (callback: EsmValidationCallback, options?: EsmOptions) => EsmMiddleware
    >;
}

export = clientCertificateAuth;

