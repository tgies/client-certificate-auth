import type { IncomingMessage, ServerResponse } from 'http';
import type { Socket } from 'net';
import type { PeerCertificate, DetailedPeerCertificate } from 'tls';
import type { CertificateSource, HeaderEncoding } from './parsers.js';

export type { CertificateSource, HeaderEncoding };

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
     * Available after successful certificate extraction, before authorization callback.
     * Contains issuerCertificate chain if includeChain option is true.
     */
    clientCertificate?: PeerCertificate | DetailedPeerCertificate;
}

/**
 * Response object for client certificate auth middleware.
 */
export type ClientCertResponse = ServerResponse;

export interface ClientCertificateAuthOptions {
    /**
     * Use a preset configuration for a known reverse proxy.
     * Header-based certs are only checked if this or certificateHeader is set.
     * @see https://github.com/tgies/client-certificate-auth#reverse-proxy-support
     */
    certificateSource?: CertificateSource;


    /**
     * Custom header name to read certificate from.
     * Overrides preset header name if also using certificateSource.
     */
    certificateHeader?: string;

    /**
     * How to decode the header value.
     * Required when using certificateHeader without certificateSource.
     */
    headerEncoding?: HeaderEncoding;

    /**
     * If header-based extraction is configured but fails (header absent or malformed),
     * try socket.getPeerCertificate() instead of returning 401.
     * @default false
     */
    fallbackToSocket?: boolean;

    /**
     * If true, include the full certificate chain via cert.issuerCertificate.
     * Applies to both socket and header-based extraction.
     * @default false
     */
    includeChain?: boolean;

    /**
     * Header name containing certificate verification status from upstream proxy.
     * Must be used together with verifyValue. Example: 'X-SSL-Client-Verify' for nginx.
     */
    verifyHeader?: string;

    /**
     * Expected value indicating successful certificate verification.
     * If verifyHeader is set, requests are rejected unless the header matches this value.
     * Example: 'SUCCESS' for nginx.
     */
    verifyValue?: string;

    /**
     * Called when a client is successfully authenticated.
     * Fire-and-forget: does not block the request, errors are logged to console.error.
     * @param cert - The validated client certificate
     * @param req - The HTTP request object
     */
    onAuthenticated?: (
        cert: PeerCertificate | DetailedPeerCertificate,
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
        cert: PeerCertificate | DetailedPeerCertificate | null,
        req: ClientCertRequest,
        reason: string
    ) => void | Promise<void>;
}

export type ValidationCallback = (
    cert: PeerCertificate | DetailedPeerCertificate,
    req?: ClientCertRequest
) => boolean | PromiseLike<boolean>;

export type Middleware = (
    req: ClientCertRequest,
    res: ClientCertResponse,
    next: (err?: Error | HttpError) => void
) => void;

/**
 * Express/Connect middleware for client SSL certificate authentication.
 *
 * @param callback - Validation function that receives the client certificate
 *   and returns true/false (sync) or `PromiseLike<boolean>` (async,
 *   including native Promises and any thenable resolving to a boolean).
 * @param options - Configuration options
 * @returns Express middleware function
 *
 * @example
 * // Socket-based validation (original behavior)
 * app.use(clientCertificateAuth((cert) => cert.subject.CN === 'admin'));
 *
 * @example
 * // AWS ALB mTLS passthrough
 * app.use(clientCertificateAuth((cert) => cert.subject.CN === 'admin', {
 *   certificateSource: 'aws-alb'
 * }));
 *
 * @example
 * // Custom header with nginx/HAProxy
 * app.use(clientCertificateAuth((cert) => cert.subject.CN === 'admin', {
 *   certificateHeader: 'X-SSL-Client-Cert',
 *   headerEncoding: 'url-pem'
 * }));
 */
declare function clientCertificateAuth(
    callback: ValidationCallback,
    options?: ClientCertificateAuthOptions
): Middleware;

export default clientCertificateAuth;
