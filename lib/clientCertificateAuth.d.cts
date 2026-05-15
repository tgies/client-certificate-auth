import type { IncomingMessage, ServerResponse } from 'http';
import type { TLSSocket, PeerCertificate, DetailedPeerCertificate } from 'tls';
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
 * Extended request object with TLS socket and optional Express properties.
 */
export interface ClientCertRequest extends IncomingMessage {
    /** True if connection is over HTTPS (Express-specific) */
    secure?: boolean;
    /** TLS socket with authorization properties */
    socket: TLSSocket & {
        /** Whether the client certificate was authorized at the TLS layer */
        authorized?: boolean;
        /** Error message if authorization failed */
        authorizationError?: string;
    };
    /**
     * Client certificate attached by clientCertificateAuth middleware.
     * Available after successful certificate extraction.
     * Contains issuerCertificate chain if includeChain option is true.
     */
    clientCertificate?: PeerCertificate | DetailedPeerCertificate;
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

