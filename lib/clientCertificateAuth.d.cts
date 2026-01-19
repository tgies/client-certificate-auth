/// <reference path="./global.d.ts" />
import type { IncomingMessage, ServerResponse } from 'http';
import type { TLSSocket, PeerCertificate, DetailedPeerCertificate } from 'tls';

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
 * Extended response object with redirect method.
 */
export interface ClientCertResponse extends ServerResponse {
    redirect(statusOrUrl: number | string, url?: string): void;
}

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
}

export type ValidationCallback = (cert: PeerCertificate | DetailedPeerCertificate) => boolean | Promise<boolean>;

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
    export function load(): Promise<typeof clientCertificateAuth>;
}

export = clientCertificateAuth;

