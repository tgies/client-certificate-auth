import type { IncomingMessage, ServerResponse } from 'http';
import type { TLSSocket, PeerCertificate } from 'tls';

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
}

/**
 * Extended response object with redirect method.
 */
export interface ClientCertResponse extends ServerResponse {
    redirect(statusOrUrl: number | string, url?: string): void;
}

export interface ClientCertificateAuthOptions {
    /**
     * If true, redirect HTTP requests to HTTPS.
     * WARNING: This can expose the initial request to MITM attacks.
     * @default false
     */
    redirectInsecure?: boolean;
}

export type ValidationCallback = (cert: PeerCertificate) => boolean | Promise<boolean>;

export type Middleware = (
    req: ClientCertRequest,
    res: ClientCertResponse,
    next: (err?: Error | HttpError) => void
) => void;

/**
 * Express/Connect middleware for client SSL certificate authentication.
 *
 * @param callback - Validation function that receives the client certificate
 *   and returns true/false (sync) or Promise<boolean> (async).
 * @param options - Configuration options
 * @returns Express middleware function
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
 */
declare function clientCertificateAuth(
    callback: ValidationCallback,
    options?: ClientCertificateAuthOptions
): Middleware;

export default clientCertificateAuth;
