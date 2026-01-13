import type { IncomingMessage, ServerResponse } from 'http';
import type { TLSSocket, PeerCertificate } from 'tls';

export interface HttpError extends Error {
    status: number;
}

export interface ClientCertRequest extends IncomingMessage {
    secure?: boolean;
    socket: TLSSocket & {
        authorized?: boolean;
        authorizationError?: string;
    };
}

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
