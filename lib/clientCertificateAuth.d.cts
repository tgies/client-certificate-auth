import type { IncomingMessage, ServerResponse } from 'http';
import type { TLSSocket, PeerCertificate } from 'tls';

/**
 * Known reverse proxy presets.
 */
export type CertificateSource = 'aws-alb' | 'envoy' | 'cloudflare' | 'traefik';

/**
 * Header encoding formats.
 */
export type HeaderEncoding = 'url-pem' | 'url-pem-aws' | 'xfcc' | 'base64-der' | 'rfc9440';

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
     */
    clientCertificate?: PeerCertificate;
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

