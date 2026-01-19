/*!
 * client-certificate-auth/parsers - TypeScript declarations
 * Copyright (C) 2013-2024 Tony Gies
 * @license MIT
 */

import type { PeerCertificate } from 'tls';

/**
 * Supported header encoding formats.
 */
export type HeaderEncoding = 'url-pem' | 'url-pem-aws' | 'xfcc' | 'base64-der' | 'rfc9440';

/**
 * Supported certificate source presets.
 */
export type CertificateSource = 'aws-alb' | 'envoy' | 'cloudflare' | 'traefik';

/**
 * Preset configuration for a reverse proxy.
 */
export interface PresetConfig {
    /** HTTP header name (lowercase) */
    header: string;
    /** Encoding format used by this proxy */
    encoding: HeaderEncoding;
}

/**
 * Preset configurations for common reverse proxies.
 */
export declare const PRESETS: Record<CertificateSource, PresetConfig>;

/**
 * Configuration for certificate extraction from headers.
 */
export interface CertificateHeaderConfig {
    /** Use a preset configuration for a known proxy */
    certificateSource?: CertificateSource;
    /** Custom header name (overrides preset) */
    certificateHeader?: string;
    /** Encoding format (required if certificateHeader is set without certificateSource) */
    headerEncoding?: HeaderEncoding;
}

/**
 * Parse URL-encoded PEM certificate (nginx, HAProxy format).
 * @see https://nginx.org/en/docs/http/ngx_http_ssl_module.html#var_ssl_client_escaped_cert
 */
export declare function parseUrlPem(headerValue: string): PeerCertificate | null;

/**
 * Parse URL-encoded PEM certificate with AWS ALB safe character handling.
 * @see https://docs.aws.amazon.com/elasticloadbalancing/latest/application/mutual-authentication.html
 */
export declare function parseUrlPemAws(headerValue: string): PeerCertificate | null;

/**
 * Parse Envoy XFCC (X-Forwarded-Client-Cert) structured header format.
 * @see https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers#x-forwarded-client-cert
 */
export declare function parseXfcc(headerValue: string): PeerCertificate | null;

/**
 * Parse base64-encoded DER certificate (Cloudflare, Traefik format).
 * Also handles Traefik's comma-separated cert chains.
 * @see https://developers.cloudflare.com/api-shield/security/mtls/configure/
 */
export declare function parseBase64Der(headerValue: string): PeerCertificate | null;

/**
 * Parse RFC 9440 format certificate (used by Google Cloud Load Balancer).
 * @see https://datatracker.ietf.org/doc/html/rfc9440#section-2.1
 */
export declare function parseRfc9440(headerValue: string): PeerCertificate | null;

/**
 * Convert PEM-encoded certificate to PeerCertificate-like object.
 */
export declare function pemToCertificate(pem: string): PeerCertificate;

/**
 * Convert DER-encoded certificate to PeerCertificate-like object.
 */
export declare function derToCertificate(der: Buffer): PeerCertificate;

/**
 * Parse certificate from header value using specified encoding.
 */
export declare function parseHeaderValue(
    headerValue: string,
    encoding: HeaderEncoding
): PeerCertificate | null;

/**
 * Get certificate from request headers using configuration.
 */
export declare function getCertificateFromHeaders(
    headers: Record<string, string | string[] | undefined>,
    config: CertificateHeaderConfig
): PeerCertificate | null;
