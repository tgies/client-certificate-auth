/*!
 * client-certificate-auth/lambda - TypeScript declarations
 * Copyright (C) 2013-2026 Tony Gies
 * @license MIT
 */

import type { PeerCertificate } from 'tls';

/**
 * Client certificate object from the API Gateway Lambda event.
 * Common to v1 and v2 payload formats. Compatible with `@types/aws-lambda`
 * without requiring it as a dependency.
 */
export interface LambdaClientCert {
    /** PEM-encoded client certificate with BEGIN/END delimiters. */
    clientCertPem: string;
    /** Optional subject distinguished name string, parsed by API Gateway. */
    subjectDN?: string;
    /** Optional issuer distinguished name string, parsed by API Gateway. */
    issuerDN?: string;
    /** Optional certificate serial number string, parsed by API Gateway. */
    serialNumber?: string;
    /** Optional validity window parsed by API Gateway. */
    validity?: {
        notBefore?: string;
        notAfter?: string;
    };
}

/**
 * Lambda event subset declaring only the cert-bearing paths.
 * Accepts HTTP API (v2.0) and REST API (v1.0) payload formats.
 */
export interface LambdaEventWithClientCert {
    requestContext?: {
        /** v2.0 payload format: HTTP API. */
        authentication?: {
            clientCert?: LambdaClientCert;
        };
        /** v1.0 payload format: REST API. */
        identity?: {
            clientCert?: LambdaClientCert;
        };
    };
}

/**
 * Result returned by `extractClientCertificateFromLambdaEvent`.
 * Matches the core extractor's `ExtractionResult`.
 */
export interface LambdaExtractionResult {
    /** Whether extraction succeeded. */
    success: boolean;
    /** Extracted certificate (null on failure). */
    certificate: PeerCertificate | null;
    /**
     * Rejection reason code (null on success). Lambda-specific reasons:
     * - 'lambda_event_missing_clientcert'
     * - 'lambda_event_clientcert_malformed'
     */
    reason: string | null;
}

/**
 * Extract a client certificate from an AWS API Gateway Lambda event. Handles
 * both v2.0 payload format (`event.requestContext.authentication.clientCert`)
 * and v1.0 payload format (`event.requestContext.identity.clientCert`).
 *
 * @param event - The Lambda event from API Gateway
 *
 * @see https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-mutual-tls.html
 */
export declare function extractClientCertificateFromLambdaEvent(
    event: LambdaEventWithClientCert
): LambdaExtractionResult;
