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
 * Rejection reason codes:
 * - 'lambda_event_missing_clientcert' - No clientCertPem at either v1 or v2 location
 * - 'lambda_event_clientcert_malformed' - clientCertPem present but parsing failed
 */
export type LambdaExtractionFailureReason =
    | 'lambda_event_missing_clientcert'
    | 'lambda_event_clientcert_malformed';

export interface LambdaExtractionSuccess {
    success: true;
    /** Extracted certificate. */
    certificate: PeerCertificate;
    reason: null;
}

export interface LambdaExtractionFailure {
    success: false;
    certificate: null;
    /** Rejection reason code. */
    reason: LambdaExtractionFailureReason;
}

/**
 * Result returned by `extractClientCertificateFromLambdaEvent`. Discriminated
 * on `success` like the core extractor's `ExtractionResult`.
 */
export type LambdaExtractionResult = LambdaExtractionSuccess | LambdaExtractionFailure;

/**
 * Extract a client certificate from an AWS API Gateway Lambda event. Handles
 * both v2.0 payload format (`event.requestContext.authentication.clientCert`)
 * and v1.0 payload format (`event.requestContext.identity.clientCert`).
 *
 * Also accepts `null` and `undefined`, returning
 * `lambda_event_missing_clientcert`.
 *
 * @param event - The Lambda event from API Gateway, or null/undefined
 *
 * @see https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-mutual-tls.html
 */
export declare function extractClientCertificateFromLambdaEvent(
    event: LambdaEventWithClientCert | null | undefined
): LambdaExtractionResult;
