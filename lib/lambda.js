/*!
 * client-certificate-auth/lambda - AWS Lambda event adapter
 * Copyright (C) 2013-2026 Tony Gies
 * @license MIT
 */

import { pemToCertificate } from './parsers.js';

/**
 * @typedef {import('./extractor.js').ExtractionResult} ExtractionResult
 */

/**
 * Extract a client certificate from an AWS API Gateway Lambda event.
 *
 * API Gateway HTTP API (v2.0 payload) delivers the validated mTLS client
 * certificate as a pre-parsed object at
 * `event.requestContext.authentication.clientCert`. The legacy REST API
 * (v1.0 payload) delivers it at `event.requestContext.identity.clientCert`.
 * Both payloads carry a `clientCertPem` field plus parsed `subjectDN`,
 * `issuerDN`, `serialNumber`, and `validity` fields.
 *
 * Parses `clientCertPem` into a `PeerCertificate` so the same validation
 * logic used with `getPeerCertificate()` or `extractClientCertificate()`
 * works inside a Lambda handler. If both v1 and v2 fields are present,
 * v2 takes precedence.
 *
 * @param {object | null | undefined} event - The Lambda event object from API Gateway (also accepts null/undefined)
 * @returns {ExtractionResult}
 *
 * Rejection reasons:
 * - 'lambda_event_missing_clientcert' - No clientCertPem at either v1 or v2 location
 * - 'lambda_event_clientcert_malformed' - clientCertPem present but parsing failed
 *
 * @example
 * import { extractClientCertificateFromLambdaEvent } from 'client-certificate-auth/lambda';
 *
 * export const handler = async (event) => {
 *   const result = extractClientCertificateFromLambdaEvent(event);
 *   if (!result.success) return { statusCode: 401, body: result.reason };
 *   if (result.certificate.subject.CN !== 'authorized-client') {
 *     return { statusCode: 403 };
 *   }
 *   return { statusCode: 200, body: 'OK' };
 * };
 */
export function extractClientCertificateFromLambdaEvent(event) {
  const v2 = event?.requestContext?.authentication?.clientCert;
  const v1 = event?.requestContext?.identity?.clientCert;
  const clientCert = v2 ?? v1;

  if (!clientCert?.clientCertPem) {
    return {
      success: false,
      certificate: null,
      reason: 'lambda_event_missing_clientcert',
    };
  }

  try {
    return {
      success: true,
      certificate: pemToCertificate(clientCert.clientCertPem),
      reason: null,
    };
  } catch {
    return {
      success: false,
      certificate: null,
      reason: 'lambda_event_clientcert_malformed',
    };
  }
}
