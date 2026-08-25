/*!
 * client-certificate-auth/helpers - TypeScript declarations
 * Copyright (C) 2013-2026 Tony Gies
 * @license MIT
 */

import type { ValidationCallback } from './clientCertificateAuth.js';

export type { ValidationCallback };

/**
 * Distinguished Name fields for matching.
 */
export interface DNFields {
    /** Common Name */
    CN?: string;
    /** Organization */
    O?: string;
    /** Organizational Unit */
    OU?: string;
    /** Country */
    C?: string;
    /** State/Province */
    ST?: string;
    /** Locality */
    L?: string;
}

/**
 * Create a validation callback that allows certificates with matching Common Names.
 * @param names - Allowed Common Names
 */
export declare function allowCN(names: string[]): ValidationCallback;

/**
 * Create a validation callback that allows certificates with matching fingerprints.
 * Supports SHA-1 fingerprints (compared against cert.fingerprint) and SHA-256
 * fingerprints with "SHA256:" prefix (compared against cert.fingerprint256).
 * Fingerprints without a prefix are treated as SHA-1 unless they carry 64 hex
 * digits, which is SHA-256.
 * @param fingerprints - Allowed fingerprints
 */
export declare function allowFingerprints(fingerprints: string[]): ValidationCallback;

/**
 * Create a validation callback that allows certificates with matching issuer fields.
 * All specified fields must match (partial matching).
 * @param match - Issuer fields to match
 */
export declare function allowIssuer(match: DNFields): ValidationCallback;

/**
 * Create a validation callback that allows certificates with matching subject fields.
 * All specified fields must match (partial matching).
 * @param match - Subject fields to match
 */
export declare function allowSubject(match: DNFields): ValidationCallback;

/**
 * Create a validation callback that allows certificates with matching Organizational Units.
 * @param ous - Allowed Organizational Units
 */
export declare function allowOU(ous: string[]): ValidationCallback;

/**
 * Create a validation callback that allows certificates with matching Organizations.
 * @param orgs - Allowed Organizations
 */
export declare function allowOrganization(orgs: string[]): ValidationCallback;

/**
 * Create a validation callback that allows certificates with matching serial numbers.
 * Normalizes hex formats (with/without colons).
 * @param serials - Allowed serial numbers
 */
export declare function allowSerial(serials: string[]): ValidationCallback;

/**
 * Create a validation callback that allows certificates with matching Subject Alternative Names.
 * Checks the subjectaltname field (format: "DNS:example.com, email:user@example.com").
 * Bare values (no type prefix) match under any SAN type. Comparison is case-insensitive
 * except for URI userinfo, path, query, and fragment; JSON-quoted values in Node's SAN rendering
 * are decoded first.
 * @param values - Allowed SAN values (e.g., "DNS:example.com", "example.com", "user@example.com")
 */
export declare function allowSAN(values: string[]): ValidationCallback;

/**
 * Create a validation callback that allows certificates with matching email addresses.
 * Checks both SAN email entries and subject.emailAddress.
 * @param emails - Allowed email addresses
 */
export declare function allowEmail(emails: string[]): ValidationCallback;

/**
 * Create a validation callback that accepts certificates issued by one of the given
 * CA certificates, directly or through the `issuerCertificate` chain attached with
 * `includeChain: true`. Performs the subset of PKIX path validation that applies to a
 * forwarded client certificate: issuer name and signature at every link, keyUsage
 * keyCertSign where an issuer carries it, basicConstraints cA on every CA including the
 * anchor, pathLenConstraint counting non-self-issued intermediates, clientAuth in the
 * Extended Key Usage of every certificate on the path that carries one, digitalSignature
 * or keyAgreement in the leaf's keyUsage when present, validity windows on every
 * certificate, and rejection of any certificate carrying name constraints at any criticality
 * or any other critical extension it does not process, so a name-constrained intermediate
 * anywhere in the chain fails the check. Does
 * not check revocation. Anchors must be CA certificates that permit clientAuth. Throws at
 * construction if a CA certificate cannot be parsed, is not a CA, does not permit
 * clientAuth, carries name constraints or an unsupported critical extension, or sits in a
 * PEM bundle whose blocks cannot all be read, and if `maxDepth` is not a positive integer.
 * @param caCertificates - PEM or DER encoded CA certificates; a PEM bundle contributes every certificate it holds
 * @param options - `maxDepth` bounds the number of certificates walked, leaf included (default 10)
 */
export declare function allowCA(
    caCertificates: string | Buffer | Array<string | Buffer>,
    options?: { maxDepth?: number }
): ValidationCallback;

/**
 * Combine multiple validation callbacks with AND logic.
 * All callbacks must return true for the certificate to be authorized.
 * @param callbacks - Validation callbacks to combine
 */
export declare function allOf(...callbacks: ValidationCallback[]): ValidationCallback;

/**
 * Combine multiple validation callbacks with OR logic.
 * At least one callback must return true for the certificate to be authorized.
 * @param callbacks - Validation callbacks to combine
 */
export declare function anyOf(...callbacks: ValidationCallback[]): ValidationCallback;
