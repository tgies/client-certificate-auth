/*!
 * client-certificate-auth/helpers - TypeScript declarations
 * Copyright (C) 2013-2026 Tony Gies
 * @license MIT
 */

import type { PeerCertificate } from 'tls';

/**
 * Validation callback for clientCertificateAuth middleware.
 */
export type ValidationCallback = (cert: PeerCertificate) => boolean | Promise<boolean>;

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
 * Supports both full format (e.g., "SHA256:AB:CD:...") and raw hex.
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
