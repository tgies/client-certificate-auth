/*!
 * client-certificate-auth/helpers - Authorization helper utilities
 * Copyright (C) 2013-2026 Tony Gies
 * @license MIT
 */

/**
 * @typedef {import('tls').PeerCertificate} PeerCertificate
 * @typedef {(cert: PeerCertificate, req?: import('http').IncomingMessage) => boolean | Promise<boolean>} ValidationCallback
 */

/**
 * Normalize a certificate DN field value to an array.
 * Node.js returns string for single-valued and string[] for multi-valued DN attributes.
 * @param {string | string[] | undefined} value
 * @returns {string[]}
 */
function toArray(value) {
    if (value === undefined || value === null) {return [];}
    return Array.isArray(value) ? value : [value];
}

/**
 * Create a validation callback that allows certificates with matching Common Names.
 *
 * @param {string[]} names - Allowed Common Names
 * @returns {ValidationCallback}
 *
 * @example
 * app.use(clientCertificateAuth(allowCN(['service-a', 'service-b'])));
 */
export function allowCN(names) {
    const allowed = new Set(names);
    return (cert) => toArray(cert.subject?.CN).some((cn) => allowed.has(cn));
}

/**
 * Create a validation callback that allows certificates with matching fingerprints.
 * Supports SHA-1 fingerprints (compared against cert.fingerprint) and SHA-256
 * fingerprints with "SHA256:" prefix (compared against cert.fingerprint256).
 * Fingerprints without a prefix are treated as SHA-1.
 *
 * @param {string[]} fingerprints - Allowed fingerprints
 * @returns {ValidationCallback}
 *
 * @example
 * app.use(clientCertificateAuth(allowFingerprints([
 *   'SHA256:AB:CD:EF:...',  // matched against cert.fingerprint256
 *   'AB:CD:EF:...'          // matched against cert.fingerprint (SHA-1)
 * ])));
 */
export function allowFingerprints(fingerprints) {
    const sha256Allowed = new Set();
    const sha1Allowed = new Set();

    for (const fp of fingerprints) {
        const upper = fp.toUpperCase();
        if (upper.startsWith('SHA256:')) {
            sha256Allowed.add(upper.slice(7));
        } else {
            sha1Allowed.add(upper);
        }
    }

    return (cert) => {
        if (sha1Allowed.size > 0 && cert.fingerprint) {
            if (sha1Allowed.has(cert.fingerprint.toUpperCase())) {return true;}
        }
        if (sha256Allowed.size > 0 && cert.fingerprint256) {
            if (sha256Allowed.has(cert.fingerprint256.toUpperCase())) {return true;}
        }
        return false;
    };
}

/**
 * Create a validation callback that allows certificates with matching issuer fields.
 * All specified fields must match (partial matching).
 *
 * @param {{ CN?: string; O?: string; OU?: string; C?: string; ST?: string; L?: string }} match - Issuer fields to match
 * @returns {ValidationCallback}
 *
 * @example
 * app.use(clientCertificateAuth(allowIssuer({ O: 'My Company', CN: 'Internal CA' })));
 */
export function allowIssuer(match) {
    const entries = Object.entries(match);
    if (entries.length === 0) {return () => false;}
    return (cert) => {
        if (!cert.issuer) {return false;}
        return entries.every(([key, value]) => toArray(cert.issuer[key]).includes(value));
    };
}

/**
 * Create a validation callback that allows certificates with matching subject fields.
 * All specified fields must match (partial matching).
 *
 * @param {{ CN?: string; O?: string; OU?: string; C?: string; ST?: string; L?: string }} match - Subject fields to match
 * @returns {ValidationCallback}
 *
 * @example
 * app.use(clientCertificateAuth(allowSubject({ O: 'My Company' })));
 */
export function allowSubject(match) {
    const entries = Object.entries(match);
    if (entries.length === 0) {return () => false;}
    return (cert) => {
        if (!cert.subject) {return false;}
        return entries.every(([key, value]) => toArray(cert.subject[key]).includes(value));
    };
}

/**
 * Create a validation callback that allows certificates with matching Organizational Units.
 *
 * @param {string[]} ous - Allowed Organizational Units
 * @returns {ValidationCallback}
 *
 * @example
 * app.use(clientCertificateAuth(allowOU(['Engineering', 'DevOps'])));
 */
export function allowOU(ous) {
    const allowed = new Set(ous);
    return (cert) => toArray(cert.subject?.OU).some((ou) => allowed.has(ou));
}

/**
 * Create a validation callback that allows certificates with matching Organizations.
 *
 * @param {string[]} orgs - Allowed Organizations
 * @returns {ValidationCallback}
 *
 * @example
 * app.use(clientCertificateAuth(allowOrganization(['My Company', 'Partner Corp'])));
 */
export function allowOrganization(orgs) {
    const allowed = new Set(orgs);
    return (cert) => toArray(cert.subject?.O).some((o) => allowed.has(o));
}

/**
 * Create a validation callback that allows certificates with matching serial numbers.
 * Normalizes hex formats (with/without colons).
 *
 * @param {string[]} serials - Allowed serial numbers
 * @returns {ValidationCallback}
 *
 * @example
 * app.use(clientCertificateAuth(allowSerial(['01:23:45:67', '89ABCDEF'])));
 */
export function allowSerial(serials) {
    // Normalize: uppercase, remove colons
    const normalize = (s) => s.toUpperCase().replace(/:/g, '');
    const allowed = new Set(serials.map(normalize));

    return (cert) => {
        if (!cert.serialNumber) {return false;}
        return allowed.has(normalize(cert.serialNumber));
    };
}

/**
 * Create a validation callback that allows certificates with matching Subject Alternative Names.
 * Checks the subjectaltname field (format: "DNS:example.com, email:user@example.com").
 *
 * @param {string[]} values - Allowed SAN values (e.g., "DNS:example.com", "example.com", "user@example.com")
 * @returns {ValidationCallback}
 *
 * @example
 * app.use(clientCertificateAuth(allowSAN(['DNS:api.example.com', 'email:admin@example.com'])));
 */
export function allowSAN(values) {
    // Normalize: if no prefix, match as-is; otherwise match the full "type:value" format
    const allowed = new Set(values.map((v) => v.toLowerCase()));

    return (cert) => {
        if (!cert.subjectaltname) {return false;}

        // Parse SAN string: "DNS:example.com, email:user@example.com, URI:https://..."
        const entries = cert.subjectaltname.split(/,\s*/).map((e) => e.toLowerCase());

        // Check if any SAN entry matches (either full "type:value" or just the value part)
        return entries.some((entry) => {
            if (allowed.has(entry)) {return true;}
            // Also check just the value part (after the colon)
            const colonIdx = entry.indexOf(':');
            // Stryker disable next-line ConditionalExpression: when true, slice(0) returns full entry which was already checked on line 159
            if (colonIdx !== -1) {
                const value = entry.slice(colonIdx + 1);
                if (allowed.has(value)) {return true;}
            }
            return false;
        });
    };
}

/**
 * Create a validation callback that allows certificates with matching email addresses.
 * Checks both SAN email entries and subject.emailAddress.
 *
 * @param {string[]} emails - Allowed email addresses
 * @returns {ValidationCallback}
 *
 * @example
 * app.use(clientCertificateAuth(allowEmail(['admin@example.com', 'service@example.com'])));
 */
export function allowEmail(emails) {
    const allowed = new Set(emails.map((e) => e.toLowerCase()));

    return (cert) => {
        // Check subject.emailAddress (may be string or string[] for multi-valued)
        if (cert.subject?.emailAddress) {
            if (toArray(cert.subject.emailAddress).some((e) => allowed.has(e.toLowerCase()))) {
                return true;
            }
        }

        // Check SAN for email entries
        if (cert.subjectaltname) {
            const entries = cert.subjectaltname.split(/,\s*/);
            for (const entry of entries) {
                if (entry.toLowerCase().startsWith('email:')) {
                    const email = entry.slice(6).toLowerCase();
                    if (allowed.has(email)) {return true;}
                }
            }
        }

        return false;
    };
}

/**
 * Combine multiple validation callbacks with AND logic.
 * All callbacks must return true for the certificate to be authorized.
 *
 * @param {...ValidationCallback} callbacks - Validation callbacks to combine
 * @returns {ValidationCallback}
 *
 * @example
 * app.use(clientCertificateAuth(allOf(
 *   allowIssuer({ O: 'My Company' }),
 *   allowOU(['Engineering', 'DevOps'])
 * )));
 */
export function allOf(...callbacks) {
    if (callbacks.length === 0) {
        return () => false;
    }
    return async (cert, req) => {
        const results = await Promise.all(callbacks.map((cb) => cb(cert, req)));
        return results.every((r) => r === true);
    };
}

/**
 * Combine multiple validation callbacks with OR logic.
 * At least one callback must return true for the certificate to be authorized.
 *
 * @param {...ValidationCallback} callbacks - Validation callbacks to combine
 * @returns {ValidationCallback}
 *
 * @example
 * app.use(clientCertificateAuth(anyOf(
 *   allowCN(['admin']),
 *   allowOU(['Administrators'])
 * )));
 */
export function anyOf(...callbacks) {
    return async (cert, req) => {
        const results = await Promise.all(callbacks.map((cb) => cb(cert, req)));
        return results.some((r) => r === true);
    };
}
