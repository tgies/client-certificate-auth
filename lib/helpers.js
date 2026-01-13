/*!
 * client-certificate-auth/helpers - Authorization helper utilities
 * Copyright (C) 2013-2026 Tony Gies
 * @license MIT
 */

/**
 * @typedef {import('tls').PeerCertificate} PeerCertificate
 * @typedef {(cert: PeerCertificate) => boolean | Promise<boolean>} ValidationCallback
 */

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
    return (cert) => allowed.has(cert.subject?.CN);
}

/**
 * Create a validation callback that allows certificates with matching fingerprints.
 * Supports both full format (e.g., "SHA256:AB:CD:...") and raw hex.
 *
 * @param {string[]} fingerprints - Allowed fingerprints
 * @returns {ValidationCallback}
 *
 * @example
 * app.use(clientCertificateAuth(allowFingerprints([
 *   'SHA256:AB:CD:EF:...',
 *   'AB:CD:EF:...'
 * ])));
 */
export function allowFingerprints(fingerprints) {
    // Normalize fingerprints: uppercase, remove SHA256: prefix if present
    const normalize = (fp) => fp.toUpperCase().replace(/^SHA256:/i, '');
    const allowed = new Set(fingerprints.map(normalize));

    return (cert) => {
        if (!cert.fingerprint) {return false;}
        return allowed.has(normalize(cert.fingerprint));
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
    return (cert) => {
        if (!cert.issuer) {return false;}
        return entries.every(([key, value]) => cert.issuer[key] === value);
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
    return (cert) => {
        if (!cert.subject) {return false;}
        return entries.every(([key, value]) => cert.subject[key] === value);
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
    return (cert) => allowed.has(cert.subject?.OU);
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
    return (cert) => allowed.has(cert.subject?.O);
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
        // Check subject.emailAddress
        if (cert.subject?.emailAddress) {
            if (allowed.has(cert.subject.emailAddress.toLowerCase())) {
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
    return async (cert) => {
        const results = await Promise.all(callbacks.map((cb) => cb(cert)));
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
    return async (cert) => {
        const results = await Promise.all(callbacks.map((cb) => cb(cert)));
        return results.some((r) => r === true);
    };
}
