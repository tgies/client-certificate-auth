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
 * Fingerprints without a prefix are treated as SHA-1 unless they carry 64
 * hex digits, which is SHA-256. Hex inputs are normalized: case and colon
 * delimiters are ignored on both sides.
 *
 * @param {string[]} fingerprints - Allowed fingerprints
 * @returns {ValidationCallback}
 *
 * @example
 * app.use(clientCertificateAuth(allowFingerprints([
 *   'SHA256:AB:CD:EF:...',  // matched against cert.fingerprint256
 *   'AB:CD:EF:...',         // colon-delimited, matched against cert.fingerprint
 *   'ABCDEF...'             // contiguous hex also matches cert.fingerprint
 * ])));
 */
export function allowFingerprints(fingerprints) {
    const normalize = (fp) => fp.toUpperCase().replace(/:/g, '');
    const sha256Allowed = new Set();
    const sha1Allowed = new Set();

    for (const fp of fingerprints) {
        const upper = fp.toUpperCase();
        if (upper.startsWith('SHA256:')) {
            sha256Allowed.add(normalize(upper.slice(7)));
        } else {
            const digest = normalize(upper);
            (digest.length === 64 ? sha256Allowed : sha1Allowed).add(digest);
        }
    }

    return (cert) => {
        if (sha1Allowed.size > 0 && cert.fingerprint) {
            if (sha1Allowed.has(normalize(cert.fingerprint))) {return true;}
        }
        if (sha256Allowed.size > 0 && cert.fingerprint256) {
            if (sha256Allowed.has(normalize(cert.fingerprint256))) {return true;}
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

const SAN_TYPES = new Set(['dns', 'email', 'uri', 'ip address', 'dirname', 'registered id', 'othername']);

/**
 * Split "type:value" at a recognized SAN type prefix. Unknown prefixes stay
 * in the value so bare items like "https://x" or "::1" keep their colons.
 * @param {string} text
 * @returns {{ type: string | null, value: string }}
 */
function splitSanType(text) {
    const colonIdx = text.indexOf(':');
    if (colonIdx !== -1) {
        let type = text.slice(0, colonIdx).toLowerCase();
        if (type === 'ip') {type = 'ip address';}
        if (SAN_TYPES.has(type)) {
            return { type, value: text.slice(colonIdx + 1) };
        }
    }
    return { type: null, value: text };
}

/**
 * Node renders SAN values containing commas, quotes, backslashes, or control
 * characters as JSON strings.
 * @param {string} value
 * @returns {string}
 */
function decodeSanValue(value) {
    if (!value.startsWith('"')) {
        return value;
    }
    try {
        return JSON.parse(value);
    } catch {
        return value;
    }
}

/**
 * Case-fold a URI for comparison: the scheme and host are case-insensitive,
 * while userinfo, path, query, and fragment are not (RFC 3986 section 6.2.2.1).
 * @param {string} value
 * @returns {string}
 */
function foldUri(value) {
    const scheme = /^[a-z][a-z0-9+.-]*:/i.exec(value);
    if (!scheme) {return value;}
    let folded = scheme[0].toLowerCase();
    let rest = value.slice(scheme[0].length);
    if (rest.startsWith('//')) {
        const end = rest.slice(2).search(/[/?#]/);
        const authority = end === -1 ? rest.slice(2) : rest.slice(2, 2 + end);
        rest = end === -1 ? '' : rest.slice(2 + end);
        const at = authority.lastIndexOf('@');
        folded += '//' + authority.slice(0, at + 1) + authority.slice(at + 1).toLowerCase();
    }
    return folded + rest;
}

/**
 * Case-fold a SAN value for comparison. URIs fold their scheme and host;
 * every other type folds the whole value.
 * @param {string | null} type
 * @param {string} value
 * @returns {string}
 */
function foldSanValue(type, value) {
    return type === 'uri' ? foldUri(value) : value.toLowerCase();
}

/**
 * Create a validation callback that allows certificates with matching Subject Alternative Names.
 * Values may carry a type prefix ("DNS:api.example.com") or be bare, in which case they match
 * that value under any SAN type. Type prefixes, DNS names, email addresses, and IP addresses
 * compare case-insensitively; URIs fold only the scheme and host, so userinfo, path, query,
 * and fragment stay case-sensitive. Values Node renders JSON-quoted (containing commas, quotes,
 * or control characters) are decoded before comparison.
 *
 * @param {string[]} values - Allowed SAN values (e.g., "DNS:example.com", "example.com", "user@example.com")
 * @returns {ValidationCallback}
 *
 * @example
 * app.use(clientCertificateAuth(allowSAN(['DNS:api.example.com', 'email:admin@example.com'])));
 */
export function allowSAN(values) {
    const allowed = values.map((v) => splitSanType(v));

    return (cert) => {
        if (!cert.subjectaltname) {return false;}

        // Node joins entries with ", " and JSON-quotes any value containing a comma.
        const entries = cert.subjectaltname.split(/,\s*/).map((entry) => {
            const { type, value } = splitSanType(entry);
            return { type, value: decodeSanValue(value) };
        });

        return entries.some(({ type, value }) => {
            const folded = foldSanValue(type, value);
            return allowed.some((item) =>
                (item.type === null || item.type === type)
                    && foldSanValue(type, item.value) === folded
            );
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
            for (const entry of cert.subjectaltname.split(/,\s*/)) {
                const { type, value } = splitSanType(entry);
                if (type === 'email' && allowed.has(decodeSanValue(value).toLowerCase())) {return true;}
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
