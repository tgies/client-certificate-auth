/*!
 * client-certificate-auth/helpers - Authorization helper utilities
 * Copyright (C) 2013-2026 Tony Gies
 * @license MIT
 */

import { X509Certificate } from 'node:crypto';
import { splitPemBlocks } from './parsers.js';

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
 * Parse a certificate object's DER bytes; null when there are none.
 * @param {import('./parsers.js').ChainedPeerCertificate} cert
 * @returns {X509Certificate | null}
 */
function toX509(cert) {
    try {
        return new X509Certificate(cert.raw);
    } catch {
        return null;
    }
}

/**
 * @param {X509Certificate} x509
 * @param {number} now
 * @returns {boolean}
 */
function withinValidity(x509, now) {
    return Date.parse(x509.validFrom) <= now && now <= Date.parse(x509.validTo);
}

/**
 * @param {X509Certificate} subject
 * @param {X509Certificate} issuer
 * @returns {boolean}
 */
function issuedBy(subject, issuer) {
    return subject.checkIssued(issuer) && subject.verify(issuer.publicKey);
}

const CLIENT_AUTH_OID = '1.3.6.1.5.5.7.3.2';
const BASIC_CONSTRAINTS_OID = '2.5.29.19';
const KEY_USAGE_OID = '2.5.29.15';
const KU_DIGITAL_SIGNATURE = 0x80;
const KU_KEY_AGREEMENT = 0x08;

/**
 * Extensions the path check processes. keyUsage, basicConstraints, and
 * extKeyUsage are read directly; subjectKeyIdentifier and
 * authorityKeyIdentifier are consumed by checkIssued(); subjectAltName is
 * carried through to the application, and is critical on certificates with
 * an empty subject (RFC 5280 s4.2.1.6). A certificate carrying any other
 * critical extension (certificate policies among them) is rejected, as
 * RFC 5280 requires of a validator that does not process it.
 */
const PROCESSED_EXTENSIONS = new Set([
    '2.5.29.14', // subjectKeyIdentifier
    '2.5.29.15', // keyUsage
    '2.5.29.17', // subjectAltName
    '2.5.29.19', // basicConstraints
    '2.5.29.35', // authorityKeyIdentifier
    '2.5.29.37', // extKeyUsage
]);

/**
 * Constraints a conforming validator enforces at any criticality. They are
 * not processed here, so a certificate carrying one is rejected outright.
 */
const UNPROCESSED_CONSTRAINTS = new Set([
    '2.5.29.30', // nameConstraints
]);

/**
 * Read one DER element: its tag and the bounds of its content.
 * @param {Buffer} der
 * @param {number} offset
 * @returns {{ tag: number, start: number, end: number }}
 */
function readElement(der, offset) {
    const tag = der[offset];
    let length = der[offset + 1];
    let start = offset + 2;
    if (length & 0x80) {
        const size = length & 0x7f;
        length = 0;
        for (let i = 0; i < size; i++) {
            length = length * 256 + der[start + i];
        }
        start += size;
    }
    return { tag, start, end: start + length };
}

/**
 * Decode a DER OBJECT IDENTIFIER body to dotted form.
 * @param {Buffer} der
 * @param {number} start
 * @param {number} end
 * @returns {string}
 */
function decodeOid(der, start, end) {
    const arcs = [];
    let value = 0;
    for (let i = start; i < end; i++) {
        value = value * 128 + (der[i] & 0x7f);
        if ((der[i] & 0x80) === 0) {
            if (arcs.length === 0) {
                const first = value < 80 ? Math.floor(value / 40) : 2;
                arcs.push(first, value - first * 40);
            } else {
                arcs.push(value);
            }
            value = 0;
        }
    }
    return arcs.join('.');
}

/**
 * List a certificate's extensions from its DER: the [3] EXPLICIT element of
 * the TBSCertificate, each entry a SEQUENCE of OID, optional critical
 * BOOLEAN, and an OCTET STRING value.
 * @param {Buffer} der
 * @returns {Array<{ oid: string, critical: boolean, value: Buffer }>}
 */
function readExtensions(der) {
    const certificate = readElement(der, 0);
    const tbs = readElement(der, certificate.start);
    const extensions = [];
    let offset = tbs.start;
    while (offset < tbs.end) {
        const field = readElement(der, offset);
        if (field.tag === 0xa3) {
            const list = readElement(der, field.start);
            let position = list.start;
            while (position < list.end) {
                const entry = readElement(der, position);
                const oid = readElement(der, entry.start);
                let next = readElement(der, oid.end);
                let critical = false;
                if (next.tag === 0x01) {
                    critical = der[next.start] !== 0;
                    next = readElement(der, next.end);
                }
                extensions.push({
                    oid: decodeOid(der, oid.start, oid.end),
                    critical,
                    value: der.subarray(next.start, next.end),
                });
                position = entry.end;
            }
            break;
        }
        offset = field.end;
    }
    return extensions;
}

/**
 * The pathLenConstraint from basicConstraints, or undefined when absent.
 * @param {Array<{ oid: string, value: Buffer }>} extensions
 * @returns {number | undefined}
 */
function pathLengthConstraint(extensions) {
    const basic = extensions.find((extension) => extension.oid === BASIC_CONSTRAINTS_OID);
    if (!basic) {
        return undefined;
    }
    const sequence = readElement(basic.value, 0);
    let offset = sequence.start;
    while (offset < sequence.end) {
        const field = readElement(basic.value, offset);
        if (field.tag === 0x02) {
            let length = 0;
            for (let i = field.start; i < field.end; i++) {
                length = length * 256 + basic.value[i];
            }
            return length;
        }
        offset = field.end;
    }
    return undefined;
}

/**
 * The first byte of the keyUsage BIT STRING (digitalSignature is its high
 * bit), or undefined when the extension is absent.
 * @param {Array<{ oid: string, value: Buffer }>} extensions
 * @returns {number | undefined}
 */
function keyUsageBits(extensions) {
    const usage = extensions.find((extension) => extension.oid === KEY_USAGE_OID);
    if (!usage) {
        return undefined;
    }
    const bits = readElement(usage.value, 0);
    return usage.value[bits.start + 1];
}

/**
 * Canonical form of a rendered distinguished name for self-issued detection:
 * ASCII-space runs collapsed and ASCII letters case folded per RDN, matching
 * what OpenSSL's canonical name comparison folds. Unicode spaces and letters
 * outside A-Z are left intact, so names differing only by a non-breaking space
 * or by a character such as U+212A KELVIN SIGN are not folded into a match,
 * which would drop a real intermediate from the path-length count.
 * An empty DN renders as undefined and canonicalizes to ''.
 * @param {string | undefined} name
 * @returns {string}
 */
function canonicalName(name) {
    return (name ?? '').split('\n').map((rdn) => rdn.replace(/ +/g, ' ').replace(/^ | $/g, '').replace(/[A-Z]/g, (letter) => letter.toLowerCase())).join('\n');
}

/**
 * @typedef {{ x509: X509Certificate, pathLen: number | undefined, keyUsage: number | undefined, selfIssued: boolean, unsupported: { oid: string, critical: boolean } | undefined }} PathCertificate
 */

/**
 * Parse the fields the path check needs from a certificate.
 * @param {X509Certificate} x509
 * @returns {PathCertificate}
 */
function inspect(x509) {
    const extensions = readExtensions(x509.raw);
    const unsupported = extensions.find((extension) =>
        UNPROCESSED_CONSTRAINTS.has(extension.oid) || (extension.critical && !PROCESSED_EXTENSIONS.has(extension.oid))
    );
    return {
        x509,
        pathLen: pathLengthConstraint(extensions),
        keyUsage: keyUsageBits(extensions),
        selfIssued: canonicalName(x509.subject) === canonicalName(x509.issuer),
        unsupported: unsupported && { oid: unsupported.oid, critical: unsupported.critical },
    };
}

/**
 * The individual CA certificates one `caCertificates` entry carries. A PEM
 * bundle contributes every block it holds; DER and unparseable input are
 * passed through for X509Certificate to accept or reject.
 * @param {string | Buffer} ca
 * @returns {Array<string | Buffer>}
 */
function toAnchorCertificates(ca) {
    const text = Buffer.isBuffer(ca) ? ca.toString('latin1') : ca;
    const blocks = splitPemBlocks(text);
    // X509Certificate reads only the first certificate of a blob, so any block
    // carrying a label splitPemBlocks does not recognize (OpenSSL's TRUSTED
    // CERTIFICATE among them) drops out of a multi-block bundle unnoticed. One
    // such block on its own still reaches X509Certificate whole.
    const present = (text.match(/-----BEGIN [^-\n]*CERTIFICATE-----/g) || []).length;
    if (present > Math.max(blocks.length, 1)) {
        throw new Error('client-certificate-auth: allowCA could not split this PEM bundle; pass each certificate as its own entry');
    }
    return blocks.length > 0 ? blocks : [ca];
}

/**
 * Whether a CA's pathLenConstraint permits `intermediates` non-self-issued CA
 * certificates below it.
 * @param {PathCertificate} ca
 * @param {number} intermediates
 * @returns {boolean}
 */
function permitsPathLength(ca, intermediates) {
    return ca.pathLen === undefined || ca.pathLen >= intermediates;
}

/**
 * A certificate carrying an Extended Key Usage extension must list
 * clientAuth; one without the extension is unrestricted. Node exposes the
 * extension's OIDs as `keyUsage`.
 * @param {X509Certificate} x509
 * @returns {boolean}
 */
function permitsClientAuth(x509) {
    const extendedKeyUsage = x509.keyUsage;
    return extendedKeyUsage === undefined || extendedKeyUsage.includes(CLIENT_AUTH_OID);
}

/**
 * Create a validation callback that accepts certificates issued by one of the
 * given CA certificates, directly or through the `issuerCertificate` chain
 * attached with `includeChain: true`.
 *
 * It performs the subset of PKIX path validation that applies to a forwarded
 * client certificate: issuer name and signature at every link, keyUsage
 * keyCertSign where an issuer carries the extension, basicConstraints cA on
 * every CA including the anchor, pathLenConstraint counting non-self-issued
 * intermediates, clientAuth in the Extended Key Usage of every certificate on
 * the path that carries one, digitalSignature or keyAgreement in the leaf's
 * keyUsage when present, validity windows on every certificate, and rejection
 * of any certificate carrying name constraints at any criticality or any
 * other critical extension it does not process, so a name-constrained or
 * policy-constrained intermediate anywhere in the chain fails the check. It
 * does not process name constraints or certificate policies, and does not
 * check revocation. Where the proxy can validate the client certificate
 * itself, prefer that.
 *
 * This establishes trust for passthrough presets (`aws-alb`,
 * `azure-app-service`), where the proxy forwards the presented certificate
 * without validating it. Anchors must be CA certificates that permit
 * clientAuth; intermediates may be listed alongside roots to trust them
 * directly, and a specific leaf is pinned with `allowFingerprints` instead.
 * Throws at construction if a CA certificate cannot be parsed, is not a CA,
 * does not permit clientAuth, carries name constraints or an unsupported
 * critical extension, or sits in a PEM bundle whose blocks cannot all be read,
 * and if `maxDepth` is not a positive integer.
 *
 * @param {string | Buffer | Array<string | Buffer>} caCertificates - PEM or DER encoded CA certificates; a PEM bundle contributes every certificate it holds
 * @param {{ maxDepth?: number }} [options] - `maxDepth` bounds the number of certificates walked, leaf included (default 10)
 * @returns {ValidationCallback}
 *
 * @example
 * app.use(clientCertificateAuth(allowCA(readFileSync('ca.pem')), {
 *   certificateSource: 'aws-alb',
 *   includeChain: true
 * }));
 */
export function allowCA(caCertificates, options = {}) {
    const anchors = toArray(caCertificates).flatMap(toAnchorCertificates).map((ca) => inspect(new X509Certificate(ca)));
    for (const anchor of anchors) {
        const name = anchor.x509.subject;
        if (anchor.unsupported) {
            const kind = anchor.unsupported.critical ? 'critical extension' : 'extension';
            throw new Error(`client-certificate-auth: allowCA CA certificate '${name}' carries unsupported ${kind} ${anchor.unsupported.oid}`);
        }
        if (!anchor.x509.ca) {
            throw new Error(`client-certificate-auth: allowCA CA certificate '${name}' is not usable as a CA certificate (needs basicConstraints cA, and keyCertSign where keyUsage is present)`);
        }
        if (!permitsClientAuth(anchor.x509)) {
            throw new Error(`client-certificate-auth: allowCA CA certificate '${name}' does not permit clientAuth in its extended key usage`);
        }
    }
    const { maxDepth = 10 } = options;
    if (!Number.isInteger(maxDepth) || maxDepth < 1) {
        throw new Error('client-certificate-auth: allowCA maxDepth must be a positive integer');
    }
    if (anchors.length === 0) {return () => false;}

    return (/** @type {import('./parsers.js').ChainedPeerCertificate} */ cert) => {
        const now = Date.now();
        const leaf = toX509(cert);
        if (!leaf) {return false;}
        let subject = inspect(leaf);
        if (subject.keyUsage !== undefined && (subject.keyUsage & (KU_DIGITAL_SIGNATURE | KU_KEY_AGREEMENT)) === 0) {return false;}
        let current = cert;
        let intermediates = 0;
        for (let depth = 0; depth < maxDepth; depth++) {
            if (subject.unsupported || !permitsClientAuth(subject.x509) || !withinValidity(subject.x509, now)) {return false;}
            if (anchors.some((ca) => withinValidity(ca.x509, now) && permitsPathLength(ca, intermediates) && issuedBy(subject.x509, ca.x509))) {
                return true;
            }
            const issuer = current.issuerCertificate;
            if (!issuer || issuer === current) {return false;}
            const issuerX509 = toX509(issuer);
            if (!issuerX509 || !issuerX509.ca || !issuedBy(subject.x509, issuerX509)) {return false;}
            const link = inspect(issuerX509);
            if (!permitsPathLength(link, intermediates)) {return false;}
            if (!link.selfIssued) {intermediates++;}
            current = issuer;
            subject = link;
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
