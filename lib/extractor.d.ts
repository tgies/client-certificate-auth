/**
 * @typedef {Object} ExtractorOptions
 * @property {'aws-alb' | 'aws-alb-verify' | 'azure-app-service' | 'cloudflare' | 'cloudflare-rfc9440' | 'envoy' | 'traefik'} [certificateSource] - Preset configuration
 * @property {string} [certificateHeader] - Custom header name
 * @property {string} [chainHeader] - Optional second header carrying the certificate chain
 * @property {'url-pem' | 'url-pem-aws' | 'xfcc' | 'base64-der' | 'rfc9440'} [headerEncoding] - Header encoding
 * @property {boolean} [fallbackToSocket=false] - Try socket if header extraction fails
 * @property {boolean} [includeChain=false] - Include issuerCertificate chain
 * @property {string} [verifyHeader] - Header name for upstream verification status. Pairs
 *   with `verifyValue`, and requires `certificateSource` or `certificateHeader`:
 *   verification applies to header-based extraction only.
 * @property {string} [verifyValue] - Expected value for successful verification. Pairs
 *   with `verifyHeader`.
 */
/**
 * Extract client certificate from request.
 *
 * Works with both header-based extraction (reverse proxy scenarios) and socket-based
 * extraction (direct TLS connections). Returns a structured result object instead of
 * throwing or using callbacks, making it suitable for any framework adapter.
 *
 * @param {Object} req - Request object with headers and optional socket. A missing or
 *   non-object `headers` field, one whose accessor throws, and one holding a
 *   property whose accessor throws are all treated as having no headers.
 * @param {Record<string, string | string[] | undefined>} [req.headers] - HTTP headers object
 * @param {string[]} [req.rawHeaders] - Node's raw header list; a certificate or
 *   verification header that appears more than once is rejected
 * @param {Object} [req.socket] - TLS socket with getPeerCertificate() method
 * @param {boolean} [req.socket.authorized] - Whether socket was authorized
 * @param {(detailed: boolean) => import('tls').PeerCertificate} [req.socket.getPeerCertificate] - Get peer certificate
 * @param {ExtractorOptions} [options={}] - Extraction options
 * @returns {ExtractionResult}
 *
 * @example
 * // AWS ALB header extraction
 * const result = extractClientCertificate(req, { certificateSource: 'aws-alb' });
 * if (result.success) {
 *   console.log('Certificate CN:', result.certificate.subject.CN);
 * } else {
 *   console.error('Extraction failed:', result.reason);
 * }
 *
 * @example
 * // Socket extraction with fallback
 * const result = extractClientCertificate(req, {
 *   certificateSource: 'envoy',
 *   fallbackToSocket: true
 * });
 */
export function extractClientCertificate(req: {
    headers?: Record<string, string | string[] | undefined>;
    rawHeaders?: string[];
    socket?: {
        authorized?: boolean;
        getPeerCertificate?: (detailed: boolean) => import("tls").PeerCertificate;
    };
}, options?: ExtractorOptions): ExtractionResult;
/**
 * Validate options shared by `extractClientCertificate` and the middleware constructor.
 * Throws on an unknown `certificateSource` or `headerEncoding`, a header-name option that
 * is not a non-empty string, a flag that is not a boolean, `certificateHeader` without an
 * encoding source, `chainHeader` or `verifyHeader` without a leaf header source, or only
 * one of `verifyHeader`/`verifyValue`.
 * Omitted or `undefined` options are treated as the empty object; any other non-object
 * value, `null` and arrays among them, throws a `TypeError`.
 */
export function validateExtractorOptions(options?: ExtractorOptions): void;
/**
 * Rejection reason codes:
 * - 'verification_header_mismatch' - Proxy verify header didn't match expected value
 * - 'header_missing_or_malformed' - Header extraction failed and no fallback configured
 * - 'socket_not_authorized' - Socket not authorized for TLS client cert, or unreadable
 * - 'certificate_not_retrievable' - Socket authorized but getPeerCertificate() is missing, returned empty, or threw
 */
export type ExtractionFailureReason =
    | "verification_header_mismatch"
    | "header_missing_or_malformed"
    | "socket_not_authorized"
    | "certificate_not_retrievable";
export type ExtractionSuccess = {
    success: true;
    /**
     * - Extracted certificate
     */
    certificate: import("./parsers.js").ChainedPeerCertificate;
    reason: null;
};
export type ExtractionFailure = {
    success: false;
    certificate: null;
    /**
     * - Rejection reason code
     */
    reason: ExtractionFailureReason;
};
/**
 * Discriminated on `success`: narrowing on it exposes `certificate` on
 * success and `reason` on failure without null checks.
 */
export type ExtractionResult = ExtractionSuccess | ExtractionFailure;
export type ExtractorOptions = {
    /**
     * - Preset configuration
     */
    certificateSource?: "aws-alb" | "aws-alb-verify" | "azure-app-service" | "cloudflare" | "cloudflare-rfc9440" | "envoy" | "traefik";
    /**
     * - Custom header name
     */
    certificateHeader?: string;
    /**
     * - Optional second header carrying the certificate chain
     */
    chainHeader?: string;
    /**
     * - Header encoding
     */
    headerEncoding?: "url-pem" | "url-pem-aws" | "xfcc" | "base64-der" | "rfc9440";
    /**
     * - Try socket if header extraction fails
     */
    fallbackToSocket?: boolean;
    /**
     * - Include issuerCertificate chain
     */
    includeChain?: boolean;
    /**
     * - Header name for upstream verification status. Pairs with `verifyValue`, and
     * requires `certificateSource` or `certificateHeader`: verification applies to
     * header-based extraction only.
     */
    verifyHeader?: string;
    /**
     * - Expected value for successful verification. Pairs with `verifyHeader`.
     */
    verifyValue?: string;
};
