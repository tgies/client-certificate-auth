/**
 * @typedef {Object} ExtractionResult
 * @property {boolean} success - Whether extraction succeeded
 * @property {import('tls').PeerCertificate | null} certificate - Extracted certificate (null on failure)
 * @property {string | null} reason - Rejection reason code (null on success)
 *
 * Rejection reasons:
 * - 'verification_header_mismatch' - Proxy verify header didn't match expected value
 * - 'header_missing_or_malformed' - Header extraction failed and no fallback configured
 * - 'socket_not_authorized' - Socket not authorized for TLS client cert
 * - 'certificate_not_retrievable' - Socket authorized but getPeerCertificate() returned empty
 */
/**
 * @typedef {Object} ExtractorOptions
 * @property {'aws-alb' | 'envoy' | 'cloudflare' | 'traefik'} [certificateSource] - Preset configuration
 * @property {string} [certificateHeader] - Custom header name
 * @property {'url-pem' | 'url-pem-aws' | 'xfcc' | 'base64-der' | 'rfc9440'} [headerEncoding] - Header encoding
 * @property {boolean} [fallbackToSocket=false] - Try socket if header extraction fails
 * @property {boolean} [includeChain=false] - Include issuerCertificate chain
 * @property {string} [verifyHeader] - Header name for upstream verification status
 * @property {string} [verifyValue] - Expected value for successful verification
 */
/**
 * Extract client certificate from request.
 *
 * Works with both header-based extraction (reverse proxy scenarios) and socket-based
 * extraction (direct TLS connections). Returns a structured result object instead of
 * throwing or using callbacks, making it suitable for any framework adapter.
 *
 * @param {Object} req - Request object with headers and optional socket
 * @param {Record<string, string | string[] | undefined>} req.headers - HTTP headers object
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
    headers: Record<string, string | string[] | undefined>;
    socket?: {
        authorized?: boolean;
        getPeerCertificate?: (detailed: boolean) => import("tls").PeerCertificate;
    };
}, options?: ExtractorOptions): ExtractionResult;
export type ExtractionResult = {
    /**
     * - Whether extraction succeeded
     */
    success: boolean;
    /**
     * - Extracted certificate (null on failure)
     */
    certificate: import("tls").PeerCertificate | null;
    /**
     * - Rejection reason code (null on success)
     *
     * Rejection reasons:
     * - 'verification_header_mismatch' - Proxy verify header didn't match expected value
     * - 'header_missing_or_malformed' - Header extraction failed and no fallback configured
     * - 'socket_not_authorized' - Socket not authorized for TLS client cert
     * - 'certificate_not_retrievable' - Socket authorized but getPeerCertificate() returned empty
     */
    reason: string | null;
};
export type ExtractorOptions = {
    /**
     * - Preset configuration
     */
    certificateSource?: "aws-alb" | "envoy" | "cloudflare" | "traefik";
    /**
     * - Custom header name
     */
    certificateHeader?: string;
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
     * - Header name for upstream verification status
     */
    verifyHeader?: string;
    /**
     * - Expected value for successful verification
     */
    verifyValue?: string;
};
