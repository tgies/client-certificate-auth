/*!
 * client-certificate-auth/fetch - TypeScript declarations
 * Copyright (C) 2013-2026 Tony Gies
 * @license MIT
 */

import type { ExtractorOptions, ExtractionResult } from './extractor.js';

/**
 * Any object whose `headers` field iterates as `[name, value]` tuples.
 * Web `Request`, undici `Headers`, Bun, Deno, and Node 18+ `Headers`
 * all work without modification.
 */
export interface RequestLike {
    /** Missing, non-iterable, and unreadable headers count as no headers. */
    headers?: Iterable<[string, string]>;
}

/**
 * Extract a client certificate from a Web standard `Request` or any
 * object with iterable headers. Header-only (no TLS socket in Web Request).
 *
 * @param request - A Web Request or any object with iterable headers. Missing or
 *   non-iterable headers, and entries that are not `[name, value]` tuples, are ignored.
 *   A repeated certificate header is rejected where the iterable exposes it. A Web
 *   `Headers` joins repeated lines into one value before this sees them: `url-pem`,
 *   `url-pem-aws`, `rfc9440`, and `base64-der` under every preset but `traefik` reject
 *   that joined form. `xfcc`, and `base64-der` read through `traefik` or a
 *   hand-configured `certificateHeader`, use the comma grammatically and cannot tell it
 *   apart, so there the origin must be reachable only through the proxy.
 * @param options - Same options as `extractClientCertificate`. Header options only.
 */
export declare function extractClientCertificateFromRequest(
    request: RequestLike,
    options?: ExtractorOptions
): ExtractionResult;
