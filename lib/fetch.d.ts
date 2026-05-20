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
    headers: Iterable<[string, string]>;
}

/**
 * Extract a client certificate from a Web standard `Request` or any
 * object with iterable headers. Header-only (no TLS socket in Web Request).
 *
 * @param request - A Web Request or any object with iterable headers
 * @param options - Same options as `extractClientCertificate`. Header options only.
 */
export declare function extractClientCertificateFromRequest(
    request: RequestLike,
    options?: ExtractorOptions
): ExtractionResult;
