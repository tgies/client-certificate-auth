/*!
 * client-certificate-auth/fetch - Web Request adapter
 * Copyright (C) 2013-2026 Tony Gies
 * @license MIT
 */

import { extractClientCertificate, validateExtractorOptions } from './extractor.js';

/**
 * @typedef {import('./extractor.js').ExtractorOptions} ExtractorOptions
 * @typedef {import('./extractor.js').ExtractionResult} ExtractionResult
 */

/**
 * Extract a client certificate from a Web standard `Request` (or any object
 * with an iterable `headers` field that yields `[name, value]` tuples).
 *
 * Normalizes header names to lowercase and delegates to the core
 * `extractClientCertificate`. Header-only: Web `Request` has no TLS socket,
 * so `fallbackToSocket` is stripped and has no effect.
 *
 * @param {{ headers?: Iterable<[string, string]> }} request - A Web Request or any object whose `headers` iterates `[name, value]` pairs.
 *   Missing or non-iterable headers, and entries that are not `[name, value]` tuples, are ignored.
 *   A repeated certificate header is rejected where the iterable exposes it. A Web `Headers`
 *   joins repeated lines into one value before this sees them: `url-pem`, `url-pem-aws`,
 *   `rfc9440`, and `base64-der` under every preset but `traefik` reject that joined form.
 *   `xfcc`, and `base64-der` read through `traefik` or a hand-configured
 *   `certificateHeader`, use the comma grammatically and cannot tell it apart, so there the
 *   origin must be reachable only through the proxy.
 * @param {ExtractorOptions} [options={}] - Same options as `extractClientCertificate`. Header-extraction options only; socket options are ignored.
 * @returns {ExtractionResult}
 *
 * @example
 * // Hono
 * import { extractClientCertificateFromRequest } from 'client-certificate-auth/fetch';
 *
 * app.get('/secure', async (c) => {
 *   const result = extractClientCertificateFromRequest(c.req.raw, {
 *     certificateSource: 'cloudflare-rfc9440',
 *   });
 *   if (!result.success) return c.text('Unauthorized', 401);
 *   return c.text(`Hello ${result.certificate.subject.CN}`);
 * });
 *
 * @example
 * // Next.js Route Handler
 * export async function GET(request) {
 *   const result = extractClientCertificateFromRequest(request, {
 *     certificateSource: 'aws-alb',
 *   });
 *   if (!result.success) return new Response('Unauthorized', { status: 401 });
 *   return Response.json({ user: result.certificate.subject.CN });
 * }
 */
export function extractClientCertificateFromRequest(request, options = {}) {
  // Validated here as well as in the extractor: fallbackToSocket is stripped
  // below and would otherwise never be checked.
  validateExtractorOptions(options);

  // Web Headers normalizes to lowercase, but Map and other iterables
  // preserve casing. Normalize here for the core extractor's lowercase lookup.
  let headers = Object.create(null);
  /** @type {string[]} */
  let rawHeaders = [];
  try {
    const supplied = /** @type {any} */ (request?.headers);
    if (typeof supplied?.[Symbol.iterator] === 'function') {
      for (const entry of supplied) {
        if (!Array.isArray(entry) || entry.length !== 2) {
          continue;
        }
        // Read once: an accessor could otherwise pass the check below and
        // hand the assignment something else.
        const [name, value] = entry;
        if (typeof name !== 'string' || typeof value !== 'string') {
          continue;
        }
        // Every entry is recorded, so a repeated certificate header reaches the
        // extractor's duplicate check.
        rawHeaders.push(name, value);
        headers[name.toLowerCase()] = value;
      }
    }
  } catch {
    // A throwing iterator or accessor leaves a partial read. Discard it.
    headers = Object.create(null);
    rawHeaders = [];
  }

  const { fallbackToSocket: _ignored, ...rest } = options;

  return extractClientCertificate({ headers, rawHeaders }, rest);
}
