/*!
 * client-certificate-auth/fetch - Web Request adapter for fetch-shaped runtimes
 * Copyright (C) 2013-2026 Tony Gies
 * @license MIT
 */

import { extractClientCertificate } from './extractor.js';

/**
 * @typedef {import('./extractor.js').ExtractorOptions} ExtractorOptions
 * @typedef {import('./extractor.js').ExtractionResult} ExtractionResult
 */

/**
 * Extract a client certificate from a Web standard `Request` (or any object
 * with an iterable `headers` field that yields `[name, value]` tuples).
 *
 * This adapter exists for fetch-shaped runtimes where there is no Node
 * `req.socket` and `request.headers` is a `Headers` map rather than a plain
 * object. It converts the headers via `Object.fromEntries(request.headers)`
 * and calls the core `extractClientCertificate` in header-only mode.
 *
 * Header-only by construction: the Web `Request` abstraction has no TLS
 * socket. Socket-based extraction is impossible through this entry point;
 * configure a header source via `certificateSource` or `certificateHeader`.
 *
 * Works in Hono, Next.js Route Handlers, SvelteKit hooks, Astro middleware,
 * Remix loaders, Cloudflare Workers, `Bun.serve`, `Deno.serve`, and any other
 * runtime that exposes a Web Request.
 *
 * @param {{ headers: Iterable<[string, string]> }} request - A Web Request or any object whose `headers` iterates `[name, value]` pairs.
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
  return extractClientCertificate(
    { headers: Object.fromEntries(request.headers) },
    options
  );
}
