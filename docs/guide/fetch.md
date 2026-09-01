# Fetch / Web Request

When using a framework that exposes Web standard `Request` and `Response` (Hono, Next.js Route Handlers, SvelteKit `hooks.server.ts`, Astro middleware, Remix loaders, Cloudflare Workers, `Bun.serve`, `Deno.serve`), the Express-style `(req, res, next)` middleware signature does not apply. There is no Node `req.socket` and `request.headers` is a `Headers` map rather than a plain object.

The `client-certificate-auth/fetch` subpath provides a small framework-agnostic adapter for this case.

## Usage

```javascript
import { extractClientCertificateFromRequest } from 'client-certificate-auth/fetch';

const result = extractClientCertificateFromRequest(request, {
  certificateSource: 'cloudflare-rfc9440',
});

if (!result.success) {
  // Reject with 401 or your framework's equivalent
}
```

The helper returns the same `{ success, certificate, reason }` result as `extractClientCertificate()` from `client-certificate-auth/extractor`. Validation helpers from `client-certificate-auth/helpers` work without modification.

A successful result means a certificate parsed, not that it is trusted. Behind passthrough presets (`aws-alb`, `azure-app-service`) the certificate is whatever the client sent; verify it with `allowCA` (Azure App Service forwards only the leaf, so give `allowCA` the issuing CA certificate), as in the Next.js recipe below, or pin it with `allowFingerprints`. See the [passthrough warnings](./reverse-proxy.md#preset-details).

## Header-Only

Web `Request` does not expose the TLS socket, so the Fetch adapter is header-only. Configure a header source via `certificateSource` or `certificateHeader` + `headerEncoding`; `fallbackToSocket` has no effect.

The header is the only evidence of the client's identity, so the origin must be reachable only through the proxy that sets it (behind ALB, a security group that admits only the load balancer). A client that can reach the origin directly can supply the header itself. See [Security Considerations](./reverse-proxy.md#security-considerations).

::: warning Runtime requirement
The adapter imports the core extractor, which uses `node:crypto` (`X509Certificate`). Runtimes must provide Node-compatible crypto: Node, Bun, Deno, and Cloudflare Workers with `nodejs_compat` all work. Pure edge runtimes without Node compatibility will fail at import time.
:::

## Recipes

### Hono

```javascript
import { Hono } from 'hono';
import { extractClientCertificateFromRequest } from 'client-certificate-auth/fetch';

const app = new Hono();

app.get('/secure', (c) => {
  const result = extractClientCertificateFromRequest(c.req.raw, {
    certificateSource: 'cloudflare-rfc9440',
  });
  if (!result.success) return c.text('Unauthorized', 401);
  return c.text(`Hello ${result.certificate.subject.CN}`);
});

export default app;
```

### Next.js Route Handler

```javascript
// app/api/secure/route.js
import { readFileSync } from 'node:fs';
import { extractClientCertificateFromRequest } from 'client-certificate-auth/fetch';
import { allowCA } from 'client-certificate-auth/helpers';

// ALB passthrough forwards the presented chain without validating it.
const trustedCA = allowCA(readFileSync('ca.pem'));

export async function GET(request) {
  const result = extractClientCertificateFromRequest(request, {
    certificateSource: 'aws-alb',
    includeChain: true,
  });
  if (!result.success || trustedCA(result.certificate) !== true) {
    return new Response('Unauthorized', { status: 401 });
  }
  return Response.json({ user: result.certificate.subject.CN });
}
```

### SvelteKit hooks.server.ts

```typescript
import type { Handle } from '@sveltejs/kit';
import { extractClientCertificateFromRequest } from 'client-certificate-auth/fetch';

export const handle: Handle = async ({ event, resolve }) => {
  const result = extractClientCertificateFromRequest(event.request, {
    certificateSource: 'cloudflare-rfc9440',
  });
  if (result.success) {
    event.locals.user = { cn: result.certificate.subject.CN };
  }
  return resolve(event);
};
```

### Astro middleware

```typescript
// src/middleware.ts
import { defineMiddleware } from 'astro:middleware';
import { extractClientCertificateFromRequest } from 'client-certificate-auth/fetch';

export const onRequest = defineMiddleware(async (context, next) => {
  // ALB verify mode: ALB validated the certificate against its trust store.
  const result = extractClientCertificateFromRequest(context.request, {
    certificateSource: 'aws-alb-verify',
  });
  if (!result.success) return new Response('Unauthorized', { status: 401 });
  context.locals.user = { cn: result.certificate.subject.CN };
  return next();
});
```

### Cloudflare Workers

```javascript
import { extractClientCertificateFromRequest } from 'client-certificate-auth/fetch';

export default {
  async fetch(request, env) {
    const result = extractClientCertificateFromRequest(request, {
      certificateSource: 'cloudflare-rfc9440',
    });
    if (!result.success) return new Response('Unauthorized', { status: 401 });
    return new Response(`Hello ${result.certificate.subject.CN}`);
  },
};
```

### Remix / React Router 7 loader

```typescript
import type { LoaderFunctionArgs } from 'react-router';
import { extractClientCertificateFromRequest } from 'client-certificate-auth/fetch';

export async function loader({ request }: LoaderFunctionArgs) {
  // ALB verify mode: ALB validated the certificate against its trust store.
  const result = extractClientCertificateFromRequest(request, {
    certificateSource: 'aws-alb-verify',
  });
  if (!result.success) throw new Response('Unauthorized', { status: 401 });
  return { user: { cn: result.certificate.subject.CN } };
}
```

### Bun.serve

```javascript
import { extractClientCertificateFromRequest } from 'client-certificate-auth/fetch';

Bun.serve({
  port: 3000,
  fetch(request) {
    const result = extractClientCertificateFromRequest(request, {
      certificateSource: 'cloudflare-rfc9440',
    });
    if (!result.success) return new Response('Unauthorized', { status: 401 });
    return new Response(`Hello ${result.certificate.subject.CN}`);
  },
});
```

## Plain Header-Iterable Objects

The adapter accepts any object whose `headers` field iterates as `[name, value]` tuples. A native `Headers` instance, a `Map`, or any custom equivalent works:

```javascript
const headers = new Map([['client-cert', ':base64DER:']]);
const result = extractClientCertificateFromRequest({ headers }, {
  certificateSource: 'cloudflare-rfc9440',
});
```

This is useful for testing without constructing a full Web `Request`.

## CommonJS

```javascript
const fetchAdapter = await require('client-certificate-auth/fetch').load();
const result = fetchAdapter.extractClientCertificateFromRequest(request, {
  certificateSource: 'aws-alb',
});
```

## See Also

- [Reverse proxy support](./reverse-proxy.md) for the supported presets and encodings, including the new `cloudflare-rfc9440` and the `chainHeader` option for RFC 9440 two-header schemes.
