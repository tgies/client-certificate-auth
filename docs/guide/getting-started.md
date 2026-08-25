# Getting Started

## What This Library Does

This library authenticates HTTP clients by their TLS client certificates, a scheme usually called mutual TLS (mTLS). Instead of presenting a password, API key, or bearer token, the client presents an X.509 certificate during the TLS handshake and proves possession of its private key; the server checks that the certificate was issued by a CA it trusts. The certificate is the credential.

Typical uses:

- **Service-to-service APIs**: internal microservices or partner integrations where each caller holds its own certificate rather than a shared secret.
- **Machine and device authentication**: CI runners, IoT devices, daemons. Certificates are issued per machine and revoked per machine.
- **Restricting sensitive endpoints**: admin interfaces, metrics, internal tooling that only known clients should reach.
- **Certificate-based user login**: enterprise PKI and smart-card environments, where certificates map to user accounts.

The TLS handshake proves who the client is; your application decides whether that client is allowed in. This library covers the part in between: it extracts the verified certificate from the request wherever your TLS terminates, parses it into a standard [`tls.PeerCertificate`](https://nodejs.org/api/tls.html#certificate-object) object, and passes it to your authorization callback. Supported certificate sources:

- **TLS terminated directly in Node.js**: the certificate is read from the TLS socket. Covered on this page.
- **A TLS-terminating reverse proxy or load balancer** that forwards the certificate in an HTTP header: AWS ALB, Envoy/Istio, Cloudflare, Traefik, Azure App Service, nginx, HAProxy, and any proxy that implements RFC 9440. See [Reverse Proxy Support](./reverse-proxy).
- **AWS Lambda** behind API Gateway mTLS. See [AWS Lambda](./lambda).
- **Web-standard `Request` runtimes** such as Hono, Next.js, SvelteKit, Cloudflare Workers, Bun, and Deno. See [Fetch / Web Request](./fetch).

Express and Connect get drop-in middleware. Other frameworks use the same extraction logic through [`extractClientCertificate()`](#extractclientcertificate-req-options). Pre-built [authorization helpers](./helpers) cover the common policies (allowlist by CN, fingerprint, issuer, OU, SAN, and more).

## Installation

```bash
npm install client-certificate-auth
```

**Requirements:** Node.js >= 20

## Basic Setup

Configure your HTTPS server to request and validate client certificates:

```javascript
import express from 'express';
import https from 'node:https';
import fs from 'node:fs';
import clientCertificateAuth from 'client-certificate-auth';

const app = express();

// Validate certificate against your authorization rules
const checkAuth = (cert) => {
  return cert.subject.CN === 'trusted-client';
};

// Apply to all routes
app.use(clientCertificateAuth(checkAuth));

app.get('/', (req, res) => {
  res.send('Authorized!');
});

// HTTPS server configuration
const opts = {
  key: fs.readFileSync('server.key'),
  cert: fs.readFileSync('server.pem'),
  ca: fs.readFileSync('ca.pem'),       // CA that signed client certs
  requestCert: true,                    // Request client certificate
  rejectUnauthorized: false             // Let middleware handle errors
};

https.createServer(opts, app).listen(443);
```

The key points in this setup:

- **`requestCert: true`** tells Node.js to ask the client for a certificate during the TLS handshake.
- **`rejectUnauthorized: false`** prevents Node.js from silently dropping connections when certificate validation fails, letting the middleware provide helpful error messages instead.
- **`ca`** specifies the CA certificate(s) that signed your client certificates.

## Per-Route Protection

You don't have to protect every route. Use `clientCertificateAuth` as per-route middleware to protect only specific endpoints:

```javascript
app.get('/public', (req, res) => {
  res.send('Hello world');
});

app.get('/admin', clientCertificateAuth(checkAuth), (req, res) => {
  res.send('Hello admin');
});
```

## Async Authorization

The authorization callback supports async functions, letting you check certificates against databases, external services, or other asynchronous sources:

```javascript
const checkAuth = async (cert) => {
  const user = await db.findByFingerprint(cert.fingerprint);
  return user !== null;
};

app.use(clientCertificateAuth(checkAuth));
```

## Custom Error Messages

Throw errors for granular authorization feedback instead of returning `false`:

```javascript
const checkAuth = (cert) => {
  if (isRevoked(cert.serialNumber)) {
    throw new Error('Certificate has been revoked');
  }
  if (!allowlist.includes(cert.fingerprint)) {
    throw new Error('Certificate not in allowlist');
  }
  return true;
};

// Thrown errors are passed to Express error handlers with:
// - error.message = your custom message
// - error.status = 401 (unless you set a different status)
```

To use a different status code, set it on the error before throwing:

```javascript
const err = new Error('Access forbidden');
err.status = 403;
throw err;
```

## Audit Logging Hooks

Use `onAuthenticated` and `onRejected` hooks to log authentication decisions without affecting request processing:

```javascript
app.use(clientCertificateAuth(checkAuth, {
  onAuthenticated: (cert, req) => {
    logger.info('mTLS auth success', {
      cn: cert.subject.CN,
      fingerprint: cert.fingerprint,
      path: req.url,
      ip: req.ip
    });
  },
  onRejected: (cert, req, reason) => {
    logger.warn('mTLS auth failed', {
      cn: cert?.subject?.CN,
      reason,
      path: req.url,
      ip: req.ip
    });
  }
}));
```

**Hook characteristics:**

- **Fire-and-forget**: Hooks don't block request processing. Async hooks run in the background.
- **Error-safe**: Hook errors are caught and logged to `console.error`, never affecting the request.
- **Cert may be null**: In `onRejected`, `cert` is `null` when certificate extraction failed (socket not authorized, header missing, etc.)

**Rejection reasons:**

| Reason | Description |
|--------|-------------|
| `socket_not_authorized` | TLS socket authorization failed |
| `certificate_not_retrievable` | Socket authorized but cert couldn't be read |
| `header_missing_or_malformed` | Certificate header absent or unparseable |
| `verification_header_mismatch` | Proxy verify header didn't match expected value |
| `callback_returned_false` | Your callback returned `false` |
| *(error message)* | Your callback threw an error |

## API Overview

### `clientCertificateAuth(callback, options?)`

Returns Express middleware that extracts a client certificate and passes it to your callback for authorization.

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `callback` | `(cert, req?) => boolean \| PromiseLike<boolean>` | Receives the client certificate and request, returns `true` to allow access |
| `options.certificateSource` | `string` | Use a preset for a known proxy: `'aws-alb'`, `'aws-alb-verify'`, `'azure-app-service'`, `'cloudflare'`, `'cloudflare-rfc9440'`, `'envoy'`, `'traefik'` |
| `options.certificateHeader` | `string` | Custom header name to read certificate from |
| `options.chainHeader` | `string` | Second header carrying the certificate chain alongside the leaf (RFC 9440 style) |
| `options.headerEncoding` | `string` | Encoding format: `'url-pem'`, `'url-pem-aws'`, `'xfcc'`, `'base64-der'`, `'rfc9440'` |
| `options.fallbackToSocket` | `boolean` | If header extraction fails, try `socket.getPeerCertificate()` (default: `false`) |
| `options.includeChain` | `boolean` | If `true`, include full certificate chain via `cert.issuerCertificate` (default: `false`) |
| `options.verifyHeader` | `string` | Header name containing verification status from proxy (e.g., `'X-SSL-Client-Verify'`) |
| `options.verifyValue` | `string` | Expected value indicating successful verification (e.g., `'SUCCESS'`) |
| `options.onAuthenticated` | `(cert, req) => void` | Called on successful authentication (fire-and-forget) |
| `options.onRejected` | `(cert, req, reason) => void` | Called on authentication failure (fire-and-forget) |

**Certificate Object:**

The `cert` parameter contains fields from [`tls.PeerCertificate`](https://nodejs.org/api/tls.html#certificate-object):

- `subject.CN` - Common Name
- `subject.O` - Organization
- `issuer` - Issuer information
- `fingerprint` - Certificate fingerprint
- `valid_from`, `valid_to` - Validity period
- `issuerCertificate` - Issuer's certificate (only when `includeChain: true`)

For the full generated API reference, see the [API docs](/api/clientCertificateAuth/).

### `extractClientCertificate(req, options?)`

Framework-agnostic certificate extraction function exported from `client-certificate-auth/extractor`. Use this when building adapters for non-Express frameworks or when you need certificate extraction without middleware.

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `req` | `Object` | Request object with `headers` and optional `socket` |
| `req.headers` | `Record<string, string \| string[]>` | Optional. HTTP headers object; a missing or unreadable one counts as no headers |
| `req.socket` | `Object` | Optional TLS socket (for socket-based extraction) |
| `options` | `Object` | Same options as middleware (except `onAuthenticated`/`onRejected`) |

**Returns:** `ExtractionResult`

```typescript
{
  success: boolean;
  certificate: PeerCertificate | null;
  reason: string | null;  // Rejection reason if success is false
}
```

**Rejection reasons:**

- `'verification_header_mismatch'` — Proxy verify header didn't match expected value
- `'header_missing_or_malformed'` — Header extraction failed and no fallback configured
- `'socket_not_authorized'` — Socket not authorized for TLS client cert
- `'certificate_not_retrievable'` — Socket authorized but `getPeerCertificate()` returned empty

**Example - Building a Koa adapter:**

```javascript
import { extractClientCertificate } from 'client-certificate-auth/extractor';

function koaClientCert(checkAuth, options = {}) {
  return async (ctx, next) => {
    const result = extractClientCertificate(ctx.req, options);

    if (!result.success) {
      ctx.throw(401, result.reason);
    }

    ctx.state.clientCertificate = result.certificate;

    const allowed = await checkAuth(result.certificate, ctx.req);
    if (!allowed) {
      ctx.throw(401, 'Certificate not authorized');
    }

    await next();
  };
}

// Usage
app.use(koaClientCert(
  (cert) => cert.subject.CN === 'admin',
  { certificateSource: 'aws-alb' }
));
```

**Example - Custom authentication flow:**

```javascript
import { extractClientCertificate } from 'client-certificate-auth/extractor';

app.post('/api/login', (req, res) => {
  // Extract certificate without middleware
  const result = extractClientCertificate(req, {
    certificateSource: 'envoy',
    fallbackToSocket: true
  });

  if (!result.success) {
    return res.status(401).json({ error: result.reason });
  }

  // Custom auth logic
  const user = lookupUserByCertFingerprint(result.certificate.fingerprint);
  if (!user) {
    return res.status(403).json({ error: 'Certificate not registered' });
  }

  // Issue session token
  const token = createSessionToken(user);
  res.json({ token, user });
});
```

For the full generated API reference, see the [extractor docs](/api/extractor/).

## Accessing the Certificate

After authentication, the certificate is attached to `req.clientCertificate` for downstream handlers:

```javascript
app.use(clientCertificateAuth(checkAuth));

app.get('/whoami', (req, res) => {
  res.json({
    cn: req.clientCertificate.subject.CN,
    fingerprint: req.clientCertificate.fingerprint
  });
});
```

The certificate is attached before the authorization callback runs, so it's available even if authorization fails (useful for logging).

## Certificate Chain Access

For enterprise PKI scenarios, you may need to inspect intermediate CAs or the root CA:

```javascript
app.use(clientCertificateAuth((cert) => {
  // Check issuer's organization
  if (cert.issuerCertificate) {
    return cert.issuerCertificate.subject.O === 'Trusted Root CA';
  }
  return false;
}, { includeChain: true }));
```

When `includeChain: true`, the certificate object includes `issuerCertificate` linking to the issuer's certificate (and so on up the chain). This works consistently for both socket-based and header-based extraction.

For header-based extraction the first certificate in the header is the leaf. If it is empty or unparseable the header is rejected with `header_missing_or_malformed` rather than promoting the next certificate into the leaf position. See [Chains in a Single Header](./reverse-proxy.md#chains-in-a-single-header) for the per-encoding details.

## User Login Patterns

Client certificates provide cryptographically-verified identity, making them ideal for user authentication. Map certificate fields to user accounts in your database:

```javascript
app.use(clientCertificateAuth(async (cert) => {
  // Option 1: Lookup by fingerprint (most secure - immutable per certificate)
  const user = await db.users.findOne({ certFingerprint: cert.fingerprint });

  // Option 2: Lookup by email (from subject or SAN)
  // const user = await db.users.findOne({ email: cert.subject.emailAddress });

  // Option 3: Lookup by Common Name
  // const user = await db.users.findOne({ certCN: cert.subject.CN });

  if (!user) {
    throw new Error('Certificate not registered to any user');
  }

  return true;
}));
```

To make the user available to downstream handlers, attach it to the request:

```javascript
app.use(clientCertificateAuth(async (cert, req) => {
  const user = await db.users.findOne({ certFingerprint: cert.fingerprint });
  if (!user) throw new Error('Unknown certificate');

  req.user = user;  // Attach for downstream routes
  return true;
}));

app.get('/profile', (req, res) => {
  res.json({
    name: req.user.name,
    certificateCN: req.clientCertificate.subject.CN
  });
});
```

**Lookup strategies:**

| Field | Pros | Cons |
|-------|------|------|
| `fingerprint` | Unique, immutable | Must register each cert |
| `subject.emailAddress` | Human-readable | Ensure uniqueness |
| `subject.CN` | Simple to configure | May not be unique |
| `serialNumber` + issuer | Traceable to your CA | More complex queries |

## Ecosystem

This package provides everything you need to build mTLS authentication for any Node.js framework:

- **Certificate extraction** via `extractClientCertificate()` - handles both socket and header-based extraction
- **Authorization helpers** - reusable validation callbacks for common patterns (`allowCN`, `allowFingerprints`, etc.)
- **Parser library** - decode certificates from various reverse proxy formats (Envoy XFCC, AWS ALB, Cloudflare, etc.)
- **Type definitions** - full TypeScript support

**Official framework adapters:**

- **[passport-client-certificate-auth](https://www.npmjs.com/package/passport-client-certificate-auth)** - Passport.js strategy for mTLS authentication

**Community adapters:**

If you build an adapter for another framework (Koa, Fastify, Hapi, NestJS, etc.), please [open an issue or PR](https://github.com/tgies/client-certificate-auth/issues) to get it listed here!

## Test Coverage

This library has comprehensive test coverage across multiple layers:

| Layer | Description |
|-------|-------------|
| **Unit tests** | 100% line/branch/function/statement coverage, enforced in CI |
| **Integration tests** | Real HTTPS servers with mTLS handshakes |
| **E2E proxy tests** | Docker containers running nginx, Envoy, and Traefik with actual certificate forwarding |
| **Mutation testing** | [Stryker](https://dashboard.stryker-mutator.io/reports/github.com/tgies/client-certificate-auth/master) verifies tests detect code changes |

The E2E tests spin up real reverse proxies, generate fresh certificates, and verify the middleware correctly parses each proxy's header format through a variety of successful and failed authentication attempts.

## Next Steps

Now that you have the basics, explore the rest of the guide:

- **[Reverse Proxy Support](./reverse-proxy)** - Configure header-based certificate extraction for AWS ALB, Envoy, Cloudflare, Traefik, and custom proxies
- **[WebSocket Support](./websocket)** - Authenticate WebSocket connections with `ws` and Socket.IO
- **[Authorization Helpers](./helpers)** - Use pre-built validators for CN, fingerprint, issuer, OU, and more
- **[TypeScript & CJS](./typescript)** - TypeScript types and CommonJS usage
- **[Troubleshooting](./troubleshooting)** - Common issues and solutions
- **[End-to-End mTLS Demo](/examples/e2e-mtls)** - A runnable example demonstrating the full mTLS flow
