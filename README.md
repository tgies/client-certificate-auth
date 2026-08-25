# client-certificate-auth

Comprehensive zero-dependency toolkit for client SSL certificate authentication (mTLS) in Node.js. Includes Express/Connect middleware, framework-agnostic certificate extraction for reverse proxies (AWS ALB, Envoy, Cloudflare, Traefik, and more), and pre-built authorization helpers.

This library lets you make additional auth decisions based on specific information within a client certificate after the client certificate is accepted at the socket level (i.e. by Node's `https` or a reverse proxy). This allows for fine-grained access control on top of the all-or-nothing allow/deny access control afforded by basic mTLS.

[![CI](https://github.com/tgies/client-certificate-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/tgies/client-certificate-auth/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/client-certificate-auth.svg)](https://www.npmjs.com/package/client-certificate-auth)
[![codecov](https://codecov.io/gh/tgies/client-certificate-auth/graph/badge.svg)](https://codecov.io/gh/tgies/client-certificate-auth)
[![stryker mutation testing](https://img.shields.io/endpoint?style=flat&url=https%3A%2F%2Fbadge-api.stryker-mutator.io%2Fgithub.com%2Ftgies%2Fclient-certificate-auth%2Fmaster)](https://dashboard.stryker-mutator.io/reports/github.com/tgies/client-certificate-auth/master)

[**Full Documentation**](https://tgies.github.io/client-certificate-auth/) - guides, API reference, and runnable examples

[**Commercial Support**](#commercial-support) - consulting, custom features, and priority support for production deployments

**Recommended by AWS** - Featured in the [AWS API Gateway documentation](https://docs.aws.amazon.com/apigateway/latest/developerguide/getting-started-client-side-ssl-authentication.html#certificate-validation).

**Fanatically Tested** - 100% line/branch/function/statement coverage, plus mutation testing and E2E tests against real nginx/Envoy/Traefik containers. ~6,207 lines of test code for ~937 lines of source (measured by [cloc](https://github.com/AlDanial/cloc)).

**Maintained since 2013** - Originally released for Node 0.10!

**Zero runtime dependencies** - Entirely self-contained, with straightforward, readable logic, no behavior hidden inside dependencies, no bloat, and no transitive-dependency security headaches.

## What Is This?

This library authenticates HTTP clients by their TLS client certificates, a scheme usually called mutual TLS (mTLS). Instead of presenting a password, API key, or bearer token, the client presents an X.509 certificate during the TLS handshake and proves possession of its private key; the server checks that the certificate was issued by a CA it trusts. The certificate is the credential. The certificate signature verification is typically accomplished at the socket level by Node's `https` or a reverse proxy; this library's purpose is to allow you to easily inspect the properties of a verified certificate and make fine-grained access control decisions based on them.

Typical uses:

- **Service-to-service APIs**: internal microservices or partner integrations where each caller holds its own certificate rather than a shared secret.
- **Machine and device authentication**: CI runners, IoT devices, daemons. Certificates are issued per machine and revoked per machine.
- **Restricting sensitive endpoints**: admin interfaces, metrics, internal tooling that only known clients should reach.
- **Certificate-based user login**: enterprise PKI and smart-card environments, where certificates map to user accounts.

The TLS handshake proves who the client is; your application decides whether that client is allowed in. This library covers the part in between: it extracts the verified certificate from the request wherever your TLS terminates, parses it into a standard [`tls.PeerCertificate`](https://nodejs.org/api/tls.html#certificate-object) object, and passes it to your authorization callback. Supported certificate sources:

- **TLS terminated directly in Node.js**: the certificate is read from the TLS socket.
- **A TLS-terminating reverse proxy or load balancer** that forwards the certificate in an HTTP header: AWS ALB, Envoy/Istio, Cloudflare, Traefik, Azure App Service, nginx, HAProxy, and any proxy that implements RFC 9440 (e.g. Google Cloud Load Balancer).
- **AWS Lambda** behind API Gateway mTLS, via `client-certificate-auth/lambda`.
- **Web-standard `Request` runtimes** (Hono, Next.js, SvelteKit, Cloudflare Workers, Bun, Deno), via `client-certificate-auth/fetch`.

Express and Connect get drop-in middleware. Other frameworks use the same extraction logic through `extractClientCertificate()`. Pre-built authorization helpers cover the common policies (allowlist by CN, fingerprint, issuer, OU, SAN, and more).

## Installation

```bash
npm install client-certificate-auth
```

**Requirements:** Node.js >= 20

## Usage

### Basic Setup

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

### Per-Route Protection

```javascript
app.get('/public', (req, res) => {
  res.send('Hello world');
});

app.get('/admin', clientCertificateAuth(checkAuth), (req, res) => {
  res.send('Hello admin');
});
```

### Async Authorization

```javascript
const checkAuth = async (cert) => {
  const user = await db.findByFingerprint(cert.fingerprint);
  return user !== null;
};

app.use(clientCertificateAuth(checkAuth));
```

### Custom Error Messages

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

### Audit Logging Hooks

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

## API

### `clientCertificateAuth(callback, options?)`

Returns Express middleware.

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

### `extractClientCertificate(req, options?)`

Framework-agnostic certificate extraction function exported from `client-certificate-auth/extractor`. Use this when building adapters for non-Express frameworks or when you need certificate extraction without middleware.

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `req` | `Object` | Request object with `headers` and optional `socket` |
| `req.headers` | `Record<string, string \| string[]>` | HTTP headers object |
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

- `'verification_header_mismatch'` - Proxy verify header didn't match expected value
- `'header_missing_or_malformed'` - Header extraction failed and no fallback configured
- `'socket_not_authorized'` - Socket not authorized for TLS client cert
- `'certificate_not_retrievable'` - Socket authorized but getPeerCertificate() returned empty

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

### Ecosystem

This package provides everything you need to build mTLS authentication for any Node.js framework:

- **Certificate extraction** via `extractClientCertificate()` - handles both socket and header-based extraction
- **Authorization helpers** - reusable validation callbacks for common patterns (`allowCN`, `allowFingerprints`, etc.)
- **Parser library** - decode certificates from various reverse proxy formats (Envoy XFCC, AWS ALB, Cloudflare, etc.)
- **Type definitions** - full TypeScript support

**Official framework adapters:**

- **[passport-client-certificate-auth](https://www.npmjs.com/package/passport-client-certificate-auth)** - Passport.js strategy for mTLS authentication

**Community adapters:**

If you build an adapter for another framework (Koa, Fastify, Hapi, NestJS, etc.), please open an issue or PR to get it listed here!

> For complete API documentation with all types, parameters, and examples, see the [API Reference](https://tgies.github.io/client-certificate-auth/api/).

### Accessing the Certificate

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

### Certificate Chain Access

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

When `includeChain: true`, the certificate object includes `issuerCertificate` linking to the issuer's certificate (and so on up the chain). This works consistently for both socket-based and header-based extraction, except on Node.js 26.8.0 and later, where a Node.js regression ([nodejs/node#65579](https://github.com/nodejs/node/issues/65579)) leaves `issuerCertificate` unset on the socket path; header-based extraction is unaffected. See [Troubleshooting](docs/guide/troubleshooting.md#certificate-chain-missing-on-nodejs-2680-and-later).

For header-based extraction the first certificate in the header is the leaf. If it is empty or unparseable the header is rejected with `header_missing_or_malformed` rather than promoting the next certificate into the leaf position. See [Reverse Proxy Setup](https://tgies.github.io/client-certificate-auth/guide/reverse-proxy#chains-in-a-single-header) for the per-encoding details.

### User Login

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

## Reverse Proxy / Load Balancer Support

When your application runs behind a TLS-terminating reverse proxy, the client certificate is available via HTTP headers instead of the TLS socket. This middleware supports reading certificates from headers for common proxies.

### Using Presets

For common proxies, use the `certificateSource` option:

```javascript
// AWS Application Load Balancer (mTLS passthrough)
app.use(clientCertificateAuth(checkAuth, {
  certificateSource: 'aws-alb'
}));

// AWS Application Load Balancer (mTLS verify mode)
app.use(clientCertificateAuth(checkAuth, {
  certificateSource: 'aws-alb-verify'
}));

// Azure App Service
app.use(clientCertificateAuth(checkAuth, {
  certificateSource: 'azure-app-service'
}));

// Envoy / Istio
app.use(clientCertificateAuth(checkAuth, {
  certificateSource: 'envoy'
}));

// Cloudflare (legacy Cf-Client-Cert-Der-Base64 header)
app.use(clientCertificateAuth(checkAuth, {
  certificateSource: 'cloudflare'
}));

// Cloudflare (RFC 9440 Client-Cert / Client-Cert-Chain headers, March 2026+)
app.use(clientCertificateAuth(checkAuth, {
  certificateSource: 'cloudflare-rfc9440'
}));

// Traefik
app.use(clientCertificateAuth(checkAuth, {
  certificateSource: 'traefik'
}));
```

### Preset Details

| Preset | Header(s) | Encoding |
|--------|-----------|----------|
| `aws-alb` | `X-Amzn-Mtls-Clientcert` | URL-encoded PEM (AWS variant) |
| `aws-alb-verify` | `X-Amzn-Mtls-Clientcert-Leaf` | URL-encoded PEM (AWS variant) |
| `azure-app-service` | `X-ARR-ClientCert` | Base64-encoded DER |
| `cloudflare` | `Cf-Client-Cert-Der-Base64` | Base64-encoded DER |
| `cloudflare-rfc9440` | `Client-Cert` + `Client-Cert-Chain` | RFC 9440 |
| `envoy` | `X-Forwarded-Client-Cert` | XFCC structured format |
| `traefik` | `X-Forwarded-Tls-Client-Cert` | Base64-encoded DER \* |

> ⚠️ **Passthrough presets do not validate the certificate.** ALB mTLS passthrough mode (`aws-alb`) and Azure App Service (`azure-app-service`) forward whatever certificate the client presented during the handshake, without checking it against a trust store. The middleware parses the certificate, but your callback is responsible for trust verification: matching the issuer against an expected CA, checking the validity window, and checking revocation if applicable. A callback that only checks `cert.subject.CN` (including the `allowCN` helper) will accept any well-formed certificate a client presents. To rely on proxy-side validation instead, use ALB verify mode (`aws-alb-verify`), which validates against a configured trust store, or pin the certificate with `allowFingerprints`.

> \* **Traefik note:** The `traefik` preset targets Traefik v3's `PassTLSClientCert` middleware with `pem: true`. Despite Traefik's docs describing this as "PEM format", the wire format is the base64 body without PEM headers, equivalent to base64-encoded DER. This applies to Traefik v2.9.4 and later and all of v3; Traefik 2.8 through 2.9.1 URL-escaped the value, which this preset does not decode. `PassTLSClientCert` never removes a client-supplied `X-Forwarded-Tls-Client-Cert`; unless the TLS options selected by the router set `clientAuth.clientAuthType: RequireAndVerifyClientCert`, clear the header with a `headers` middleware ahead of it.

> **Cloudflare note:** Cloudflare also provides certificates via the `CF-Client-Cert-PEM` header (URL-encoded PEM). If you use that header instead, configure manually with `certificateHeader: 'CF-Client-Cert-PEM'` and `headerEncoding: 'url-pem'`. For the RFC 9440 forwarding feature (March 2026 and later), use the `cloudflare-rfc9440` preset, which pairs the `Client-Cert` header with `Client-Cert-Chain` via the `chainHeader` option.

### Custom Headers

For nginx, HAProxy, Google Cloud Load Balancer, or other proxies with configurable headers:

```javascript
// nginx with $ssl_client_escaped_cert
app.use(clientCertificateAuth(checkAuth, {
  certificateHeader: 'X-SSL-Whatever-You-Use',
  headerEncoding: 'url-pem'
}));

// Google Cloud Load Balancer (custom header populated from {client_cert_leaf}, RFC 9440)
app.use(clientCertificateAuth(checkAuth, {
  certificateHeader: 'X-Client-Cert-Leaf',
  headerEncoding: 'rfc9440'
}));

// HAProxy with base64 DER
app.use(clientCertificateAuth(checkAuth, {
  certificateHeader: 'X-SSL-Whatever-You-Use',
  headerEncoding: 'base64-der'
}));
```

### Encoding Formats

| Encoding | Description | Used By |
|----------|-------------|---------|
| `url-pem` | URL-encoded PEM certificate | nginx (`$ssl_client_escaped_cert`) |
| `url-pem-aws` | URL-encoded PEM (AWS variant, `+` as safe char) | AWS ALB |
| `xfcc` | Envoy's structured `Key=Value;...` format | Envoy, Istio |
| `base64-der` | Base64-encoded DER certificate | Cloudflare, Traefik, Azure App Service, HAProxy (`ssl_c_der,base64`) |
| `rfc9440` | RFC 9440 format: `:base64-der:` | Cloudflare (RFC 9440 forwarding), Google Cloud LB |

HAProxy's native certificate forwarding (`http-request set-header ... %[ssl_c_der,base64]`) is base64 DER, so pair it with `base64-der`. HAProxy has no built-in URL-encoded-PEM output; `url-pem` from HAProxy requires a custom Lua `url_enc` converter.

### Fallback Mode

If your proxy might not always forward certificates (e.g., direct connections bypass the proxy), enable fallback:

```javascript
app.use(clientCertificateAuth(checkAuth, {
  certificateSource: 'aws-alb',
  fallbackToSocket: true  // Try socket if header missing
}));
```

### Security Considerations

> ⚠️ **Important:** When using header-based authentication, your reverse proxy **must** strip any incoming certificate headers from external requests to prevent spoofing.

Configure your proxy to:
1. **Strip** the certificate header from incoming requests
2. **Set** the header only for authenticated mTLS connections
3. **Never** trust certificate headers from untrusted sources

#### Verification Header (Defense in Depth)

For additional protection, use `verifyHeader` and `verifyValue` to validate that your proxy has actually verified the certificate. This guards against proxy misconfiguration (e.g., `ssl_verify_client optional` passing unverified certs):

```javascript
app.use(clientCertificateAuth(checkAuth, {
  certificateHeader: 'X-SSL-Client-Cert',
  headerEncoding: 'url-pem',
  verifyHeader: 'X-SSL-Client-Verify',
  verifyValue: 'SUCCESS'
}));
```

Example nginx configuration:
```nginx
# Strip any existing headers from clients
proxy_set_header X-SSL-Client-Cert "";
proxy_set_header X-SSL-Client-Verify "";

# Always send verification status
proxy_set_header X-SSL-Client-Verify $ssl_client_verify;

# Only send cert if verified
if ($ssl_client_verify = SUCCESS) {
    proxy_set_header X-SSL-Client-Cert $ssl_client_escaped_cert;
}
```

## WebSocket Support

WebSocket connections work seamlessly with mTLS because the TLS handshake occurs before the HTTP upgrade request. The middleware authenticates the upgrade request just like any other HTTP request.

### With the `ws` Library

```javascript
import https from 'node:https';
import { WebSocketServer } from 'ws';
import clientCertificateAuth from 'client-certificate-auth';

const server = https.createServer({
  key: fs.readFileSync('server.key'),
  cert: fs.readFileSync('server.pem'),
  ca: fs.readFileSync('ca.pem'),
  requestCert: true,
  rejectUnauthorized: false,
});

const wss = new WebSocketServer({ noServer: true });

wss.on('connection', (ws, req) => {
  // Certificate is available on req.clientCertificate
  console.log(`Client connected: ${req.clientCertificate.subject.CN}`);

  ws.on('message', (data) => {
    ws.send(`Echo: ${data}`);
  });
});

// Authenticate upgrade requests
server.on('upgrade', (req, socket, head) => {
  const middleware = clientCertificateAuth((cert) => {
    return cert.subject.CN === 'trusted-client';
  });

  // Minimal response object for middleware compatibility
  const res = { writeHead: () => {}, end: () => {}, redirect: () => {} };

  middleware(req, res, (err) => {
    if (err) {
      socket.write(`HTTP/1.1 ${err.status} ${err.message}\r\n\r\n`);
      socket.destroy();
      return;
    }

    wss.handleUpgrade(req, socket, head, (ws) => {
      wss.emit('connection', ws, req);
    });
  });
});

server.listen(443);
```

### With Socket.IO

```javascript
import https from 'node:https';
import { Server } from 'socket.io';
import clientCertificateAuth from 'client-certificate-auth';

const server = https.createServer({
  key: fs.readFileSync('server.key'),
  cert: fs.readFileSync('server.pem'),
  ca: fs.readFileSync('ca.pem'),
  requestCert: true,
  rejectUnauthorized: false,
});

const io = new Server(server);

// Socket.IO middleware for mTLS authentication
io.use((socket, next) => {
  const req = socket.request;
  const res = { writeHead: () => {}, end: () => {}, redirect: () => {} };

  const middleware = clientCertificateAuth((cert) => {
    return cert.subject.CN === 'trusted-client';
  });

  middleware(req, res, (err) => {
    if (err) {
      return next(new Error('Authentication failed'));
    }
    // Attach certificate info to socket for later use
    socket.clientCert = req.clientCertificate;
    next();
  });
});

io.on('connection', (socket) => {
  console.log(`Client connected: ${socket.clientCert.subject.CN}`);
});

server.listen(443);
```

## Authorization Helpers

Pre-built validation callbacks for common authorization patterns, available as a separate import:

```javascript
import clientCertificateAuth from 'client-certificate-auth';
import { allowCN, allowFingerprints, allowIssuer, allOf, anyOf } from 'client-certificate-auth/helpers';
```

> **Note:** In CommonJS, the `/helpers`, `/parsers`, and `/extractor` subpath exports provide a `load()` function for async access. See the [CommonJS](#commonjs) section for details.

### Basic Helpers

```javascript
// Allowlist by Common Name
app.use(clientCertificateAuth(allowCN(['service-a', 'service-b'])));

// Allowlist by fingerprint
app.use(clientCertificateAuth(allowFingerprints([
  'SHA256:AB:CD:EF:...',  // matched against cert.fingerprint256
  'AB:CD:EF:...'          // SHA-1, matched against cert.fingerprint
])));

// Allowlist by Organization
app.use(clientCertificateAuth(allowOrganization(['My Company'])));

// Allowlist by Organizational Unit
app.use(clientCertificateAuth(allowOU(['Engineering', 'DevOps'])));

// Allowlist by email (checks SAN and subject.emailAddress)
app.use(clientCertificateAuth(allowEmail(['admin@example.com'])));

// Allowlist by serial number
app.use(clientCertificateAuth(allowSerial(['01:23:45:67:89:AB:CD:EF'])));

// Allowlist by Subject Alternative Name
app.use(clientCertificateAuth(allowSAN(['DNS:api.example.com', 'email:service@example.com'])));
```

### Field Matching

Match certificates by issuer or subject fields (all specified fields must match):

```javascript
// Match by issuer
app.use(clientCertificateAuth(allowIssuer({ O: 'My Company', CN: 'Internal CA' })));

// Match by subject
app.use(clientCertificateAuth(allowSubject({ O: 'Partner Corp', ST: 'California' })));
```

### Combining Helpers

```javascript
// AND - all conditions must pass
app.use(clientCertificateAuth(allOf(
  allowIssuer({ O: 'My Company' }),
  allowOU(['Engineering', 'DevOps'])
)));

// OR - at least one condition must pass
app.use(clientCertificateAuth(anyOf(
  allowCN(['admin']),
  allowOU(['Administrators'])
)));
```

### Available Helpers

| Helper | Description |
|--------|-------------|
| `allowCN(names)` | Match by Common Name |
| `allowFingerprints(fps)` | Match by certificate fingerprint |
| `allowIssuer(match)` | Match by issuer fields (partial) |
| `allowSubject(match)` | Match by subject fields (partial) |
| `allowOU(ous)` | Match by Organizational Unit |
| `allowOrganization(orgs)` | Match by Organization |
| `allowSerial(serials)` | Match by serial number |
| `allowSAN(values)` | Match by Subject Alternative Name |
| `allowEmail(emails)` | Match by email (SAN or subject) |
| `allOf(...callbacks)` | AND combinator |
| `anyOf(...callbacks)` | OR combinator |

## TypeScript

Types are included:

```typescript
import clientCertificateAuth from 'client-certificate-auth';
import type { ClientCertRequest } from 'client-certificate-auth';
import type { PeerCertificate } from 'tls';

const checkAuth = (cert: PeerCertificate): boolean => {
  return cert.subject.CN === 'admin';
};

app.use(clientCertificateAuth(checkAuth));

// Access certificate in downstream handlers
app.get('/whoami', (req: ClientCertRequest, res) => {
  res.json({ cn: req.clientCertificate?.subject.CN });
});

// With reverse proxy
app.use(clientCertificateAuth(checkAuth, {
  certificateSource: 'aws-alb'
}));
```

## CommonJS

The main entry point works with `require()` out of the box for socket-based mTLS:

```javascript
const clientCertificateAuth = require('client-certificate-auth');

app.use(clientCertificateAuth((cert) => cert.subject.CN === 'admin'));
```

The sync CJS wrapper supports `includeChain`, `onAuthenticated`, and `onRejected` options:

```javascript
const clientCertificateAuth = require('client-certificate-auth');

app.use(clientCertificateAuth(
  (cert) => cert.subject.CN === 'admin',
  {
    includeChain: true,
    onAuthenticated: (cert, req) => {
      console.log(`Authenticated: ${cert.subject.CN}`);
    }
  }
));
```

### Full Features via `load()`

Reverse proxy support (header-based certificate extraction) requires async initialization. Use the `load()` function to get the full-featured ESM module:

```javascript
const { load } = require('client-certificate-auth');

async function setup() {
  const clientCertificateAuth = await load();

  app.use(clientCertificateAuth(checkAuth, {
    certificateSource: 'aws-alb'  // Now supported
  }));
}

setup();
```

The `load()` function dynamically imports the ESM module and caches it. Subsequent calls return the cached module immediately.

### CJS Limitations

| Feature | `require()` (sync) | `load()` (async) |
|---------|---------------------|-------------------|
| Socket-based mTLS | Yes | Yes |
| `includeChain` | Yes | Yes |
| `onAuthenticated` / `onRejected` | Yes | Yes |
| `certificateSource` presets | No | Yes |
| `certificateHeader` / `headerEncoding` | No | Yes |
| `verifyHeader` / `verifyValue` | No | Yes |
| `fallbackToSocket` | No | Yes |

### Subpath Exports in CJS

The `/helpers`, `/parsers`, and `/extractor` subpath exports each provide a `load()` function for async access in CommonJS. The individual functions are not synchronously available via `require()`.

```javascript
// Helpers
const { load } = require('client-certificate-auth/helpers');
const { allowCN, allOf, allowIssuer } = await load();

// Extractor
const { load: loadExtractor } = require('client-certificate-auth/extractor');
const { extractClientCertificate } = await loadExtractor();
```

Alternatively, you can use dynamic `import()`:

```javascript
const { allowCN } = await import('client-certificate-auth/helpers');
```

## Testing

This library has comprehensive test coverage across multiple layers:

| Layer | Description |
|-------|-------------|
| **Unit tests** | 100% line/branch/function/statement coverage, enforced in CI |
| **Integration tests** | Real HTTPS servers with mTLS handshakes |
| **E2E proxy tests** | Docker containers running nginx, Envoy, and Traefik with actual certificate forwarding |
| **Mutation testing** | [Stryker](https://dashboard.stryker-mutator.io/reports/github.com/tgies/client-certificate-auth/master) verifies tests detect code changes |

The E2E tests spin up real reverse proxies, generate fresh certificates, and verify the middleware correctly parses each proxy's header format through a variety of successful and failed authentication attempts.

## Security Notes

- Set `rejectUnauthorized: false` on your HTTPS server to let this middleware provide helpful error messages, rather than dropping connections silently
- **When using header-based auth**, ensure your proxy strips certificate headers from external requests
- Use `verifyHeader`/`verifyValue` as defense-in-depth when using header-based authentication

## Upgrading from 1.x

v2.0.0 introduced two behavior changes:

- **Validation callbacks must return exactly `true`.** Previously any truthy value (`'admin'`, `1`, an object) authorized; now only `true` (or a `Promise`/thenable resolving to `true`) does. Callbacks that returned ad-hoc truthy values (e.g., `return cert.subject.CN`) must be rewritten to explicit `return true` / `return false`.
- **Header options are validated at construction.** Typos like `certificateSource: 'aws-alp'` now throw at app startup instead of failing at request time.

See the [CHANGELOG](./CHANGELOG.md) for the full v2.0.0 entry.

## Troubleshooting

### `DEPTH_ZERO_SELF_SIGNED_CERT` error

This error occurs when the TLS layer rejects a self-signed client certificate. Set `rejectUnauthorized: false` in your HTTPS server options to let the middleware handle authorization instead of dropping the connection:

```javascript
const opts = {
  key: fs.readFileSync('server.key'),
  cert: fs.readFileSync('server.pem'),
  ca: fs.readFileSync('ca.pem'),
  requestCert: true,
  rejectUnauthorized: false  // Required for self-signed certs
};

https.createServer(opts, app).listen(443);
```

> **Warning:** In production, prefer certificates signed by your own CA rather than self-signed certificates. If you must use self-signed certs, ensure you set `ca` to the self-signed certificate so Node.js can verify the chain.

### Certificate not reaching middleware

If the middleware always rejects with "socket not authorized", verify that your HTTPS server has `requestCert: true` set. Without this option, Node.js will not ask clients for a certificate during the TLS handshake:

```javascript
const opts = {
  // ...
  requestCert: true,           // Must be true
  rejectUnauthorized: false
};
```

Also confirm that the client is actually sending a certificate. Tools like `openssl s_client` can verify this:

```bash
openssl s_client -connect localhost:443 -cert client.pem -key client.key
```

### Reverse proxy headers not working

When using header-based certificate extraction behind a reverse proxy:

1. **Verify the proxy is setting the correct header.** Check your proxy logs or use a test endpoint to inspect incoming headers.

2. **Ensure the `certificateSource` or `certificateHeader`/`headerEncoding` options match your proxy's configuration.** A mismatch will result in unparseable or missing certificate data.

3. **Confirm the proxy strips certificate headers from external requests.** If external clients can set these headers directly, they can bypass authentication. See [Security Considerations](#security-considerations).

4. **Consider using `verifyHeader`/`verifyValue`** for defense-in-depth, so the middleware validates that the proxy actually verified the certificate.

### WebSocket authentication failing

For WebSocket connections using the `ws` library with `noServer: true`, you must handle the `upgrade` event yourself and run the middleware manually. The middleware needs a response-like object and a `next` callback:

```javascript
server.on('upgrade', (req, socket, head) => {
  const middleware = clientCertificateAuth(checkAuth);
  const res = { writeHead: () => {}, end: () => {}, redirect: () => {} };

  middleware(req, res, (err) => {
    if (err) {
      socket.write(`HTTP/1.1 ${err.status} ${err.message}\r\n\r\n`);
      socket.destroy();
      return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => {
      wss.emit('connection', ws, req);
    });
  });
});
```

See the full [WebSocket Support](#websocket-support) section for complete examples with `ws` and Socket.IO.

### ESM vs CJS import differences

This package is an ES module (`"type": "module"` in package.json) with a CJS compatibility wrapper.

**ESM** (recommended):
```javascript
import clientCertificateAuth from 'client-certificate-auth';
import { allowCN } from 'client-certificate-auth/helpers';
```

**CJS** (sync, socket-only):
```javascript
const clientCertificateAuth = require('client-certificate-auth');
```

**CJS** (async, full features):
```javascript
const clientCertificateAuth = await require('client-certificate-auth').load();
```

The sync CJS wrapper does not support reverse proxy options (`certificateSource`, `certificateHeader`, etc.). Passing these options will throw a descriptive error. Use `load()` to access the full ESM module from CJS code. See the [CommonJS](#commonjs) section for details.

The `/helpers`, `/parsers`, and `/extractor` subpath exports each provide a `load()` function in CJS. See [Subpath Exports in CJS](#subpath-exports-in-cjs) for details.

## Commercial Support

`client-certificate-auth` is built and maintained by [Tony Gies](https://github.com/tgies). For organizations running it in production, commercial support is available through his consultancy, Crash United, LLC.

### Support Offerings

| Service | Description |
|---------|-------------|
| **Priority bug fixes** | Reported issues triaged and patched ahead of the public queue |
| **Custom features & integrations** | Adapters for new reverse proxies, encoding formats, or framework wrappers |
| **mTLS architecture consulting** | Review of your certificate issuance, rotation, and trust-chain design |
| **Deployment security review** | Threat modeling for your specific proxy + middleware + auth flow |
| **Private security advisories** | Coordinated disclosure for vulnerabilities affecting your deployment |

For pricing, scoping, or anything not listed above, email **[support@crashunited.com](mailto:support@crashunited.com)** to discuss your needs.

### Sponsorship

To support ongoing development without a formal contract, [GitHub Sponsors](https://github.com/sponsors/tgies) is the simplest path.

### Enterprise Procurement

This package is enrolled in [Tidelift](https://tidelift.com/) (now part of SonarQube Advanced Security). If your organization already subscribes, `client-certificate-auth` is included in your coverage for security disclosures, license compliance, and version metadata.

## License

MIT © Tony Gies
