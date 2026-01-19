# client-certificate-auth

Express/Connect middleware for client SSL certificate authentication (mTLS).

[![CI](https://github.com/tgies/client-certificate-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/tgies/client-certificate-auth/actions/workflows/ci.yml)
[![npm version](https://badge.fury.io/js/client-certificate-auth.svg)](https://www.npmjs.com/package/client-certificate-auth)
[![codecov](https://codecov.io/gh/tgies/client-certificate-auth/graph/badge.svg)](https://codecov.io/gh/tgies/client-certificate-auth)

## Installation

```bash
npm install client-certificate-auth
```

**Requirements:** Node.js >= 20

## Synopsis

This middleware requires clients to present a valid, verifiable SSL certificate (mutual TLS / mTLS). The certificate is validated at the TLS layer, then passed to your callback for additional authorization logic.

Compatible with Express, Connect, and any Node.js HTTP server framework that uses standard `req.socket` and `req.headers`.

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

## API

### `clientCertificateAuth(callback, options?)`

Returns Express middleware.

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `callback` | `(cert) => boolean \| Promise<boolean>` | Receives the client certificate, returns `true` to allow access |
| `options.certificateSource` | `string` | Use a preset for a known proxy: `'aws-alb'`, `'envoy'`, `'cloudflare'`, `'traefik'` |
| `options.certificateHeader` | `string` | Custom header name to read certificate from |
| `options.headerEncoding` | `string` | Encoding format: `'url-pem'`, `'url-pem-aws'`, `'xfcc'`, `'base64-der'`, `'rfc9440'` |
| `options.fallbackToSocket` | `boolean` | If header extraction fails, try `socket.getPeerCertificate()` (default: `false`) |
| `options.includeChain` | `boolean` | If `true`, include full certificate chain via `cert.issuerCertificate` (default: `false`) |
| `options.verifyHeader` | `string` | Header name containing verification status from proxy (e.g., `'X-SSL-Client-Verify'`) |
| `options.verifyValue` | `string` | Expected value indicating successful verification (e.g., `'SUCCESS'`) |

**Certificate Object:**

The `cert` parameter contains fields from [`tls.PeerCertificate`](https://nodejs.org/api/tls.html#certificate-object):

- `subject.CN` - Common Name
- `subject.O` - Organization
- `issuer` - Issuer information
- `fingerprint` - Certificate fingerprint
- `valid_from`, `valid_to` - Validity period
- `issuerCertificate` - Issuer's certificate (only when `includeChain: true`)

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

When `includeChain: true`, the certificate object includes `issuerCertificate` linking to the issuer's certificate (and so on up the chain). This works consistently for both socket-based and header-based extraction.

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
// AWS Application Load Balancer
app.use(clientCertificateAuth(checkAuth, {
  certificateSource: 'aws-alb'
}));

// Envoy / Istio
app.use(clientCertificateAuth(checkAuth, {
  certificateSource: 'envoy'
}));

// Cloudflare
app.use(clientCertificateAuth(checkAuth, {
  certificateSource: 'cloudflare'
}));

// Traefik
app.use(clientCertificateAuth(checkAuth, {
  certificateSource: 'traefik'
}));
```

### Preset Details

| Preset | Header | Encoding |
|--------|--------|----------|
| `aws-alb` | `X-Amzn-Mtls-Clientcert` | URL-encoded PEM (AWS variant) |
| `envoy` | `X-Forwarded-Client-Cert` | XFCC structured format |
| `cloudflare` | `Cf-Client-Cert-Der-Base64` | Base64-encoded DER |
| `traefik` | `X-Forwarded-Tls-Client-Cert` | Base64-encoded DER |

### Custom Headers

For nginx, HAProxy, Google Cloud Load Balancer, or other proxies with configurable headers:

```javascript
// nginx with $ssl_client_escaped_cert
app.use(clientCertificateAuth(checkAuth, {
  certificateHeader: 'X-SSL-Whatever-You-Use',
  headerEncoding: 'url-pem'
}));

// Google Cloud Load Balancer (RFC 9440)
app.use(clientCertificateAuth(checkAuth, {
  certificateHeader: 'X-SSL-Whatever-You-Use',
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
| `url-pem` | URL-encoded PEM certificate | nginx, HAProxy |
| `url-pem-aws` | URL-encoded PEM (AWS variant, `+` as safe char) | AWS ALB |
| `xfcc` | Envoy's structured `Key=Value;...` format | Envoy, Istio |
| `base64-der` | Base64-encoded DER certificate | Cloudflare, Traefik |
| `rfc9440` | RFC 9440 format: `:base64-der:` | Google Cloud LB |

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

## Authorization Helpers

Pre-built validation callbacks for common authorization patterns, available as a separate import:

```javascript
import clientCertificateAuth from 'client-certificate-auth';
import { allowCN, allowFingerprints, allowIssuer, allOf, anyOf } from 'client-certificate-auth/helpers';
```

### Basic Helpers

```javascript
// Allowlist by Common Name
app.use(clientCertificateAuth(allowCN(['service-a', 'service-b'])));

// Allowlist by fingerprint
app.use(clientCertificateAuth(allowFingerprints([
  'SHA256:AB:CD:EF:...',
  'AB:CD:EF:...'  // SHA256: prefix optional
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

```javascript
const clientCertificateAuth = require('client-certificate-auth');

app.use(clientCertificateAuth((cert) => cert.subject.CN === 'admin'));
```

## Security Notes

- Set `rejectUnauthorized: false` on your HTTPS server to let this middleware provide helpful error messages, rather than dropping connections silently
- **When using header-based auth**, ensure your proxy strips certificate headers from external requests
- Use `verifyHeader`/`verifyValue` as defense-in-depth when using header-based authentication

## License

MIT © Tony Gies