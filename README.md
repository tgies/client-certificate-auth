# client-certificate-auth

Express/Connect middleware for client SSL certificate authentication (mTLS).

[![CI](https://github.com/tgies/client-certificate-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/tgies/client-certificate-auth/actions/workflows/ci.yml)
[![npm version](https://badge.fury.io/js/client-certificate-auth.svg)](https://www.npmjs.com/package/client-certificate-auth)

## Installation

```bash
npm install client-certificate-auth
```

**Requirements:** Node.js >= 18

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

## API

### `clientCertificateAuth(callback, options?)`

Returns Express middleware.

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `callback` | `(cert) => boolean \| Promise<boolean>` | Receives the client certificate, returns `true` to allow access |
| `options.redirectInsecure` | `boolean` | If `true`, redirect HTTP → HTTPS (default: `false`) |

**Certificate Object:**

The `cert` parameter contains fields from [`tls.PeerCertificate`](https://nodejs.org/api/tls.html#certificate-object):

- `subject.CN` - Common Name
- `subject.O` - Organization
- `issuer` - Issuer information
- `fingerprint` - Certificate fingerprint
- `valid_from`, `valid_to` - Validity period

## TypeScript

Types are included:

```typescript
import clientCertificateAuth from 'client-certificate-auth';
import type { PeerCertificate } from 'tls';

const checkAuth = (cert: PeerCertificate): boolean => {
  return cert.subject.CN === 'admin';
};

app.use(clientCertificateAuth(checkAuth));
```

## CommonJS

```javascript
const clientCertificateAuth = require('client-certificate-auth');

app.use(clientCertificateAuth((cert) => cert.subject.CN === 'admin'));
```

## Security Notes

- **Do not use `redirectInsecure: true` in production** — the initial HTTP request can be intercepted
- Set `rejectUnauthorized: false` on your HTTPS server to let this middleware provide helpful error messages, rather than dropping connections silently

## License

MIT © Tony Gies
