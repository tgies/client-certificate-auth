# TypeScript & CommonJS

## TypeScript

Types are included with the package. No separate `@types/` install is needed.

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

The `ClientCertRequest` type extends Node's `http.IncomingMessage` and is structurally compatible with Express's `Request` and other Connect-style request types. It adds the optional `clientCertificate` property the middleware attaches after authentication. Use it in downstream route handlers to get type-safe access to the attached certificate. The package does not depend on `@types/express`, so consumers using bare Node or non-Express Connect-style frameworks can use these types without pulling in Express's types.

For complete type definitions, see the [API reference](/api/clientCertificateAuth/).

## CommonJS

This package is an ES module (`"type": "module"` in package.json) with a CJS compatibility wrapper. The level of CJS support depends on whether you use the sync `require()` entry or the async `load()` function.

### Socket-Based (Sync)

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

The sync CJS wrapper does not support reverse proxy options. Passing these options will throw a descriptive error telling you to use `load()` instead.

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

## ESM vs CJS Quick Reference

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

ESM is the recommended module format. It provides access to all features without any async initialization step. If you must use CommonJS, the sync wrapper covers the most common use case (socket-based mTLS), and `load()` unlocks everything else.
