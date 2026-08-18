# Authorization Helpers

Pre-built validation callbacks cover common authorization patterns so you don't have to write them from scratch. Import them from the `/helpers` subpath:

```javascript
import clientCertificateAuth from 'client-certificate-auth';
import { allowCN, allowFingerprints, allowIssuer, allOf, anyOf } from 'client-certificate-auth/helpers';
```

::: info CommonJS note
In CommonJS, the `/helpers` subpath export provides a `load()` function for async access. See the [CommonJS section](./typescript#subpath-exports-in-cjs) for details.
:::

## Basic Helpers

Each helper returns a callback suitable for passing directly to `clientCertificateAuth()`:

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

## Field Matching

Match certificates by issuer or subject fields. All specified fields must match for the callback to return `true`:

```javascript
// Match by issuer
app.use(clientCertificateAuth(allowIssuer({ O: 'My Company', CN: 'Internal CA' })));

// Match by subject
app.use(clientCertificateAuth(allowSubject({ O: 'Partner Corp', ST: 'California' })));
```

## Combining Helpers

Use `allOf` and `anyOf` to compose multiple helpers into a single authorization check:

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

These combinators accept any number of callbacks, including custom functions, so you can mix helpers with your own logic:

```javascript
app.use(clientCertificateAuth(allOf(
  allowIssuer({ O: 'My Company' }),
  (cert) => !isRevoked(cert.serialNumber)
)));
```

## Available Helpers

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
| `allOf(...callbacks)` | AND combinator - all must pass |
| `anyOf(...callbacks)` | OR combinator - at least one must pass |

For full parameter types and return values, see the [helpers API reference](/api/helpers/).
