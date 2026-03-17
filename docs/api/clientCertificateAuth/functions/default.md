[**client-certificate-auth API Reference**](../../index.md)

***

[client-certificate-auth API Reference](../../index.md) / [clientCertificateAuth](../index.md) / default

# Function: default()

> **default**(`callback`, `options?`): [`Middleware`](../type-aliases/Middleware.md)

Defined in: [clientCertificateAuth.d.ts:159](https://github.com/tgies/client-certificate-auth/blob/1592b323472fe6163dd3cb046c134c3830f5ff4e/lib/clientCertificateAuth.d.ts#L159)

Express/Connect middleware for client SSL certificate authentication.

## Parameters

### callback

[`ValidationCallback`](../type-aliases/ValidationCallback.md)

Validation function that receives the client certificate
  and returns true/false (sync) or `Promise<boolean>` (async).

### options?

[`ClientCertificateAuthOptions`](../interfaces/ClientCertificateAuthOptions.md)

Configuration options

## Returns

[`Middleware`](../type-aliases/Middleware.md)

Express middleware function

## Examples

```ts
// Socket-based validation (original behavior)
app.use(clientCertificateAuth((cert) => cert.subject.CN === 'admin'));
```

```ts
// AWS ALB mTLS passthrough
app.use(clientCertificateAuth((cert) => cert.subject.CN === 'admin', {
  certificateSource: 'aws-alb'
}));
```

```ts
// Custom header with nginx/HAProxy
app.use(clientCertificateAuth((cert) => cert.subject.CN === 'admin', {
  certificateHeader: 'X-SSL-Client-Cert',
  headerEncoding: 'url-pem'
}));
```
