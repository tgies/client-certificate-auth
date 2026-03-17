# Reverse Proxy Support

When your application runs behind a TLS-terminating reverse proxy, the client certificate is available via HTTP headers instead of the TLS socket. This middleware supports reading certificates from headers for common proxies out of the box, and can be configured for any proxy with custom headers.

## Using Presets

For common proxies, use the `certificateSource` option to automatically configure the correct header and encoding:

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

## Preset Details

Each preset maps to a specific header name and encoding format:

| Preset | Header | Encoding |
|--------|--------|----------|
| `aws-alb` | `X-Amzn-Mtls-Clientcert` | URL-encoded PEM (AWS variant) |
| `envoy` | `X-Forwarded-Client-Cert` | XFCC structured format |
| `cloudflare` | `Cf-Client-Cert-Der-Base64` | Base64-encoded DER |
| `traefik` | `X-Forwarded-Tls-Client-Cert` | Base64-encoded DER \* |

::: tip Traefik note
The `traefik` preset targets Traefik v3's `PassTLSClientCert` middleware with `pem: true`. Despite Traefik's docs describing this as "PEM format", the wire format is the base64 body without PEM headers — equivalent to base64-encoded DER. Behavior may differ in Traefik v2.
:::

::: tip Cloudflare note
Cloudflare also provides certificates via the `CF-Client-Cert-PEM` header (URL-encoded PEM). If you use that header instead, configure manually with `certificateHeader: 'CF-Client-Cert-PEM'` and `headerEncoding: 'url-pem'`.
:::

## Custom Headers

For nginx, HAProxy, Google Cloud Load Balancer, or other proxies with configurable headers, specify the header name and encoding explicitly:

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

## Encoding Formats

The library supports five encoding formats covering all major reverse proxies:

| Encoding | Description | Used By |
|----------|-------------|---------|
| `url-pem` | URL-encoded PEM certificate | nginx, HAProxy |
| `url-pem-aws` | URL-encoded PEM (AWS variant, `+` as safe char) | AWS ALB |
| `xfcc` | Envoy's structured `Key=Value;...` format | Envoy, Istio |
| `base64-der` | Base64-encoded DER certificate | Cloudflare, Traefik |
| `rfc9440` | RFC 9440 format: `:base64-der:` | Google Cloud LB |

## Fallback Mode

If your proxy might not always forward certificates (e.g., direct connections bypass the proxy), enable `fallbackToSocket` to try the TLS socket when header extraction fails:

```javascript
app.use(clientCertificateAuth(checkAuth, {
  certificateSource: 'aws-alb',
  fallbackToSocket: true  // Try socket if header missing
}));
```

This is useful during migration periods or in environments where some requests come through the proxy and others connect directly.

## Security Considerations

::: warning Important
When using header-based authentication, your reverse proxy **must** strip any incoming certificate headers from external requests to prevent spoofing.
:::

Configure your proxy to:
1. **Strip** the certificate header from incoming requests
2. **Set** the header only for authenticated mTLS connections
3. **Never** trust certificate headers from untrusted sources

Without these precautions, an attacker could forge certificate headers and bypass authentication entirely.

## Verification Header (Defense in Depth)

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

The verification header is checked before certificate parsing. If the header is absent or doesn't match the expected value, the request is rejected immediately — the certificate header is never read.
