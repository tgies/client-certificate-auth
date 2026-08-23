# Reverse Proxy Support

When your application runs behind a TLS-terminating reverse proxy, the client certificate is available via HTTP headers instead of the TLS socket. This middleware supports reading certificates from headers for common proxies out of the box, and can be configured for any proxy with custom headers.

## Using Presets

For common proxies, use the `certificateSource` option to automatically configure the correct header and encoding:

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

## Preset Details

Each preset maps to a specific header name and encoding format:

| Preset | Header(s) | Encoding |
|--------|-----------|----------|
| `aws-alb` | `X-Amzn-Mtls-Clientcert` | URL-encoded PEM (AWS variant) |
| `aws-alb-verify` | `X-Amzn-Mtls-Clientcert-Leaf` | URL-encoded PEM (AWS variant) |
| `azure-app-service` | `X-ARR-ClientCert` | Base64-encoded DER |
| `cloudflare` | `Cf-Client-Cert-Der-Base64` | Base64-encoded DER |
| `cloudflare-rfc9440` | `Client-Cert` + `Client-Cert-Chain` | RFC 9440 |
| `envoy` | `X-Forwarded-Client-Cert` | XFCC structured format |
| `traefik` | `X-Forwarded-Tls-Client-Cert` | Base64-encoded DER \* |

::: tip Traefik note
The `traefik` preset targets Traefik v3's `PassTLSClientCert` middleware with `pem: true`. Despite Traefik's docs describing this as "PEM format", the wire format is the base64 body without PEM headers, equivalent to base64-encoded DER. This applies to Traefik v2.9.4 and later and all of v3; Traefik 2.8 through 2.9.1 URL-escaped the value, which this preset does not decode.
:::

::: tip Cloudflare note
Cloudflare also provides certificates via the `CF-Client-Cert-PEM` header (URL-encoded PEM). If you use that header instead, configure manually with `certificateHeader: 'CF-Client-Cert-PEM'` and `headerEncoding: 'url-pem'`.

For the newer RFC 9440 forwarding feature (March 2026+), use the `cloudflare-rfc9440` preset, which pairs the standard `Client-Cert` header with the `Client-Cert-Chain` header via the new `chainHeader` option (see "Chain Header" below).
:::

::: tip Azure note
The `azure-app-service` preset targets Azure App Service, which sends the bare base64-encoded DER (the body of a PEM cert with the BEGIN/END delimiters stripped) in `X-ARR-ClientCert`.

Azure Application Gateway uses the same header name via a rewrite rule on the `{var_client_certificate}` server variable, but emits PEM (with BEGIN/END delimiters), not base64 DER. Azure API Management exposes client certificates through a policy/context model rather than a header. Both are deployment-specific; configure manually with the appropriate `certificateHeader` + `headerEncoding` combination, or open an issue if you want a dedicated preset.
:::

::: warning Azure App Service does not validate the client certificate
App Service forwards whatever certificate the client presents during the TLS handshake. It does not check the certificate against a configured trust store. The middleware can parse the certificate out of the header, but your validation callback is responsible for full trust verification: matching the issuer against an expected CA, checking the validity window, checking revocation if applicable, and any application-level subject checks. A callback that only checks `cert.subject.CN` will accept any well-formed certificate any client cares to present.

If you need ALB-style "the proxy already validated the cert" semantics on Azure, configure validation at the Application Gateway or API Management layer ahead of App Service, or run client cert validation in your application code against a trust store you control.
:::

::: warning ALB passthrough mode does not validate the client certificate
The `aws-alb` preset targets ALB mTLS **passthrough** mode, where ALB forwards the certificate chain the client presented without checking it against a trust store. As with Azure App Service above, your validation callback owns trust verification, and a callback that only checks `cert.subject.CN` (including the `allowCN` helper) will accept any well-formed certificate a client presents.

The `aws-alb-verify` preset targets ALB mTLS **verify** mode, where ALB validates the client certificate against a configured trust store before forwarding the leaf. In verify mode the proxy has already established trust, so subject checks in your callback are an authorization layer on top of a validated certificate rather than the only line of defense. When you cannot use verify mode, pin the certificate with `allowFingerprints` instead of matching on subject fields.
:::

## Custom Headers

For nginx, HAProxy, Google Cloud Load Balancer, or other proxies with configurable headers, specify the header name and encoding explicitly:

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

// Caddy with the certificate_der_base64 placeholder
app.use(clientCertificateAuth(checkAuth, {
  certificateHeader: 'X-Client-Cert',
  headerEncoding: 'base64-der'
}));
```

## Encoding Formats

The library supports five encoding formats covering all major reverse proxies:

| Encoding | Description | Used By |
|----------|-------------|---------|
| `url-pem` | URL-encoded PEM certificate | nginx (`$ssl_client_escaped_cert`) |
| `url-pem-aws` | URL-encoded PEM (AWS variant, `+` as safe char) | AWS ALB |
| `xfcc` | Envoy's structured `Key=Value;...` format | Envoy, Istio |
| `base64-der` | Base64-encoded DER certificate | Cloudflare, Traefik, Azure App Service, Caddy, HAProxy (`ssl_c_der,base64`) |
| `rfc9440` | RFC 9440 format: `:base64-der:` | Cloudflare (RFC 9440 forwarding), Google Cloud LB |

HAProxy's native certificate forwarding (`http-request set-header ... %[ssl_c_der,base64]`) is base64 DER, so pair it with `base64-der`. HAProxy has no built-in URL-encoded-PEM output; `url-pem` from HAProxy requires a custom Lua `url_enc` converter.

### Chains in a Single Header

`url-pem`, `url-pem-aws`, and `xfcc` accept concatenated PEM blocks in one header value; `base64-der` accepts comma-separated DER. The first entry is the leaf, and the leaf is the identity the request authenticates as.

The leaf entry has to parse on its own. If it is empty, unparseable, or preceded by anything other than whitespace, the whole header is rejected and extraction fails with `header_missing_or_malformed`. A leaf damaged in transit therefore produces a 401 rather than authenticating the request as the next certificate in the header. Entries after the leaf are dropped individually when they fail to parse, and the chain links past them.

## Chain Header

Some proxies forward the leaf certificate and the certificate chain in two separate headers. RFC 9440 is the canonical example: the leaf goes in `Client-Cert` and the chain in `Client-Cert-Chain` (a comma-separated structured-field list of `:base64:` items, leaf-nearest first).

The `chainHeader` option pairs a chain header with the configured leaf header. The chain header value is split on commas, each item is parsed with the same `headerEncoding`, and the resulting certificates are linked via `issuerCertificate` after the leaf. Set `includeChain: true` to keep the chain on the request object; otherwise the chain is parsed and dropped (matching the existing single-header chain stripping behavior).

```javascript
// Cloudflare RFC 9440 (chain header is configured automatically by the preset)
app.use(clientCertificateAuth(checkAuth, {
  certificateSource: 'cloudflare-rfc9440',
  includeChain: true
}));

// Custom two-header scheme
app.use(clientCertificateAuth(checkAuth, {
  certificateHeader: 'X-Client-Cert',
  chainHeader: 'X-Client-Cert-Chain',
  headerEncoding: 'rfc9440',
  includeChain: true
}));
```

The comma splitting targets RFC 9440 structured-field lists. For non-RFC-9440 encodings that may contain commas inside a single cert value, use the single-header chain support built into `base64-der` (comma-separated DER), `url-pem` and `url-pem-aws` (concatenated PEM blocks), and `xfcc` (the `Chain` element) instead.

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

The `verifyValue` comparison is exact (case-sensitive, no whitespace trimming); set it to the exact string your proxy emits.

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
