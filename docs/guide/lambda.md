# AWS Lambda

When AWS API Gateway has mTLS enabled on a custom domain and a Lambda function is the integration target, the validated client certificate arrives **inside the Lambda event object**, not as an HTTP header. The Express middleware in this package handles the header-based and socket-based cases but cannot reach into a Lambda event directly.

The `client-certificate-auth/lambda` subpath provides a small framework-agnostic helper for this case.

## Usage

```javascript
import { extractClientCertificateFromLambdaEvent } from 'client-certificate-auth/lambda';

export const handler = async (event) => {
  const result = extractClientCertificateFromLambdaEvent(event);

  if (!result.success) {
    return { statusCode: 401, body: result.reason };
  }

  if (result.certificate.subject.CN !== 'authorized-client') {
    return { statusCode: 403, body: 'Forbidden' };
  }

  return { statusCode: 200, body: 'OK' };
};
```

The helper returns the same `{ success, certificate, reason }` result as `extractClientCertificate()` from `client-certificate-auth/extractor`. The returned `certificate` is a `PeerCertificate` matching Node's `getPeerCertificate()` output, so validation helpers from `client-certificate-auth/helpers` (`allowCN`, `allowOU`, `allOf`, etc.) work without modification.

## Event Payload Formats

API Gateway sends client certificate information at one of two paths depending on the API type and payload version:

| API Type | Payload Format | Path |
|----------|----------------|------|
| HTTP API | v2.0 | `event.requestContext.authentication.clientCert` |
| REST API | v1.0 | `event.requestContext.identity.clientCert` |

The helper reads both paths; if both are present, v2.0 takes precedence.

The `clientCert` object always contains:

```typescript
{
  clientCertPem: string,   // PEM with BEGIN/END delimiters
  subjectDN: string,
  issuerDN: string,
  serialNumber: string,
  validity: { notBefore: string, notAfter: string }
}
```

The helper parses `clientCertPem` into a `PeerCertificate` and returns it; the API-Gateway-parsed `subjectDN` / `issuerDN` / `serialNumber` / `validity` fields are not surfaced through this helper (use `result.certificate.subject`, `result.certificate.issuer`, etc.).

## Rejection Reasons

| Reason | Meaning |
|--------|---------|
| `lambda_event_missing_clientcert` | No `clientCertPem` at either the v2 or v1 path. Typical cause: mTLS not enabled on the API Gateway custom domain, or the client did not present a certificate. |
| `lambda_event_clientcert_malformed` | `clientCertPem` was present but failed to parse as a PEM certificate. |

## CommonJS

```javascript
const lambda = await require('client-certificate-auth/lambda').load();
exports.handler = async (event) => {
  const result = lambda.extractClientCertificateFromLambdaEvent(event);
  // ...
};
```

## See Also

- [AWS API Gateway HTTP API mTLS documentation](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-mutual-tls.html)
- For AWS ALB mTLS, use the [`aws-alb` or `aws-alb-verify` preset](./reverse-proxy.md#preset-details) with the standard middleware instead. ALB forwards certificates as HTTP headers, not Lambda event fields.
