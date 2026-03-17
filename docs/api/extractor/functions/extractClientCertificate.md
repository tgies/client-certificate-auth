[**client-certificate-auth API Reference**](../../index.md)

***

[client-certificate-auth API Reference](../../index.md) / [extractor](../index.md) / extractClientCertificate

# Function: extractClientCertificate()

> **extractClientCertificate**(`req`, `options?`): [`ExtractionResult`](../type-aliases/ExtractionResult.md)

Defined in: [extractor.d.ts:54](https://github.com/tgies/client-certificate-auth/blob/1592b323472fe6163dd3cb046c134c3830f5ff4e/lib/extractor.d.ts#L54)

Extract client certificate from request.

Works with both header-based extraction (reverse proxy scenarios) and socket-based
extraction (direct TLS connections). Returns a structured result object instead of
throwing or using callbacks, making it suitable for any framework adapter.

## Parameters

### req

Request object with headers and optional socket

#### headers

`Record`&lt;`string`, `string` \| `string`[] \| `undefined`&gt;

HTTP headers object

#### socket?

\{ `authorized?`: `boolean`; `getPeerCertificate?`: (`detailed`) => `PeerCertificate`; \}

TLS socket with getPeerCertificate() method

#### socket.authorized?

`boolean`

Whether socket was authorized

#### socket.getPeerCertificate?

(`detailed`) => `PeerCertificate`

Get peer certificate

### options?

[`ExtractorOptions`](../type-aliases/ExtractorOptions.md)

Extraction options

## Returns

[`ExtractionResult`](../type-aliases/ExtractionResult.md)

## Examples

```ts
// AWS ALB header extraction
const result = extractClientCertificate(req, { certificateSource: 'aws-alb' });
if (result.success) {
  console.log('Certificate CN:', result.certificate.subject.CN);
} else {
  console.error('Extraction failed:', result.reason);
}
```

```ts
// Socket extraction with fallback
const result = extractClientCertificate(req, {
  certificateSource: 'envoy',
  fallbackToSocket: true
});
```
