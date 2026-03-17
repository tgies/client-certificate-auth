[**client-certificate-auth API Reference**](../../index.md)

***

[client-certificate-auth API Reference](../../index.md) / [parsers](../index.md) / CertificateHeaderConfig

# Interface: CertificateHeaderConfig

Defined in: [parsers.d.ts:37](https://github.com/tgies/client-certificate-auth/blob/1592b323472fe6163dd3cb046c134c3830f5ff4e/lib/parsers.d.ts#L37)

Configuration for certificate extraction from headers.

## Properties

### certificateHeader?

> `optional` **certificateHeader**: `string`

Defined in: [parsers.d.ts:41](https://github.com/tgies/client-certificate-auth/blob/1592b323472fe6163dd3cb046c134c3830f5ff4e/lib/parsers.d.ts#L41)

Custom header name (overrides preset)

***

### certificateSource?

> `optional` **certificateSource**: [`CertificateSource`](../type-aliases/CertificateSource.md)

Defined in: [parsers.d.ts:39](https://github.com/tgies/client-certificate-auth/blob/1592b323472fe6163dd3cb046c134c3830f5ff4e/lib/parsers.d.ts#L39)

Use a preset configuration for a known proxy

***

### headerEncoding?

> `optional` **headerEncoding**: [`HeaderEncoding`](../type-aliases/HeaderEncoding.md)

Defined in: [parsers.d.ts:43](https://github.com/tgies/client-certificate-auth/blob/1592b323472fe6163dd3cb046c134c3830f5ff4e/lib/parsers.d.ts#L43)

Encoding format (required if certificateHeader is set without certificateSource)
