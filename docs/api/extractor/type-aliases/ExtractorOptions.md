[**client-certificate-auth API Reference**](../../index.md)

***

[client-certificate-auth API Reference](../../index.md) / [extractor](../index.md) / ExtractorOptions

# Type Alias: ExtractorOptions

> **ExtractorOptions** = `object`

Defined in: [extractor.d.ts:81](https://github.com/tgies/client-certificate-auth/blob/1592b323472fe6163dd3cb046c134c3830f5ff4e/lib/extractor.d.ts#L81)

## Properties

### certificateHeader?

> `optional` **certificateHeader**: `string`

Defined in: [extractor.d.ts:89](https://github.com/tgies/client-certificate-auth/blob/1592b323472fe6163dd3cb046c134c3830f5ff4e/lib/extractor.d.ts#L89)

- Custom header name

***

### certificateSource?

> `optional` **certificateSource**: `"aws-alb"` \| `"envoy"` \| `"cloudflare"` \| `"traefik"`

Defined in: [extractor.d.ts:85](https://github.com/tgies/client-certificate-auth/blob/1592b323472fe6163dd3cb046c134c3830f5ff4e/lib/extractor.d.ts#L85)

- Preset configuration

***

### fallbackToSocket?

> `optional` **fallbackToSocket**: `boolean`

Defined in: [extractor.d.ts:97](https://github.com/tgies/client-certificate-auth/blob/1592b323472fe6163dd3cb046c134c3830f5ff4e/lib/extractor.d.ts#L97)

- Try socket if header extraction fails

***

### headerEncoding?

> `optional` **headerEncoding**: `"url-pem"` \| `"url-pem-aws"` \| `"xfcc"` \| `"base64-der"` \| `"rfc9440"`

Defined in: [extractor.d.ts:93](https://github.com/tgies/client-certificate-auth/blob/1592b323472fe6163dd3cb046c134c3830f5ff4e/lib/extractor.d.ts#L93)

- Header encoding

***

### includeChain?

> `optional` **includeChain**: `boolean`

Defined in: [extractor.d.ts:101](https://github.com/tgies/client-certificate-auth/blob/1592b323472fe6163dd3cb046c134c3830f5ff4e/lib/extractor.d.ts#L101)

- Include issuerCertificate chain

***

### verifyHeader?

> `optional` **verifyHeader**: `string`

Defined in: [extractor.d.ts:105](https://github.com/tgies/client-certificate-auth/blob/1592b323472fe6163dd3cb046c134c3830f5ff4e/lib/extractor.d.ts#L105)

- Header name for upstream verification status

***

### verifyValue?

> `optional` **verifyValue**: `string`

Defined in: [extractor.d.ts:109](https://github.com/tgies/client-certificate-auth/blob/1592b323472fe6163dd3cb046c134c3830f5ff4e/lib/extractor.d.ts#L109)

- Expected value for successful verification
