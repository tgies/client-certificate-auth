[**client-certificate-auth API Reference**](../../index.md)

***

[client-certificate-auth API Reference](../../index.md) / [extractor](../index.md) / ExtractionResult

# Type Alias: ExtractionResult

> **ExtractionResult** = `object`

Defined in: [extractor.d.ts:61](https://github.com/tgies/client-certificate-auth/blob/1592b323472fe6163dd3cb046c134c3830f5ff4e/lib/extractor.d.ts#L61)

## Properties

### certificate

> **certificate**: `PeerCertificate` \| `null`

Defined in: [extractor.d.ts:69](https://github.com/tgies/client-certificate-auth/blob/1592b323472fe6163dd3cb046c134c3830f5ff4e/lib/extractor.d.ts#L69)

- Extracted certificate (null on failure)

***

### reason

> **reason**: `string` \| `null`

Defined in: [extractor.d.ts:79](https://github.com/tgies/client-certificate-auth/blob/1592b323472fe6163dd3cb046c134c3830f5ff4e/lib/extractor.d.ts#L79)

- Rejection reason code (null on success)

Rejection reasons:
- 'verification_header_mismatch' - Proxy verify header didn't match expected value
- 'header_missing_or_malformed' - Header extraction failed and no fallback configured
- 'socket_not_authorized' - Socket not authorized for TLS client cert
- 'certificate_not_retrievable' - Socket authorized but getPeerCertificate() returned empty

***

### success

> **success**: `boolean`

Defined in: [extractor.d.ts:65](https://github.com/tgies/client-certificate-auth/blob/1592b323472fe6163dd3cb046c134c3830f5ff4e/lib/extractor.d.ts#L65)

- Whether extraction succeeded
