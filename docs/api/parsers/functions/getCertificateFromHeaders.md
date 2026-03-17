[**client-certificate-auth API Reference**](../../index.md)

***

[client-certificate-auth API Reference](../../index.md) / [parsers](../index.md) / getCertificateFromHeaders

# Function: getCertificateFromHeaders()

> **getCertificateFromHeaders**(`headers`, `config`): `PeerCertificate` \| `null`

Defined in: [parsers.d.ts:98](https://github.com/tgies/client-certificate-auth/blob/1592b323472fe6163dd3cb046c134c3830f5ff4e/lib/parsers.d.ts#L98)

Get certificate from request headers using configuration.

## Parameters

### headers

`Record`&lt;`string`, `string` \| `string`[] \| `undefined`&gt;

### config

[`CertificateHeaderConfig`](../interfaces/CertificateHeaderConfig.md)

## Returns

`PeerCertificate` \| `null`
