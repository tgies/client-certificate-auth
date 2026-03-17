[**client-certificate-auth API Reference**](../../index.md)

***

[client-certificate-auth API Reference](../../index.md) / [parsers](../index.md) / parseBase64Der

# Function: parseBase64Der()

> **parseBase64Der**(`headerValue`): `PeerCertificate` \| `null`

Defined in: [parsers.d.ts:69](https://github.com/tgies/client-certificate-auth/blob/1592b323472fe6163dd3cb046c134c3830f5ff4e/lib/parsers.d.ts#L69)

Parse base64-encoded DER certificate (Cloudflare, Traefik format).
Also handles Traefik's comma-separated cert chains.

## Parameters

### headerValue

`string`

## Returns

`PeerCertificate` \| `null`

## See

https://developers.cloudflare.com/api-shield/security/mtls/configure/
