[**client-certificate-auth API Reference**](../../index.md)

***

[client-certificate-auth API Reference](../../index.md) / [parsers](../index.md) / parseRfc9440

# Function: parseRfc9440()

> **parseRfc9440**(`headerValue`): `PeerCertificate` \| `null`

Defined in: [parsers.d.ts:75](https://github.com/tgies/client-certificate-auth/blob/1592b323472fe6163dd3cb046c134c3830f5ff4e/lib/parsers.d.ts#L75)

Parse RFC 9440 format certificate (used by Google Cloud Load Balancer).

## Parameters

### headerValue

`string`

## Returns

`PeerCertificate` \| `null`

## See

https://datatracker.ietf.org/doc/html/rfc9440#section-2.1
