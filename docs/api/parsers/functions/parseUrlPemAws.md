[**client-certificate-auth API Reference**](../../index.md)

***

[client-certificate-auth API Reference](../../index.md) / [parsers](../index.md) / parseUrlPemAws

# Function: parseUrlPemAws()

> **parseUrlPemAws**(`headerValue`): `PeerCertificate` \| `null`

Defined in: [parsers.d.ts:56](https://github.com/tgies/client-certificate-auth/blob/1592b323472fe6163dd3cb046c134c3830f5ff4e/lib/parsers.d.ts#L56)

Parse URL-encoded PEM certificate with AWS ALB safe character handling.

## Parameters

### headerValue

`string`

## Returns

`PeerCertificate` \| `null`

## See

https://docs.aws.amazon.com/elasticloadbalancing/latest/application/mutual-authentication.html
