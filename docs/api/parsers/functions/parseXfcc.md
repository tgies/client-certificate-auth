[**client-certificate-auth API Reference**](../../index.md)

***

[client-certificate-auth API Reference](../../index.md) / [parsers](../index.md) / parseXfcc

# Function: parseXfcc()

> **parseXfcc**(`headerValue`): `PeerCertificate` \| `null`

Defined in: [parsers.d.ts:62](https://github.com/tgies/client-certificate-auth/blob/1592b323472fe6163dd3cb046c134c3830f5ff4e/lib/parsers.d.ts#L62)

Parse Envoy XFCC (X-Forwarded-Client-Cert) structured header format.

## Parameters

### headerValue

`string`

## Returns

`PeerCertificate` \| `null`

## See

https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers#x-forwarded-client-cert
