[**client-certificate-auth API Reference**](../../index.md)

***

[client-certificate-auth API Reference](../../index.md) / [parsers](../index.md) / parseUrlPem

# Function: parseUrlPem()

> **parseUrlPem**(`headerValue`): `PeerCertificate` \| `null`

Defined in: [parsers.d.ts:50](https://github.com/tgies/client-certificate-auth/blob/1592b323472fe6163dd3cb046c134c3830f5ff4e/lib/parsers.d.ts#L50)

Parse URL-encoded PEM certificate (nginx, HAProxy format).

## Parameters

### headerValue

`string`

## Returns

`PeerCertificate` \| `null`

## See

https://nginx.org/en/docs/http/ngx_http_ssl_module.html#var_ssl_client_escaped_cert
