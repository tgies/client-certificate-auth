[**client-certificate-auth API Reference**](../../index.md)

***

[client-certificate-auth API Reference](../../index.md) / [clientCertificateAuth](../index.md) / ClientCertRequest

# Interface: ClientCertRequest

Defined in: [clientCertificateAuth.d.ts:27](https://github.com/tgies/client-certificate-auth/blob/1592b323472fe6163dd3cb046c134c3830f5ff4e/lib/clientCertificateAuth.d.ts#L27)

Extended request object with TLS socket and optional Express properties.

## Extends

- `IncomingMessage`

## Properties

### clientCertificate?

> `optional` **clientCertificate**: `PeerCertificate` \| `DetailedPeerCertificate`

Defined in: [clientCertificateAuth.d.ts:42](https://github.com/tgies/client-certificate-auth/blob/1592b323472fe6163dd3cb046c134c3830f5ff4e/lib/clientCertificateAuth.d.ts#L42)

Client certificate attached by clientCertificateAuth middleware.
Available after successful certificate extraction, before authorization callback.
Contains issuerCertificate chain if includeChain option is true.

***

### secure?

> `optional` **secure**: `boolean`

Defined in: [clientCertificateAuth.d.ts:29](https://github.com/tgies/client-certificate-auth/blob/1592b323472fe6163dd3cb046c134c3830f5ff4e/lib/clientCertificateAuth.d.ts#L29)

True if connection is over HTTPS (Express-specific)

***

### socket

> **socket**: `TLSSocket` & `object`

Defined in: [clientCertificateAuth.d.ts:31](https://github.com/tgies/client-certificate-auth/blob/1592b323472fe6163dd3cb046c134c3830f5ff4e/lib/clientCertificateAuth.d.ts#L31)

TLS socket with authorization properties

#### Type Declaration

##### authorizationError?

> `optional` **authorizationError**: `string`

Error message if authorization failed

##### authorized?

> `optional` **authorized**: `boolean`

Whether the client certificate was authorized at the TLS layer

#### Overrides

`IncomingMessage.socket`
