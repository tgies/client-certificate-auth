[**client-certificate-auth API Reference**](../../index.md)

***

[client-certificate-auth API Reference](../../index.md) / [clientCertificateAuth](../index.md) / ClientCertificateAuthOptions

# Interface: ClientCertificateAuthOptions

Defined in: [clientCertificateAuth.d.ts:50](https://github.com/tgies/client-certificate-auth/blob/1592b323472fe6163dd3cb046c134c3830f5ff4e/lib/clientCertificateAuth.d.ts#L50)

## Properties

### certificateHeader?

> `optional` **certificateHeader**: `string`

Defined in: [clientCertificateAuth.d.ts:63](https://github.com/tgies/client-certificate-auth/blob/1592b323472fe6163dd3cb046c134c3830f5ff4e/lib/clientCertificateAuth.d.ts#L63)

Custom header name to read certificate from.
Overrides preset header name if also using certificateSource.

***

### certificateSource?

> `optional` **certificateSource**: [`CertificateSource`](../../parsers/type-aliases/CertificateSource.md)

Defined in: [clientCertificateAuth.d.ts:56](https://github.com/tgies/client-certificate-auth/blob/1592b323472fe6163dd3cb046c134c3830f5ff4e/lib/clientCertificateAuth.d.ts#L56)

Use a preset configuration for a known reverse proxy.
Header-based certs are only checked if this or certificateHeader is set.

#### See

https://github.com/tgies/client-certificate-auth#reverse-proxy-support

***

### fallbackToSocket?

> `optional` **fallbackToSocket**: `boolean`

Defined in: [clientCertificateAuth.d.ts:76](https://github.com/tgies/client-certificate-auth/blob/1592b323472fe6163dd3cb046c134c3830f5ff4e/lib/clientCertificateAuth.d.ts#L76)

If header-based extraction is configured but fails (header absent or malformed),
try socket.getPeerCertificate() instead of returning 401.

#### Default

```ts
false
```

***

### headerEncoding?

> `optional` **headerEncoding**: [`HeaderEncoding`](../../parsers/type-aliases/HeaderEncoding.md)

Defined in: [clientCertificateAuth.d.ts:69](https://github.com/tgies/client-certificate-auth/blob/1592b323472fe6163dd3cb046c134c3830f5ff4e/lib/clientCertificateAuth.d.ts#L69)

How to decode the header value.
Required when using certificateHeader without certificateSource.

***

### includeChain?

> `optional` **includeChain**: `boolean`

Defined in: [clientCertificateAuth.d.ts:83](https://github.com/tgies/client-certificate-auth/blob/1592b323472fe6163dd3cb046c134c3830f5ff4e/lib/clientCertificateAuth.d.ts#L83)

If true, include the full certificate chain via cert.issuerCertificate.
Applies to both socket and header-based extraction.

#### Default

```ts
false
```

***

### onAuthenticated()?

> `optional` **onAuthenticated**: (`cert`, `req`) => `void` \| `Promise`&lt;`void`&gt;

Defined in: [clientCertificateAuth.d.ts:104](https://github.com/tgies/client-certificate-auth/blob/1592b323472fe6163dd3cb046c134c3830f5ff4e/lib/clientCertificateAuth.d.ts#L104)

Called when a client is successfully authenticated.
Fire-and-forget: does not block the request, errors are logged to console.error.

#### Parameters

##### cert

The validated client certificate

`PeerCertificate` | `DetailedPeerCertificate`

##### req

[`ClientCertRequest`](ClientCertRequest.md)

The HTTP request object

#### Returns

`void` \| `Promise`&lt;`void`&gt;

***

### onRejected()?

> `optional` **onRejected**: (`cert`, `req`, `reason`) => `void` \| `Promise`&lt;`void`&gt;

Defined in: [clientCertificateAuth.d.ts:116](https://github.com/tgies/client-certificate-auth/blob/1592b323472fe6163dd3cb046c134c3830f5ff4e/lib/clientCertificateAuth.d.ts#L116)

Called when authentication is rejected.
Fire-and-forget: does not block the request, errors are logged to console.error.

#### Parameters

##### cert

The client certificate (null if extraction failed)

`PeerCertificate` | `DetailedPeerCertificate` | `null`

##### req

[`ClientCertRequest`](ClientCertRequest.md)

The HTTP request object

##### reason

`string`

Why authentication was rejected

#### Returns

`void` \| `Promise`&lt;`void`&gt;

***

### verifyHeader?

> `optional` **verifyHeader**: `string`

Defined in: [clientCertificateAuth.d.ts:89](https://github.com/tgies/client-certificate-auth/blob/1592b323472fe6163dd3cb046c134c3830f5ff4e/lib/clientCertificateAuth.d.ts#L89)

Header name containing certificate verification status from upstream proxy.
Must be used together with verifyValue. Example: 'X-SSL-Client-Verify' for nginx.

***

### verifyValue?

> `optional` **verifyValue**: `string`

Defined in: [clientCertificateAuth.d.ts:96](https://github.com/tgies/client-certificate-auth/blob/1592b323472fe6163dd3cb046c134c3830f5ff4e/lib/clientCertificateAuth.d.ts#L96)

Expected value indicating successful certificate verification.
If verifyHeader is set, requests are rejected unless the header matches this value.
Example: 'SUCCESS' for nginx.
