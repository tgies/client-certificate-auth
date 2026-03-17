[**client-certificate-auth API Reference**](../../index.md)

***

[client-certificate-auth API Reference](../../index.md) / [clientCertificateAuth](../index.md) / ValidationCallback

# Type Alias: ValidationCallback()

> **ValidationCallback** = (`cert`, `req?`) => `boolean` \| `Promise`&lt;`boolean`&gt;

Defined in: [clientCertificateAuth.d.ts:123](https://github.com/tgies/client-certificate-auth/blob/1592b323472fe6163dd3cb046c134c3830f5ff4e/lib/clientCertificateAuth.d.ts#L123)

## Parameters

### cert

`PeerCertificate` | `DetailedPeerCertificate`

### req?

[`ClientCertRequest`](../interfaces/ClientCertRequest.md)

## Returns

`boolean` \| `Promise`&lt;`boolean`&gt;
