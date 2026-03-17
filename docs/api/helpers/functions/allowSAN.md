[**client-certificate-auth API Reference**](../../index.md)

***

[client-certificate-auth API Reference](../../index.md) / [helpers](../index.md) / allowSAN

# Function: allowSAN()

> **allowSAN**(`values`): [`ValidationCallback`](../../clientCertificateAuth/type-aliases/ValidationCallback.md)

Defined in: [helpers.d.ts:82](https://github.com/tgies/client-certificate-auth/blob/1592b323472fe6163dd3cb046c134c3830f5ff4e/lib/helpers.d.ts#L82)

Create a validation callback that allows certificates with matching Subject Alternative Names.
Checks the subjectaltname field (format: "DNS:example.com, email:user@example.com").

## Parameters

### values

`string`[]

Allowed SAN values (e.g., "DNS:example.com", "example.com", "user@example.com")

## Returns

[`ValidationCallback`](../../clientCertificateAuth/type-aliases/ValidationCallback.md)
