[**client-certificate-auth API Reference**](../../index.md)

***

[client-certificate-auth API Reference](../../index.md) / [helpers](../index.md) / anyOf

# Function: anyOf()

> **anyOf**(...`callbacks`): [`ValidationCallback`](../../clientCertificateAuth/type-aliases/ValidationCallback.md)

Defined in: [helpers.d.ts:103](https://github.com/tgies/client-certificate-auth/blob/1592b323472fe6163dd3cb046c134c3830f5ff4e/lib/helpers.d.ts#L103)

Combine multiple validation callbacks with OR logic.
At least one callback must return true for the certificate to be authorized.

## Parameters

### callbacks

...[`ValidationCallback`](../../clientCertificateAuth/type-aliases/ValidationCallback.md)[]

Validation callbacks to combine

## Returns

[`ValidationCallback`](../../clientCertificateAuth/type-aliases/ValidationCallback.md)
