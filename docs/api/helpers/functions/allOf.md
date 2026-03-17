[**client-certificate-auth API Reference**](../../index.md)

***

[client-certificate-auth API Reference](../../index.md) / [helpers](../index.md) / allOf

# Function: allOf()

> **allOf**(...`callbacks`): [`ValidationCallback`](../../clientCertificateAuth/type-aliases/ValidationCallback.md)

Defined in: [helpers.d.ts:96](https://github.com/tgies/client-certificate-auth/blob/1592b323472fe6163dd3cb046c134c3830f5ff4e/lib/helpers.d.ts#L96)

Combine multiple validation callbacks with AND logic.
All callbacks must return true for the certificate to be authorized.

## Parameters

### callbacks

...[`ValidationCallback`](../../clientCertificateAuth/type-aliases/ValidationCallback.md)[]

Validation callbacks to combine

## Returns

[`ValidationCallback`](../../clientCertificateAuth/type-aliases/ValidationCallback.md)
