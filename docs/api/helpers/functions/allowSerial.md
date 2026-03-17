[**client-certificate-auth API Reference**](../../index.md)

***

[client-certificate-auth API Reference](../../index.md) / [helpers](../index.md) / allowSerial

# Function: allowSerial()

> **allowSerial**(`serials`): [`ValidationCallback`](../../clientCertificateAuth/type-aliases/ValidationCallback.md)

Defined in: [helpers.d.ts:75](https://github.com/tgies/client-certificate-auth/blob/1592b323472fe6163dd3cb046c134c3830f5ff4e/lib/helpers.d.ts#L75)

Create a validation callback that allows certificates with matching serial numbers.
Normalizes hex formats (with/without colons).

## Parameters

### serials

`string`[]

Allowed serial numbers

## Returns

[`ValidationCallback`](../../clientCertificateAuth/type-aliases/ValidationCallback.md)
