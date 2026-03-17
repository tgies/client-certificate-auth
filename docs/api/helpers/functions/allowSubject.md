[**client-certificate-auth API Reference**](../../index.md)

***

[client-certificate-auth API Reference](../../index.md) / [helpers](../index.md) / allowSubject

# Function: allowSubject()

> **allowSubject**(`match`): [`ValidationCallback`](../../clientCertificateAuth/type-aliases/ValidationCallback.md)

Defined in: [helpers.d.ts:56](https://github.com/tgies/client-certificate-auth/blob/1592b323472fe6163dd3cb046c134c3830f5ff4e/lib/helpers.d.ts#L56)

Create a validation callback that allows certificates with matching subject fields.
All specified fields must match (partial matching).

## Parameters

### match

[`DNFields`](../interfaces/DNFields.md)

Subject fields to match

## Returns

[`ValidationCallback`](../../clientCertificateAuth/type-aliases/ValidationCallback.md)
