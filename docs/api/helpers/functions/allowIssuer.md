[**client-certificate-auth API Reference**](../../index.md)

***

[client-certificate-auth API Reference](../../index.md) / [helpers](../index.md) / allowIssuer

# Function: allowIssuer()

> **allowIssuer**(`match`): [`ValidationCallback`](../../clientCertificateAuth/type-aliases/ValidationCallback.md)

Defined in: [helpers.d.ts:49](https://github.com/tgies/client-certificate-auth/blob/1592b323472fe6163dd3cb046c134c3830f5ff4e/lib/helpers.d.ts#L49)

Create a validation callback that allows certificates with matching issuer fields.
All specified fields must match (partial matching).

## Parameters

### match

[`DNFields`](../interfaces/DNFields.md)

Issuer fields to match

## Returns

[`ValidationCallback`](../../clientCertificateAuth/type-aliases/ValidationCallback.md)
