[**client-certificate-auth API Reference**](../../index.md)

***

[client-certificate-auth API Reference](../../index.md) / [helpers](../index.md) / allowEmail

# Function: allowEmail()

> **allowEmail**(`emails`): [`ValidationCallback`](../../clientCertificateAuth/type-aliases/ValidationCallback.md)

Defined in: [helpers.d.ts:89](https://github.com/tgies/client-certificate-auth/blob/1592b323472fe6163dd3cb046c134c3830f5ff4e/lib/helpers.d.ts#L89)

Create a validation callback that allows certificates with matching email addresses.
Checks both SAN email entries and subject.emailAddress.

## Parameters

### emails

`string`[]

Allowed email addresses

## Returns

[`ValidationCallback`](../../clientCertificateAuth/type-aliases/ValidationCallback.md)
