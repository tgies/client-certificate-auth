[**client-certificate-auth API Reference**](../../index.md)

***

[client-certificate-auth API Reference](../../index.md) / [helpers](../index.md) / allowFingerprints

# Function: allowFingerprints()

> **allowFingerprints**(`fingerprints`): [`ValidationCallback`](../../clientCertificateAuth/type-aliases/ValidationCallback.md)

Defined in: [helpers.d.ts:42](https://github.com/tgies/client-certificate-auth/blob/1592b323472fe6163dd3cb046c134c3830f5ff4e/lib/helpers.d.ts#L42)

Create a validation callback that allows certificates with matching fingerprints.
Supports SHA-1 fingerprints (compared against cert.fingerprint) and SHA-256
fingerprints with "SHA256:" prefix (compared against cert.fingerprint256).
Fingerprints without a prefix are treated as SHA-1.

## Parameters

### fingerprints

`string`[]

Allowed fingerprints

## Returns

[`ValidationCallback`](../../clientCertificateAuth/type-aliases/ValidationCallback.md)
