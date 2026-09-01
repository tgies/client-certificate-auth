import assert from 'node:assert/strict';
import {
    allowCN,
    allowFingerprints,
    allowIssuer,
    allowSubject,
    allowOU,
    allowOrganization,
    allowSerial,
    allowSAN,
    allowEmail,
    allowCA,
    allOf,
    anyOf,
} from '../lib/helpers.js';
import { pemToCertificate } from '../lib/parsers.js';
import { generateMtlsCertificates, generateIntermediateChain, generateClientCertificate, pemToDer } from './test-helpers.js';
import selfsigned from 'selfsigned';
import * as x509 from '@peculiar/x509';
import { webcrypto } from 'node:crypto';

const RSA_SHA256 = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };

/**
 * Issue a certificate with arbitrary extensions, signed by a selfsigned-style
 * CA ({ cert, key } PEM pair), or self-signed when `ca` is null. Returns the
 * PEM certificate and its PKCS#8 private key.
 */
async function issueWithExtensions(ca, commonName, extensions) {
    const keys = await webcrypto.subtle.generateKey({ ...RSA_SHA256, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) }, true, ['sign', 'verify']);
    const validity = { notBefore: new Date(Date.now() - 60_000), notAfter: new Date(Date.now() + 86_400_000) };
    let cert;
    if (ca) {
        const pkcs8 = Buffer.from(ca.key.replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, ''), 'base64');
        const signingKey = await webcrypto.subtle.importKey('pkcs8', pkcs8, RSA_SHA256, false, ['sign']);
        cert = await x509.X509CertificateGenerator.create({
            ...validity,
            subject: commonName ? `CN=${commonName}` : '',
            issuer: new x509.X509Certificate(ca.cert).subject,
            signingAlgorithm: RSA_SHA256,
            publicKey: keys.publicKey,
            signingKey,
            extensions,
        });
    } else {
        cert = await x509.X509CertificateGenerator.createSelfSigned({
            ...validity,
            name: `CN=${commonName}`,
            signingAlgorithm: RSA_SHA256,
            keys,
            extensions,
        });
    }
    const der = Buffer.from(await webcrypto.subtle.exportKey('pkcs8', keys.privateKey));
    const key = `-----BEGIN PRIVATE KEY-----\n${der.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END PRIVATE KEY-----\n`;
    return { cert: cert.toString('pem'), key };
}

// Mock certificate for testing
const mockCert = {
    subject: {
        C: 'US',
        ST: 'California',
        L: 'San Francisco',
        O: 'Test Corp',
        OU: 'Engineering',
        CN: 'test-client',
        emailAddress: 'test@example.com',
    },
    issuer: {
        C: 'US',
        ST: 'California',
        O: 'Test CA',
        CN: 'Test CA Root',
    },
    fingerprint: 'AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01',
    fingerprint256: 'AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99',
    serialNumber: '01:23:45:67:89:AB:CD:EF',
    subjectaltname: 'DNS:test.example.com, email:alt@example.com, URI:https://example.com',
};

// Mock certificate with multi-valued DN fields (Node.js returns string[] for repeated attributes)
const mockMultiValueCert = {
    subject: {
        C: 'US',
        ST: 'California',
        L: 'San Francisco',
        O: ['Test Corp', 'Parent Corp'],
        OU: ['Engineering', 'DevTeam'],
        CN: 'test-client',
        emailAddress: ['test@example.com', 'admin@example.com'],
    },
    issuer: {
        C: 'US',
        O: 'Test CA',
        CN: 'Test CA Root',
        OU: ['CA Operations', 'Security'],
    },
    fingerprint: 'AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01',
    fingerprint256: 'AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99',
    serialNumber: '01:23:45:67:89:AB:CD:EF',
    subjectaltname: 'DNS:test.example.com, email:alt@example.com',
};

describe('helpers', () => {
    describe('allowCN', () => {
        it('should return true when CN matches', () => {
            const check = allowCN(['test-client', 'other-client']);
            assert.equal(check(mockCert), true);
        });

        it('should return false when CN does not match', () => {
            const check = allowCN(['admin', 'service']);
            assert.equal(check(mockCert), false);
        });

        it('should handle missing subject gracefully', () => {
            const check = allowCN(['test']);
            assert.equal(check({}), false);
        });

        it('should return false when subject exists but CN is undefined', () => {
            const check = allowCN(['test']);
            assert.equal(check({ subject: { O: 'Test Corp' } }), false);
        });

        it('should return false with empty allowlist', () => {
            const check = allowCN([]);
            assert.equal(check(mockCert), false);
        });

        it('should match when CN is a multi-valued array', () => {
            const cert = { subject: { CN: ['primary-client', 'alt-client'] } };
            const check = allowCN(['alt-client']);
            assert.equal(check(cert), true);
        });

        it('should return false when no CN in multi-valued array matches', () => {
            const cert = { subject: { CN: ['primary-client', 'alt-client'] } };
            const check = allowCN(['other-client']);
            assert.equal(check(cert), false);
        });
    });

    describe('allowFingerprints', () => {
        // SHA-1 (no prefix) tests — compared against cert.fingerprint
        it('should match SHA-1 fingerprint (no prefix)', () => {
            const check = allowFingerprints(['AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01']);
            assert.equal(check(mockCert), true);
        });

        it('should be case-insensitive for SHA-1 fingerprints', () => {
            const check = allowFingerprints(['ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01']);
            assert.equal(check(mockCert), true);
        });

        it('should return false when SHA-1 fingerprint does not match', () => {
            const check = allowFingerprints(['00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00']);
            assert.equal(check(mockCert), false);
        });

        it('should handle missing fingerprint gracefully', () => {
            const check = allowFingerprints(['AB:CD']);
            assert.equal(check({}), false);
        });

        it('should return false with empty allowlist', () => {
            const check = allowFingerprints([]);
            assert.equal(check(mockCert), false);
        });

        it('should match when cert has lowercase SHA-1 fingerprint and allowed has uppercase', () => {
            const certLowerFp = { fingerprint: 'ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01' };
            const check = allowFingerprints(['AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01']);
            assert.equal(check(certLowerFp), true);
        });

        it('should match when both SHA-1 fingerprints have mixed case', () => {
            const certMixedFp = { fingerprint: 'Ab:Cd:Ef:01:23:45:67:89:aB:cD:eF:01:23:45:67:89:AB:cd:EF:01' };
            const check = allowFingerprints(['ab:cd:ef:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:ab:cd:ef:01']);
            assert.equal(check(certMixedFp), true);
        });

        it('should match SHA-1 fingerprint supplied as contiguous hex against colon-delimited cert', () => {
            const check = allowFingerprints(['ABCDEF0123456789ABCDEF0123456789ABCDEF01']);
            assert.equal(check(mockCert), true);
        });

        it('should treat an unprefixed 64-hex-digit fingerprint as SHA-256', () => {
            const bare = 'AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99';
            assert.equal(allowFingerprints([bare])(mockCert), true);
            assert.equal(allowFingerprints([bare.replace(/:/g, '').toLowerCase()])(mockCert), true);
            assert.equal(allowFingerprints([bare])({ fingerprint: mockCert.fingerprint }), false);
        });

        it('should match SHA-1 fingerprint with arbitrary colon placement', () => {
            const check = allowFingerprints(['ABCD:EF0123456789AB:CDEF0123456789ABCDEF01']);
            assert.equal(check(mockCert), true);
        });

        // SHA-256 (with SHA256: prefix) tests — compared against cert.fingerprint256
        it('should match SHA-256 fingerprint with SHA256: prefix against cert.fingerprint256', () => {
            const check = allowFingerprints([
                'SHA256:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99',
            ]);
            assert.equal(check(mockCert), true);
        });

        it('should match SHA-256 fingerprint case-insensitively', () => {
            const check = allowFingerprints([
                'sha256:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99',
            ]);
            assert.equal(check(mockCert), true);
        });

        it('should match SHA-256 fingerprint with prefix and contiguous hex digest', () => {
            const check = allowFingerprints([
                'SHA256:AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899',
            ]);
            assert.equal(check(mockCert), true);
        });

        it('should not match SHA-256 fingerprint against cert.fingerprint (SHA-1)', () => {
            // SHA256: prefix but the value is the SHA-1 fingerprint — should NOT match
            const check = allowFingerprints([
                'SHA256:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01',
            ]);
            assert.equal(check(mockCert), false);
        });

        it('should return false for SHA-256 fingerprint when cert has no fingerprint256', () => {
            const certNoFp256 = { fingerprint: 'AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01' };
            const check = allowFingerprints([
                'SHA256:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99',
            ]);
            assert.equal(check(certNoFp256), false);
        });

        // Mixed SHA-1 and SHA-256 tests
        it('should support mixed SHA-1 and SHA-256 fingerprints', () => {
            const check = allowFingerprints([
                'AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01',
                'SHA256:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99',
            ]);
            // Both should match
            assert.equal(check(mockCert), true);
        });

        it('should match SHA-1 from mixed list even when SHA-256 does not match', () => {
            const check = allowFingerprints([
                'AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01',
                'SHA256:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00',
            ]);
            assert.equal(check(mockCert), true);
        });

        it('should match SHA-256 from mixed list even when SHA-1 does not match', () => {
            const check = allowFingerprints([
                '00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00',
                'SHA256:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99',
            ]);
            assert.equal(check(mockCert), true);
        });

        it('should handle cert with only fingerprint256 and SHA256: prefixed allowed', () => {
            const certOnlyFp256 = {
                fingerprint256: 'AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99',
            };
            const check = allowFingerprints([
                'SHA256:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99',
            ]);
            assert.equal(check(certOnlyFp256), true);
        });

        it('should return false when only SHA-1 allowed but cert only has fingerprint256', () => {
            const certOnlyFp256 = {
                fingerprint256: 'AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99',
            };
            const check = allowFingerprints([
                'AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01',
            ]);
            assert.equal(check(certOnlyFp256), false);
        });

        it('should not access fingerprint properties if allowlist is empty for that type', () => {
            let sha1Accessed = false;
            let sha256Accessed = false;
            const cert = {
                get fingerprint() { sha1Accessed = true; return 'AA'; },
                get fingerprint256() { sha256Accessed = true; return 'BB'; },
            };

            // Empty allowlist
            let check = allowFingerprints([]);
            check(cert);
            assert.equal(sha1Accessed, false);
            assert.equal(sha256Accessed, false);

            // Only SHA-1 allowlist
            check = allowFingerprints(['AA']);
            check(cert);
            assert.equal(sha1Accessed, true);
            assert.equal(sha256Accessed, false);

            // Only SHA-256 allowlist
            sha1Accessed = false;
            check = allowFingerprints(['SHA256:BB']);
            check(cert);
            assert.equal(sha1Accessed, false);
            assert.equal(sha256Accessed, true);
        });
    });

    describe('allowIssuer', () => {
        it('should match when all specified fields match', () => {
            const check = allowIssuer({ O: 'Test CA', CN: 'Test CA Root' });
            assert.equal(check(mockCert), true);
        });

        it('should match with partial field specification', () => {
            const check = allowIssuer({ O: 'Test CA' });
            assert.equal(check(mockCert), true);
        });

        it('should return false when any field does not match', () => {
            const check = allowIssuer({ O: 'Test CA', CN: 'Wrong CN' });
            assert.equal(check(mockCert), false);
        });

        it('should handle missing issuer gracefully', () => {
            const check = allowIssuer({ O: 'Test CA' });
            assert.equal(check({}), false);
        });

        it('should match when issuer field is a multi-valued array', () => {
            const check = allowIssuer({ OU: 'Security' });
            assert.equal(check(mockMultiValueCert), true);
        });

        it('should return false when no value in multi-valued issuer field matches', () => {
            const check = allowIssuer({ OU: 'Finance' });
            assert.equal(check(mockMultiValueCert), false);
        });

        it('should match mixed scalar and multi-valued issuer fields', () => {
            const check = allowIssuer({ O: 'Test CA', OU: 'CA Operations' });
            assert.equal(check(mockMultiValueCert), true);
        });

        it('should return false when issuer field value is null', () => {
            const check = allowIssuer({ OU: 'Engineering' });
            assert.equal(check({ issuer: { OU: null } }), false);
        });

        it('should return false with empty match object', () => {
            const check = allowIssuer({});
            assert.equal(check(mockCert), false);
        });
    });

    describe('allowSubject', () => {
        it('should match when all specified fields match', () => {
            const check = allowSubject({ O: 'Test Corp', OU: 'Engineering' });
            assert.equal(check(mockCert), true);
        });

        it('should match with partial field specification', () => {
            const check = allowSubject({ ST: 'California' });
            assert.equal(check(mockCert), true);
        });

        it('should return false when any field does not match', () => {
            const check = allowSubject({ O: 'Test Corp', L: 'New York' });
            assert.equal(check(mockCert), false);
        });

        it('should handle missing subject gracefully', () => {
            const check = allowSubject({ O: 'Test' });
            assert.equal(check({}), false);
        });

        it('should match when subject field is a multi-valued array', () => {
            const check = allowSubject({ OU: 'DevTeam' });
            assert.equal(check(mockMultiValueCert), true);
        });

        it('should return false when no value in multi-valued subject field matches', () => {
            const check = allowSubject({ OU: 'Sales' });
            assert.equal(check(mockMultiValueCert), false);
        });

        it('should return false when subject field value is null', () => {
            const check = allowSubject({ OU: 'Engineering' });
            assert.equal(check({ subject: { OU: null } }), false);
        });

        it('should match mixed scalar and multi-valued subject fields', () => {
            const check = allowSubject({ CN: 'test-client', O: 'Parent Corp' });
            assert.equal(check(mockMultiValueCert), true);
        });

        it('should return false with empty match object', () => {
            const check = allowSubject({});
            assert.equal(check(mockCert), false);
        });
    });

    describe('allowOU', () => {
        it('should return true when OU matches', () => {
            const check = allowOU(['Engineering', 'DevOps']);
            assert.equal(check(mockCert), true);
        });

        it('should return false when OU does not match', () => {
            const check = allowOU(['Sales', 'Marketing']);
            assert.equal(check(mockCert), false);
        });

        it('should handle missing subject gracefully', () => {
            const check = allowOU(['Engineering']);
            assert.equal(check({}), false);
        });

        it('should return false with empty allowlist', () => {
            const check = allowOU([]);
            assert.equal(check(mockCert), false);
        });

        it('should match when OU is a multi-valued array', () => {
            const check = allowOU(['DevTeam', 'Operations']);
            assert.equal(check(mockMultiValueCert), true);
        });

        it('should return false when no OU in multi-valued array matches', () => {
            const check = allowOU(['Sales', 'Marketing']);
            assert.equal(check(mockMultiValueCert), false);
        });
    });

    describe('allowOrganization', () => {
        it('should return true when O matches', () => {
            const check = allowOrganization(['Test Corp', 'Other Corp']);
            assert.equal(check(mockCert), true);
        });

        it('should return false when O does not match', () => {
            const check = allowOrganization(['Another Corp']);
            assert.equal(check(mockCert), false);
        });

        it('should handle missing subject gracefully', () => {
            const check = allowOrganization(['Test']);
            assert.equal(check({}), false);
        });

        it('should return false with empty allowlist', () => {
            const check = allowOrganization([]);
            assert.equal(check(mockCert), false);
        });

        it('should match when O is a multi-valued array', () => {
            const check = allowOrganization(['Parent Corp', 'Other Corp']);
            assert.equal(check(mockMultiValueCert), true);
        });

        it('should return false when no O in multi-valued array matches', () => {
            const check = allowOrganization(['Unknown Corp']);
            assert.equal(check(mockMultiValueCert), false);
        });
    });

    describe('allowSerial', () => {
        it('should match serial with colons', () => {
            const check = allowSerial(['01:23:45:67:89:AB:CD:EF']);
            assert.equal(check(mockCert), true);
        });

        it('should match serial without colons', () => {
            const check = allowSerial(['0123456789ABCDEF']);
            assert.equal(check(mockCert), true);
        });

        it('should be case-insensitive', () => {
            const check = allowSerial(['01:23:45:67:89:ab:cd:ef']);
            assert.equal(check(mockCert), true);
        });

        it('should return false when serial does not match', () => {
            const check = allowSerial(['FF:FF:FF:FF']);
            assert.equal(check(mockCert), false);
        });

        it('should handle missing serialNumber gracefully', () => {
            const check = allowSerial(['0123']);
            assert.equal(check({}), false);
        });

        it('should return false with empty allowlist', () => {
            const check = allowSerial([]);
            assert.equal(check(mockCert), false);
        });

        it('should match when cert serial has colons and allowed has none', () => {
            const certWithColons = { serialNumber: 'AA:BB:CC:DD' };
            const check = allowSerial(['AABBCCDD']);
            assert.equal(check(certWithColons), true);
        });

        it('should match when allowed serial has colons and cert has none', () => {
            const certNoColons = { serialNumber: 'AABBCCDD' };
            const check = allowSerial(['AA:BB:CC:DD']);
            assert.equal(check(certNoColons), true);
        });

        it('should match lowercase cert serial against uppercase allowed', () => {
            const certLower = { serialNumber: 'aabbccdd' };
            const check = allowSerial(['AABBCCDD']);
            assert.equal(check(certLower), true);
        });

        it('should strictly use toUpperCase for normalization', () => {
            // 'ς' and 'σ' both uppercase to 'Σ', but lowercase to themselves.
            // If the implementation incorrectly uses toLowerCase, this will fail.
            // Mostly mutation defense
            const certSigma = { serialNumber: 'σ' };
            const check = allowSerial(['ς']);
            assert.equal(check(certSigma), true);
        });
    });

    describe('allowSAN', () => {
        it('should match DNS SAN with full format', () => {
            const check = allowSAN(['DNS:test.example.com']);
            assert.equal(check(mockCert), true);
        });

        it('should match DNS SAN value only', () => {
            const check = allowSAN(['test.example.com']);
            assert.equal(check(mockCert), true);
        });

        it('should match email SAN', () => {
            const check = allowSAN(['email:alt@example.com']);
            assert.equal(check(mockCert), true);
        });

        it('should match URI SAN', () => {
            const check = allowSAN(['URI:https://example.com']);
            assert.equal(check(mockCert), true);
        });

        it('should be case-insensitive', () => {
            const check = allowSAN(['DNS:TEST.EXAMPLE.COM']);
            assert.equal(check(mockCert), true);
        });

        it('should return false when SAN does not match', () => {
            const check = allowSAN(['DNS:other.example.com']);
            assert.equal(check(mockCert), false);
        });

        it('should handle missing subjectaltname gracefully', () => {
            const check = allowSAN(['test.example.com']);
            assert.equal(check({}), false);
        });

        it('should return false with empty allowlist', () => {
            const check = allowSAN([]);
            assert.equal(check(mockCert), false);
        });

        it('should match IP Address SAN by value only', () => {
            const cert = { subjectaltname: 'IP Address:10.0.0.1, DNS:service.local' };
            assert.equal(allowSAN(['10.0.0.1'])(cert), true);
        });

        it('should match IP Address SAN with full type prefix', () => {
            const cert = { subjectaltname: 'IP Address:10.0.0.1' };
            assert.equal(allowSAN(['IP Address:10.0.0.1'])(cert), true);
        });

        it('should handle SAN entries separated by multiple spaces', () => {
            const cert = { subjectaltname: 'DNS:first.example.com,  email:user@test.com' };
            assert.equal(allowSAN(['email:user@test.com'])(cert), true);
        });

        it('should handle SAN entries without colon prefix', () => {
            // Edge case: malformed SAN entry without type prefix
            const certMalformedSAN = { subjectaltname: 'nocolon, DNS:valid.com' };
            const check = allowSAN(['nocolon']);
            assert.equal(check(certMalformedSAN), true);
        });

        it('should return false when SAN entry without colon does not match', () => {
            // Edge case: entry without colon, none match
            const certMalformedSAN = { subjectaltname: 'nocolon' };
            const check = allowSAN(['other']);
            assert.equal(check(certMalformedSAN), false);
        });

        it('should compare an unrecognized type prefix as part of the value', () => {
            const cert = { subjectaltname: 'X:short-prefix-value' };
            assert.equal(allowSAN(['x:SHORT-prefix-value'])(cert), true);
            assert.equal(allowSAN(['short-prefix-value'])(cert), false);
        });

        it('should not match a typed value against a different SAN type', () => {
            assert.equal(allowSAN(['DNS:alt@example.com'])(mockCert), false);
            assert.equal(allowSAN(['email:test.example.com'])(mockCert), false);
        });

        it('should accept IP: as an alias for IP Address:', () => {
            const cert = { subjectaltname: 'IP Address:10.0.0.1' };
            assert.equal(allowSAN(['IP:10.0.0.1'])(cert), true);
            assert.equal(allowSAN(['ip:10.0.0.2'])(cert), false);
        });

        it('should split the DirName and Registered ID prefixes OpenSSL renders', () => {
            const dirName = { subjectaltname: 'DirName:/CN=Directory Name' };
            assert.equal(allowSAN(['DirName:/CN=Directory Name'])(dirName), true);
            assert.equal(allowSAN(['dirname:/cn=directory name'])(dirName), true);
            assert.equal(allowSAN(['DNS:/CN=Directory Name'])(dirName), false);

            const registeredId = { subjectaltname: 'Registered ID:1.3.6.1.4.1.311.20.2.3' };
            assert.equal(allowSAN(['Registered ID:1.3.6.1.4.1.311.20.2.3'])(registeredId), true);
            assert.equal(allowSAN(['DNS:1.3.6.1.4.1.311.20.2.3'])(registeredId), false);
        });

        it('should keep URI paths case-sensitive while folding scheme and host', () => {
            const cert = { subjectaltname: 'URI:https://Example.com/Path/A' };
            assert.equal(allowSAN(['URI:https://example.com/path/a'])(cert), false);
            assert.equal(allowSAN(['URI:HTTPS://EXAMPLE.COM/Path/A'])(cert), true);
            assert.equal(allowSAN(['https://example.com/Path/A'])(cert), true);
            assert.equal(allowSAN(['uri:https://example.com/Path/A?Q=1'])(cert), false);
        });

        it('should fold only the scheme of URIs without an authority', () => {
            const cert = { subjectaltname: 'URI:urn:example:Abc' };
            assert.equal(allowSAN(['URI:URN:example:Abc'])(cert), true);
            assert.equal(allowSAN(['URI:urn:example:abc'])(cert), false);
            assert.equal(allowSAN(['URI:not a uri'])({ subjectaltname: 'URI:Not A URI' }), false);
        });

        it('should keep URI userinfo case-sensitive', () => {
            const cert = { subjectaltname: 'URI:https://User@Example.com:8443/Path' };
            assert.equal(allowSAN(['URI:HTTPS://User@EXAMPLE.COM:8443/Path'])(cert), true);
            assert.equal(allowSAN(['URI:https://user@example.com:8443/Path'])(cert), false);
        });

        it('should decode JSON-quoted SAN values', () => {
            const cert = {
                subjectaltname: 'URI:"https://example.com/x\\u002cy", othername:"UPN:first\\u002clast@example.com", DNS:"a\\"b.example.com"',
            };
            assert.equal(allowSAN(['URI:https://example.com/x,y'])(cert), true);
            assert.equal(allowSAN(['othername:UPN:first,last@example.com'])(cert), true);
            assert.equal(allowSAN(['a"b.example.com'])(cert), true);
            assert.equal(allowSAN(['URI:https://example.com/x'])(cert), false);
        });

        it('should fall back to the raw text when a quoted value is not valid JSON', () => {
            const cert = { subjectaltname: 'DNS:"broken\\x"' };
            assert.equal(allowSAN(['DNS:"BROKEN\\x"'])(cert), true);
            assert.equal(allowSAN(['DNS:broken'])(cert), false);
        });
    });

    describe('allowEmail', () => {
        it('should match email from subject.emailAddress', () => {
            const check = allowEmail(['test@example.com']);
            assert.equal(check(mockCert), true);
        });

        it('should match email from SAN', () => {
            const check = allowEmail(['alt@example.com']);
            assert.equal(check(mockCert), true);
        });

        it('should be case-insensitive', () => {
            const check = allowEmail(['TEST@EXAMPLE.COM']);
            assert.equal(check(mockCert), true);
        });

        it('should return false when email does not match', () => {
            const check = allowEmail(['other@example.com']);
            assert.equal(check(mockCert), false);
        });

        it('should handle missing email fields gracefully', () => {
            const check = allowEmail(['test@example.com']);
            assert.equal(check({}), false);
        });

        it('should return false with empty allowlist', () => {
            const check = allowEmail([]);
            assert.equal(check(mockCert), false);
        });

        it('should handle cert with only SAN email', () => {
            const certOnlySAN = { subjectaltname: 'email:only@example.com' };
            const check = allowEmail(['only@example.com']);
            assert.equal(check(certOnlySAN), true);
        });

        it('should handle SAN entries separated by multiple spaces', () => {
            const cert = { subjectaltname: 'DNS:example.com,  email:user@test.com' };
            assert.equal(allowEmail(['user@test.com'])(cert), true);
        });

        it('should not match non-email SAN type even if value at offset 6 matches', () => {
            const cert = { subjectaltname: 'URI:x:me@test.com' };
            assert.equal(allowEmail(['me@test.com'])(cert), false);
        });

        it('should decode a JSON-quoted SAN email', () => {
            const cert = { subjectaltname: 'email:"First\\u002cLast@example.com"' };
            assert.equal(allowEmail(['first,last@example.com'])(cert), true);
            assert.equal(allowEmail(['first@example.com'])(cert), false);
        });

        it('should match subject.emailAddress when SAN has no email entries', () => {
            const certSubjectEmailOnly = {
                subject: { emailAddress: 'admin@example.com' },
                subjectaltname: 'DNS:example.com, URI:https://example.com',
            };
            const check = allowEmail(['admin@example.com']);
            assert.equal(check(certSubjectEmailOnly), true);
        });

        it('should return false when subject.emailAddress present but not in allowed list and SAN has no email', () => {
            const certSubjectEmailOnly = {
                subject: { emailAddress: 'admin@example.com' },
                subjectaltname: 'DNS:example.com',
            };
            const check = allowEmail(['other@example.com']);
            assert.equal(check(certSubjectEmailOnly), false);
        });

        it('should match when subject.emailAddress is a multi-valued array', () => {
            const check = allowEmail(['admin@example.com']);
            assert.equal(check(mockMultiValueCert), true);
        });

        it('should return false when no email in multi-valued array matches', () => {
            const cert = {
                subject: { emailAddress: ['first@example.com', 'second@example.com'] },
            };
            const check = allowEmail(['other@example.com']);
            assert.equal(check(cert), false);
        });
    });

    describe('allowCA', () => {
        let pki;        // root CA + client signed by it
        let chain;      // intermediate signed by pki.ca + client signed by the intermediate
        let lookalike;  // a second CA with the same subject DN but a different key
        let selfSigned;
        let expired;
        let notYetValid;
        let expiredCa;

        const day = 24 * 60 * 60 * 1000;
        const signedBy = (ca, commonName, dates = {}) => selfsigned.generate(
            [{ name: 'commonName', value: commonName }],
            {
                algorithm: 'sha256',
                keySize: 2048,
                notBeforeDate: new Date(Date.now() - 60_000),
                ...dates,
                ...(ca ? { ca: { key: ca.key, cert: ca.cert } } : {}),
                extensions: [{ name: 'basicConstraints', cA: !ca, critical: true }],
            }
        );

        beforeAll(async () => {
            pki = await generateMtlsCertificates();
            chain = await generateIntermediateChain(pki.ca);
            lookalike = await generateMtlsCertificates({ caCommonName: 'Test CA' });
            selfSigned = await generateClientCertificate('Self Signed');
            expired = await signedBy(pki.ca, 'Expired', { notBeforeDate: new Date(Date.now() - 2 * day), notAfterDate: new Date(Date.now() - day) });
            notYetValid = await signedBy(pki.ca, 'Future', { notBeforeDate: new Date(Date.now() + day), notAfterDate: new Date(Date.now() + 2 * day) });
            const oldCa = await signedBy(null, 'Old CA', { notBeforeDate: new Date(Date.now() - 2 * day), notAfterDate: new Date(Date.now() - day) });
            expiredCa = { ca: { cert: oldCa.cert, key: oldCa.private }, client: await signedBy({ cert: oldCa.cert, key: oldCa.private }, 'Client Of Old CA') };
        }, 60_000);

        it('should accept a certificate issued directly by a configured CA', () => {
            const cert = pemToCertificate(pki.client.cert);
            assert.equal(allowCA(pki.ca.cert)(cert), true);
            assert.equal(allowCA([pki.ca.cert])(cert), true);
            assert.equal(allowCA(pemToDer(pki.ca.cert))(cert), true);
        });

        it('should reject a self-signed certificate', () => {
            assert.equal(allowCA(pki.ca.cert)(pemToCertificate(selfSigned.cert)), false);
        });

        it('should reject a certificate from a CA with the same subject name but a different key', () => {
            const cert = pemToCertificate(lookalike.client.cert);
            assert.equal(cert.issuer.CN, 'Test CA');
            assert.equal(allowCA(pki.ca.cert)(cert), false);
        });

        it('should walk the issuerCertificate chain to a configured root', () => {
            const leaf = pemToCertificate(chain.client.cert);
            assert.equal(allowCA(pki.ca.cert)(leaf), false);

            leaf.issuerCertificate = pemToCertificate(chain.intermediate.cert);
            assert.equal(allowCA(pki.ca.cert)(leaf), true);
        });

        it('should trust an intermediate listed as an anchor without the root', () => {
            const leaf = pemToCertificate(chain.client.cert);
            assert.equal(allowCA(chain.intermediate.cert)(leaf), true);
        });

        it('should reject a chain link through a certificate that is not a CA', async () => {
            const leaf = await signedBy(pki.ca, 'Mallory');
            const forged = await signedBy({ cert: leaf.cert, key: leaf.private }, 'admin');
            assert.equal(allowCA(pki.ca.cert)(pemToCertificate(leaf.cert)), true);

            const cert = pemToCertificate(forged.cert);
            cert.issuerCertificate = pemToCertificate(leaf.cert);
            assert.equal(allowCA(pki.ca.cert)(cert), false);
        });

        it('should require clientAuth when the leaf carries an extended key usage', async () => {
            const withEku = (usage) => selfsigned.generate([{ name: 'commonName', value: usage }], {
                algorithm: 'sha256',
                keySize: 2048,
                notBeforeDate: new Date(Date.now() - 60_000),
                ca: { key: pki.ca.key, cert: pki.ca.cert },
                extensions: [
                    { name: 'basicConstraints', cA: false, critical: true },
                    { name: 'extKeyUsage', [usage]: true },
                ],
            });
            const serverOnly = await withEku('serverAuth');
            const client = await withEku('clientAuth');

            assert.equal(allowCA(pki.ca.cert)(pemToCertificate(serverOnly.cert)), false);
            assert.equal(allowCA(pki.ca.cert)(pemToCertificate(client.cert)), true);
        });

        const signedCa = (ca, commonName, pathLenConstraint) => selfsigned.generate(
            [{ name: 'commonName', value: commonName }],
            {
                algorithm: 'sha256',
                keySize: 2048,
                notBeforeDate: new Date(Date.now() - 60_000),
                ...(ca ? { ca: { key: ca.key, cert: ca.cert } } : {}),
                extensions: [
                    { name: 'basicConstraints', cA: true, critical: true, ...(pathLenConstraint === undefined ? {} : { pathLenConstraint }) },
                    { name: 'keyUsage', keyCertSign: true, cRLSign: true, critical: true },
                ],
            }
        );
        const asCa = (generated) => ({ cert: generated.cert, key: generated.private });
        const chainOf = (...pems) => {
            const certs = pems.map(pemToCertificate);
            for (let i = 0; i < certs.length - 1; i++) {
                certs[i].issuerCertificate = certs[i + 1];
            }
            return certs[0];
        };

        it('should enforce pathLenConstraint on intermediates', async () => {
            const limited = await signedCa(pki.ca, 'Limited Intermediate', 0);
            const subCa = await signedCa(asCa(limited), 'Sub CA');
            const deep = await signedBy(asCa(subCa), 'Deep Leaf');
            assert.equal(allowCA(pki.ca.cert)(chainOf(deep.cert, subCa.cert, limited.cert)), false);

            const shallow = await signedBy(asCa(limited), 'Shallow Leaf');
            assert.equal(allowCA(pki.ca.cert)(chainOf(shallow.cert, limited.cert)), true);
        });

        it('should count a rollover intermediate whose names differ only by whitespace encoding', async () => {
            // Root name carries a non-breaking space, the intermediate an ASCII
            // space: they render identically but the DER Names differ, so the
            // intermediate is not self-issued and must count toward the path length.
            const NBSP = '\u00a0';
            const bc = (ca, pathLen) => new x509.BasicConstraintsExtension(ca, pathLen, true);
            const root = await issueWithExtensions(null, `Rollover${NBSP}CA`, [bc(true, 0)]);
            const intermediate = await issueWithExtensions(root, 'Rollover CA', [bc(true, undefined)]);
            const leaf = await issueWithExtensions(intermediate, 'Rollover Leaf', [bc(false, undefined)]);
            assert.equal(allowCA(root.cert)(chainOf(leaf.cert, intermediate.cert, root.cert)), false);

            const roomier = await issueWithExtensions(null, `Rollover${NBSP}CA`, [bc(true, 1)]);
            const under = await issueWithExtensions(roomier, 'Rollover CA', [bc(true, undefined)]);
            const underLeaf = await issueWithExtensions(under, 'Rollover Leaf', [bc(false, undefined)]);
            assert.equal(allowCA(roomier.cert)(chainOf(underLeaf.cert, under.cert, roomier.cert)), true);
        });

        it('should count a rollover intermediate whose name differs only by Unicode case', async () => {
            // U+212A KELVIN SIGN lowercases to 'k' in Unicode but not in the
            // ASCII-only fold X.509 canonical name comparison applies, so the
            // intermediate is not self-issued and must count toward the path length.
            const KELVIN = '\u212a';
            const bc = (ca, pathLen) => new x509.BasicConstraintsExtension(ca, pathLen, true);
            const root = await issueWithExtensions(null, 'Rollover KA', [bc(true, 0)]);
            const intermediate = await issueWithExtensions(root, `Rollover ${KELVIN}A`, [bc(true, undefined)]);
            const leaf = await issueWithExtensions(intermediate, 'Rollover Leaf', [bc(false, undefined)]);
            assert.equal(allowCA(root.cert)(chainOf(leaf.cert, intermediate.cert, root.cert)), false);

            const roomier = await issueWithExtensions(null, 'Rollover KA', [bc(true, 1)]);
            const under = await issueWithExtensions(roomier, `Rollover ${KELVIN}A`, [bc(true, undefined)]);
            const underLeaf = await issueWithExtensions(under, 'Rollover Leaf', [bc(false, undefined)]);
            assert.equal(allowCA(roomier.cert)(chainOf(underLeaf.cert, under.cert, roomier.cert)), true);
        });

        it('should not count a genuine rollover intermediate that is self-issued', async () => {
            const bc = (ca, pathLen) => new x509.BasicConstraintsExtension(ca, pathLen, true);
            const root = await issueWithExtensions(null, 'Rollover CA', [bc(true, 0)]);
            const rollover = await issueWithExtensions(root, 'Rollover CA', [bc(true, undefined)]);
            const leaf = await issueWithExtensions(rollover, 'Rollover Leaf', [bc(false, undefined)]);
            assert.equal(allowCA(root.cert)(chainOf(leaf.cert, rollover.cert, root.cert)), true);
        });

        it('should enforce pathLenConstraint on the anchor', async () => {
            const root = await signedCa(null, 'Shallow Root', 0);
            const intermediate = await signedCa(asCa(root), 'Intermediate Under Shallow Root');
            const twoDeep = await signedBy(asCa(intermediate), 'Two Deep');
            assert.equal(allowCA(root.cert)(chainOf(twoDeep.cert, intermediate.cert)), false);

            const direct = await signedBy(asCa(root), 'Direct');
            assert.equal(allowCA(root.cert)(pemToCertificate(direct.cert)), true);
        });

        it('should reject an intermediate whose keyUsage lacks keyCertSign', async () => {
            const signer = await selfsigned.generate([{ name: 'commonName', value: 'No CertSign' }], {
                algorithm: 'sha256',
                keySize: 2048,
                notBeforeDate: new Date(Date.now() - 60_000),
                ca: { key: pki.ca.key, cert: pki.ca.cert },
                extensions: [
                    { name: 'basicConstraints', cA: true, critical: true },
                    { name: 'keyUsage', digitalSignature: true, critical: true },
                ],
            });
            const leaf = await signedBy(asCa(signer), 'Leaf Of No CertSign');
            assert.equal(allowCA(pki.ca.cert)(chainOf(leaf.cert, signer.cert)), false);
        });

        it('should reject certificates carrying a critical extension it does not process', async () => {
            const unknownCritical = new x509.Extension('1.3.6.1.4.1.99999.1', true, new Uint8Array([0x05, 0x00]));
            const unknownNonCritical = new x509.Extension('1.3.6.1.4.1.99999.1', false, new Uint8Array([0x05, 0x00]));

            const leaf = await issueWithExtensions(pki.ca, 'Critical Leaf', [unknownCritical]);
            assert.equal(allowCA(pki.ca.cert)(pemToCertificate(leaf.cert)), false);

            const tolerated = await issueWithExtensions(pki.ca, 'Tolerated Leaf', [unknownNonCritical]);
            assert.equal(allowCA(pki.ca.cert)(pemToCertificate(tolerated.cert)), true);

            const intermediate = await issueWithExtensions(pki.ca, 'Critical Intermediate', [
                new x509.BasicConstraintsExtension(true, undefined, true),
                new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign, true),
                unknownCritical,
            ]);
            const underIntermediate = await signedBy(intermediate, 'Under Critical Intermediate');
            assert.equal(allowCA(pki.ca.cert)(chainOf(underIntermediate.cert, intermediate.cert)), false);

            const root = await issueWithExtensions(null, 'Critical Root', [unknownCritical]);
            assert.throws(() => allowCA(root.cert), /unsupported critical extension 1\.3\.6\.1\.4\.1\.99999\.1/);
        });

        it('should reject unprocessed extensions by OID when critical and tolerate them otherwise', async () => {
            const bodies = {
                // CertificatePolicies { PolicyInformation { anyPolicy } }
                '2.5.29.32': '300830060604551d2000',
                // CRLDistributionPoints { DistributionPoint { fullName { URI http://crl.test/ca.crl } } }
                '2.5.29.31': '301e301ca01aa0188616687474703a2f2f63726c2e746573742f63612e63726c',
                // IssuerAltName { URI http://ca.test }
                '2.5.29.18': '3010860e687474703a2f2f63612e74657374',
                // AuthorityInfoAccess { AccessDescription { id-ad-ocsp, URI http://ocsp.test } }
                '1.3.6.1.5.5.7.1.1': '301e301c06082b060105050730018610687474703a2f2f6f6373702e74657374',
            };
            for (const [oid, hex] of Object.entries(bodies)) {
                const value = Buffer.from(hex, 'hex');
                const rejected = await issueWithExtensions(pki.ca, `Critical ${oid}`, [new x509.Extension(oid, true, value)]);
                assert.equal(allowCA(pki.ca.cert)(pemToCertificate(rejected.cert)), false, oid);
                const tolerated = await issueWithExtensions(pki.ca, `Tolerated ${oid}`, [new x509.Extension(oid, false, value)]);
                assert.equal(allowCA(pki.ca.cert)(pemToCertificate(tolerated.cert)), true, oid);
            }

            const policyRoot = await issueWithExtensions(null, 'Policy Root', [
                new x509.BasicConstraintsExtension(true, undefined, true),
                new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign, true),
                new x509.Extension('2.5.29.32', true, Buffer.from(bodies['2.5.29.32'], 'hex')),
            ]);
            assert.throws(() => allowCA(policyRoot.cert), /unsupported critical extension 2\.5\.29\.32/);
        });

        it('should accept a leaf with an empty subject and a critical subjectAltName', async () => {
            const workload = await issueWithExtensions(pki.ca, '', [
                new x509.SubjectAlternativeNameExtension([{ type: 'url', value: 'spiffe://example.org/workload' }], true),
            ]);
            assert.equal(allowCA(pki.ca.cert)(pemToCertificate(workload.cert)), true);
        });

        it('should require clientAuth in the extended key usage of intermediates too', async () => {
            const caExtensions = (usage) => [
                new x509.BasicConstraintsExtension(true, undefined, true),
                new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign, true),
                new x509.ExtendedKeyUsageExtension([usage], true),
            ];
            const serverCa = await issueWithExtensions(pki.ca, 'Server CA', caExtensions(x509.ExtendedKeyUsage.serverAuth));
            const underServerCa = await signedBy(serverCa, 'Under Server CA');
            assert.equal(allowCA(pki.ca.cert)(chainOf(underServerCa.cert, serverCa.cert)), false);

            const clientCa = await issueWithExtensions(pki.ca, 'Client CA', caExtensions(x509.ExtendedKeyUsage.clientAuth));
            const underClientCa = await signedBy(clientCa, 'Under Client CA');
            assert.equal(allowCA(pki.ca.cert)(chainOf(underClientCa.cert, clientCa.cert)), true);
        });

        it('should require digitalSignature or keyAgreement in the leaf keyUsage when present', async () => {
            const encipherOnly = await issueWithExtensions(pki.ca, 'Encipher Leaf', [
                new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyEncipherment, true),
                new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.clientAuth]),
            ]);
            assert.equal(allowCA(pki.ca.cert)(pemToCertificate(encipherOnly.cert)), false);

            const agreement = await issueWithExtensions(pki.ca, 'Agreement Leaf', [
                new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyAgreement, true),
            ]);
            assert.equal(allowCA(pki.ca.cert)(pemToCertificate(agreement.cert)), true);
            assert.equal(allowCA(pki.ca.cert)(pemToCertificate(pki.client.cert)), true);
        });

        it('should reject anchors that are not CA certificates or do not permit clientAuth', async () => {
            assert.throws(() => allowCA(pki.client.cert), /is not usable as a CA certificate/);

            const serverRoot = await issueWithExtensions(null, 'Server Root', [
                new x509.BasicConstraintsExtension(true, undefined, true),
                new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign, true),
                new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.serverAuth], true),
            ]);
            assert.throws(() => allowCA(serverRoot.cert), /does not permit clientAuth/);
        });

        it('should not count self-issued rollover certificates toward pathLenConstraint', async () => {
            const root = await signedCa(null, 'Rollover Root', 1);
            const rollover = await signedCa(asCa(root), 'Rollover Root');
            const subCa = await signedCa(asCa(rollover), 'Rollover Sub CA');
            const leaf = await signedBy(asCa(subCa), 'Rollover Leaf');
            assert.equal(allowCA(root.cert)(chainOf(leaf.cert, subCa.cert, rollover.cert)), true);
        });

        it('should reject name constraints at any criticality', async () => {
            // NameConstraints { permittedSubtrees [0] { GeneralSubtree { dNSName "allowed.test" } } }
            const nameConstraints = Buffer.concat([Buffer.from([0x30, 0x12, 0xa0, 0x10, 0x30, 0x0e, 0x82, 0x0c]), Buffer.from('allowed.test')]);
            for (const critical of [false, true]) {
                const constrained = await issueWithExtensions(pki.ca, 'Constrained CA', [
                    new x509.BasicConstraintsExtension(true, undefined, true),
                    new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign, true),
                    new x509.Extension('2.5.29.30', critical, nameConstraints),
                ]);
                const leaf = await signedBy(constrained, 'evil.test');
                assert.equal(allowCA(pki.ca.cert)(chainOf(leaf.cert, constrained.cert)), false);
                const named = critical ? /unsupported critical extension 2\.5\.29\.30/ : /unsupported extension 2\.5\.29\.30/;
                assert.throws(() => allowCA(constrained.cert), named);
            }
        });

        it('should detect self-issued rollover certificates by canonical name', async () => {
            const root = await signedCa(null, 'rollover root', 1);
            const rollover = await signedCa(asCa(root), 'ROLLOVER  ROOT');
            const subCa = await signedCa(asCa(rollover), 'Rollover Sub CA 2');
            const leaf = await signedBy(asCa(subCa), 'Rollover Leaf 2');
            assert.equal(allowCA(root.cert)(chainOf(leaf.cert, subCa.cert, rollover.cert)), true);
        });

        it('should throw at construction when maxDepth is not a positive integer', () => {
            for (const maxDepth of [0, -1, 1.5, 'ten', Infinity]) {
                assert.throws(() => allowCA(pki.ca.cert, { maxDepth }), /maxDepth must be a positive integer/);
            }
        });

        it('should reject a chain whose link does not verify', () => {
            const leaf = pemToCertificate(chain.client.cert);
            leaf.issuerCertificate = pemToCertificate(lookalike.ca.cert);
            assert.equal(allowCA([pki.ca.cert, lookalike.ca.cert])(leaf), false);
        });

        it('should stop at a self-referencing root', () => {
            const cert = pemToCertificate(selfSigned.cert);
            cert.issuerCertificate = cert;
            assert.equal(allowCA(pki.ca.cert)(cert), false);
        });

        it('should reject expired and not-yet-valid certificates', () => {
            assert.equal(allowCA(pki.ca.cert)(pemToCertificate(expired.cert)), false);
            assert.equal(allowCA(pki.ca.cert)(pemToCertificate(notYetValid.cert)), false);
        });

        it('should reject a certificate issued by an expired CA', () => {
            assert.equal(allowCA(expiredCa.ca.cert)(pemToCertificate(expiredCa.client.cert)), false);
        });

        it('should stop walking at maxDepth', () => {
            const leaf = pemToCertificate(chain.client.cert);
            leaf.issuerCertificate = pemToCertificate(chain.intermediate.cert);
            assert.equal(allowCA(pki.ca.cert, { maxDepth: 1 })(leaf), false);
            assert.equal(allowCA(pki.ca.cert, { maxDepth: 2 })(leaf), true);
        });

        it('should reject certificates without parseable raw bytes', () => {
            const check = allowCA(pki.ca.cert);
            assert.equal(check({ subject: { CN: 'no raw' } }), false);
            assert.equal(check({ raw: Buffer.from('not a certificate') }), false);

            const leaf = pemToCertificate(chain.client.cert);
            leaf.issuerCertificate = { subject: { CN: 'no raw' } };
            assert.equal(check(leaf), false);
        });

        it('should return false with an empty CA list', () => {
            assert.equal(allowCA([])(pemToCertificate(pki.client.cert)), false);
        });

        it('should trust every certificate in a PEM bundle', async () => {
            const second = await generateMtlsCertificates({ caCommonName: 'Bundled CA' });
            const bundle = `${pki.ca.cert}\n${second.ca.cert}`;
            for (const input of [bundle, Buffer.from(bundle)]) {
                const check = allowCA(input);
                assert.equal(check(pemToCertificate(pki.client.cert)), true);
                assert.equal(check(pemToCertificate(second.client.cert)), true);
            }

            // The first block alone must not vouch for the second CA's client.
            assert.equal(allowCA(pki.ca.cert)(pemToCertificate(second.client.cert)), false);
        });

        it('should throw on a bundle whose PEM blocks it cannot split', async () => {
            const second = await generateMtlsCertificates({ caCommonName: 'Trusted Label CA' });
            const trust = (pem) => pem.replace(/BEGIN CERTIFICATE/g, 'BEGIN TRUSTED CERTIFICATE').replace(/END CERTIFICATE/g, 'END TRUSTED CERTIFICATE');
            const bundle = `${trust(pki.ca.cert)}\n${trust(second.ca.cert)}`;
            assert.throws(() => allowCA(bundle), /could not split this PEM bundle/);

            // A single unrecognized block still reaches X509Certificate intact.
            assert.equal(allowCA(trust(pki.ca.cert))(pemToCertificate(pki.client.cert)), true);

            // A bundle mixing recognized and unrecognized labels must not drop
            // the unrecognized one.
            assert.throws(
                () => allowCA(`${pki.ca.cert}\n${trust(second.ca.cert)}`),
                /could not split this PEM bundle/
            );
        });

        it('should name keyUsage when an anchor carries cA without keyCertSign', async () => {
            const noCertSign = await issueWithExtensions(null, 'No CertSign Root', [
                new x509.BasicConstraintsExtension(true, undefined, true),
                new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
            ]);
            assert.throws(() => allowCA(noCertSign.cert), /needs basicConstraints cA, and keyCertSign where keyUsage is present/);
        });

        it('should reject a chain through an expired or not-yet-valid intermediate', async () => {
            const intermediateAt = (dates) => selfsigned.generate([{ name: 'commonName', value: 'Dated Intermediate' }], {
                algorithm: 'sha256',
                keySize: 2048,
                ca: { key: pki.ca.key, cert: pki.ca.cert },
                ...dates,
                extensions: [
                    { name: 'basicConstraints', cA: true, critical: true },
                    { name: 'keyUsage', keyCertSign: true, cRLSign: true, critical: true },
                ],
            });

            const current = await intermediateAt({ notBeforeDate: new Date(Date.now() - 60_000) });
            const live = await signedBy(asCa(current), 'Leaf Of Current Intermediate');
            assert.equal(allowCA(pki.ca.cert)(chainOf(live.cert, current.cert)), true);

            // The leaf stays valid; only the intermediate's window moves.
            const stale = await intermediateAt({ notBeforeDate: new Date(Date.now() - 2 * day), notAfterDate: new Date(Date.now() - day) });
            const underStale = await signedBy(asCa(stale), 'Leaf Of Stale Intermediate');
            assert.equal(allowCA(pki.ca.cert)(chainOf(underStale.cert, stale.cert)), false);

            const future = await intermediateAt({ notBeforeDate: new Date(Date.now() + day), notAfterDate: new Date(Date.now() + 2 * day) });
            const underFuture = await signedBy(asCa(future), 'Leaf Of Future Intermediate');
            assert.equal(allowCA(pki.ca.cert)(chainOf(underFuture.cert, future.cert)), false);
        });

        it('should throw at construction when a CA certificate cannot be parsed', () => {
            assert.throws(() => allowCA('not a certificate'));
        });
    });

    describe('allOf', () => {
        it('should return true when all callbacks return true', async () => {
            const check = allOf(
                allowCN(['test-client']),
                allowOU(['Engineering'])
            );
            assert.equal(await check(mockCert), true);
        });

        it('should return false when any callback returns false', async () => {
            const check = allOf(
                allowCN(['test-client']),
                allowOU(['Sales'])
            );
            assert.equal(await check(mockCert), false);
        });

        it('should handle async callbacks', async () => {
            const asyncTrue = async () => true;
            const check = allOf(allowCN(['test-client']), asyncTrue);
            assert.equal(await check(mockCert), true);
        });

        it('should return false when async callback returns false', async () => {
            const asyncFalse = async () => false;
            const check = allOf(allowCN(['test-client']), asyncFalse);
            assert.equal(await check(mockCert), false);
        });

        it('should forward req to sub-callbacks', async () => {
            const mockReq = { url: '/test' };
            const reqChecker = (cert, req) => {
                assert.strictEqual(req, mockReq);
                return cert.subject.CN === 'test-client';
            };
            const check = allOf(allowCN(['test-client']), reqChecker);
            assert.equal(await check(mockCert, mockReq), true);
        });

        it('should return false with zero callbacks (fail closed)', async () => {
            const check = allOf();
            assert.equal(await check(mockCert), false);
        });

        it('should return false when callback returns truthy non-boolean value', async () => {
            const check = allOf(() => 'yes');
            assert.equal(await check(mockCert), false);
        });
    });

    describe('anyOf', () => {
        it('should return true when at least one callback returns true', async () => {
            const check = anyOf(
                allowCN(['other-client']),
                allowOU(['Engineering'])
            );
            assert.equal(await check(mockCert), true);
        });

        it('should return false when all callbacks return false', async () => {
            const check = anyOf(
                allowCN(['other-client']),
                allowOU(['Sales'])
            );
            assert.equal(await check(mockCert), false);
        });

        it('should handle async callbacks', async () => {
            const asyncTrue = async () => true;
            const check = anyOf(allowCN(['other']), asyncTrue);
            assert.equal(await check(mockCert), true);
        });

        it('should return true when first passes, others async', async () => {
            const asyncFalse = async () => false;
            const check = anyOf(allowCN(['test-client']), asyncFalse);
            assert.equal(await check(mockCert), true);
        });

        it('should forward req to sub-callbacks', async () => {
            const mockReq = { url: '/test' };
            const reqChecker = (cert, req) => {
                assert.strictEqual(req, mockReq);
                return cert.subject.CN === 'test-client';
            };
            const check = anyOf(allowCN(['other-client']), reqChecker);
            assert.equal(await check(mockCert, mockReq), true);
        });

        it('should return false with zero callbacks (no match possible)', async () => {
            const check = anyOf();
            assert.equal(await check(mockCert), false);
        });

        it('should return false when callback returns truthy non-boolean value', async () => {
            const check = anyOf(() => 'yes');
            assert.equal(await check(mockCert), false);
        });
    });
});
