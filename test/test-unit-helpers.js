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
    allOf,
    anyOf,
} from '../lib/helpers.js';

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

        it('should match value-only for SAN with short type prefix', () => {
            // Kills UnaryOperator mutation: colonIdx !== -1 → colonIdx !== +1
            // IP: has colon at index 2, but a synthetic 1-char prefix has colon at index 1
            const cert = { subjectaltname: 'X:short-prefix-value' };
            const check = allowSAN(['short-prefix-value']);
            assert.equal(check(cert), true);
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
            // With startsWith mutation (→ true), "URI:x:me@test.com".slice(6) would be "me@test.com" → false positive
            const cert = { subjectaltname: 'URI:x:me@test.com' };
            assert.equal(allowEmail(['me@test.com'])(cert), false);
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

        it('should return true with zero callbacks (vacuous truth)', async () => {
            const check = allOf();
            assert.equal(await check(mockCert), true);
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
