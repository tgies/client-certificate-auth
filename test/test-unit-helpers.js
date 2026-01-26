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
    serialNumber: '01:23:45:67:89:AB:CD:EF',
    subjectaltname: 'DNS:test.example.com, email:alt@example.com, URI:https://example.com',
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
    });

    describe('allowFingerprints', () => {
        it('should match raw fingerprint', () => {
            const check = allowFingerprints(['AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01']);
            assert.equal(check(mockCert), true);
        });

        it('should match fingerprint with SHA256 prefix', () => {
            const check = allowFingerprints(['SHA256:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01']);
            assert.equal(check(mockCert), true);
        });

        it('should be case-insensitive', () => {
            const check = allowFingerprints(['ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01']);
            assert.equal(check(mockCert), true);
        });

        it('should return false when fingerprint does not match', () => {
            const check = allowFingerprints(['00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00']);
            assert.equal(check(mockCert), false);
        });

        it('should handle missing fingerprint gracefully', () => {
            const check = allowFingerprints(['AB:CD']);
            assert.equal(check({}), false);
        });

        it('should match when cert has lowercase fingerprint and allowed has uppercase', () => {
            const certLowerFp = { fingerprint: 'ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01' };
            const check = allowFingerprints(['AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01']);
            assert.equal(check(certLowerFp), true);
        });

        it('should match when both have mixed case', () => {
            const certMixedFp = { fingerprint: 'Ab:Cd:Ef:01:23:45:67:89:aB:cD:eF:01:23:45:67:89:AB:cd:EF:01' };
            const check = allowFingerprints(['ab:cd:ef:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:ab:cd:ef:01']);
            assert.equal(check(certMixedFp), true);
        });

        it('should correctly remove SHA256: prefix regardless of case', () => {
            const check = allowFingerprints(['sha256:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01']);
            assert.equal(check(mockCert), true);
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

        it('should handle cert with only SAN email', () => {
            const certOnlySAN = { subjectaltname: 'email:only@example.com' };
            const check = allowEmail(['only@example.com']);
            assert.equal(check(certOnlySAN), true);
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
    });
});
