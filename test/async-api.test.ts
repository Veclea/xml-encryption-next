import { describe, it, expect } from 'vitest';
import { encrypt, decrypt } from '../lib/index.js';
import forge from 'node-forge';

// ============================================================================
// 测试工具函数
// ============================================================================

function generateTestKeys() {
    const keys = forge.pki.rsa.generateKeyPair(2048);
    return {
        publicKey: forge.pki.publicKeyToPem(keys.publicKey),
        privateKey: forge.pki.privateKeyToPem(keys.privateKey),
        certificate: (() => {
            const cert = forge.pki.createCertificate();
            cert.publicKey = keys.publicKey;
            cert.serialNumber = '01';
            cert.validity.notBefore = new Date();
            cert.validity.notAfter = new Date();
            cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
            const attrs = [{ name: 'commonName', value: 'test' }];
            cert.setSubject(attrs);
            cert.setIssuer(attrs);
            cert.sign(keys.privateKey);
            return forge.pki.certificateToPem(cert);
        })()
    };
}

const testKeys = generateTestKeys();
const TEST_CONTENT = 'Test content for async/await API';

// ============================================================================
// Async/Await API 测试
// ============================================================================

describe('Async/Await API Tests', () => {
    const baseOptions = {
        rsa_pub: testKeys.publicKey,
        pem: testKeys.certificate,
        keyEncryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#rsa-oaep',
        keyEncryptionDigest: 'sha256',
        keyEncryptionMgf1: 'sha256',
        encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes128-gcm',
        key: testKeys.privateKey
    };

    describe('encrypt async/await', () => {
        it('should encrypt with async/await', async () => {
            const encryptedXml = await encrypt(TEST_CONTENT, baseOptions);
            expect(encryptedXml).toBeDefined();
            expect(typeof encryptedXml).toBe('string');
            expect(encryptedXml).toContain('<xenc:EncryptedData');
        });

        it('should encrypt and decrypt with async/await', async () => {
            const encryptedXml = await encrypt(TEST_CONTENT, baseOptions);
            const decrypted = await decrypt(encryptedXml, baseOptions);
            expect(decrypted.toString('utf8')).toBe(TEST_CONTENT);
        });

        it('should handle errors with async/await', async () => {
            await expect(encrypt(null, baseOptions)).rejects.toThrow('must provide content to encrypt');
        });

        it('should handle decrypt errors with async/await', async () => {
            await expect(decrypt('', baseOptions)).rejects.toThrow('must provide XML to decrypt');
        });

        it('should work with different algorithms using async/await', async () => {
            const algorithms = [
                'http://www.w3.org/2009/xmlenc11#aes128-gcm',
                'http://www.w3.org/2009/xmlenc11#aes256-gcm',
                'http://www.w3.org/2001/04/xmlenc#aes128-cbc'
            ];

            for (const alg of algorithms) {
                const options = { ...baseOptions, encryptionAlgorithm: alg };
                const encrypted = await encrypt(TEST_CONTENT, options);
                const decrypted = await decrypt(encrypted, options);
                expect(decrypted.toString('utf8')).toBe(TEST_CONTENT);
            }
        });

        it('should work with RSA-1_5 using async/await', async () => {
            const options = {
                rsa_pub: testKeys.publicKey,
                pem: testKeys.certificate,
                keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5',
                encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes128-gcm',
                key: testKeys.privateKey
            };

            const encrypted = await encrypt(TEST_CONTENT, options);
            const decrypted = await decrypt(encrypted, options);
            expect(decrypted.toString('utf8')).toBe(TEST_CONTENT);
        });

        it('should work with RSA-OAEP-MGF1P using async/await', async () => {
            const options = {
                rsa_pub: testKeys.publicKey,
                pem: testKeys.certificate,
                keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
                keyEncryptionDigest: 'sha256',
                encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes128-gcm',
                key: testKeys.privateKey
            };

            const encrypted = await encrypt(TEST_CONTENT, options);
            const decrypted = await decrypt(encrypted, options);
            expect(decrypted.toString('utf8')).toBe(TEST_CONTENT);
        });

        it('should handle large content with async/await', async () => {
            const largeContent = 'A'.repeat(100000);
            const encrypted = await encrypt(largeContent, baseOptions);
            const decrypted = await decrypt(encrypted, baseOptions);
            expect(decrypted.toString('utf8')).toBe(largeContent);
        });

        it('should handle unicode content with async/await', async () => {
            const unicodeContent = '测试中文内容 🚀 特殊字符：@#$%^&*()';
            const encrypted = await encrypt(unicodeContent, baseOptions);
            const decrypted = await decrypt(encrypted, baseOptions);
            expect(decrypted.toString('utf8')).toBe(unicodeContent);
        });
    });

    describe('encrypt with callback (backward compatibility)', () => {
        it('should encrypt with callback', () => {
            return new Promise((resolve, reject) => {
                encrypt(TEST_CONTENT, baseOptions, (err, result) => {
                    if (err) reject(err);
                    expect(result).toBeDefined();
                    expect(result).toContain('<xenc:EncryptedData');
                    resolve();
                });
            });
        });

        it('should encrypt and decrypt with callback', () => {
            return new Promise((resolve, reject) => {
                encrypt(TEST_CONTENT, baseOptions, (err, encryptedXml) => {
                    if (err) reject(err);
                    decrypt(encryptedXml, baseOptions, (decryptErr, decrypted) => {
                        if (decryptErr) reject(decryptErr);
                        expect(decrypted.toString('utf8')).toBe(TEST_CONTENT);
                        resolve();
                    });
                });
            });
        });

        it('should handle errors with callback', () => {
            return new Promise((resolve) => {
                encrypt(null, baseOptions, (err) => {
                    expect(err).toBeDefined();
                    expect(err.message).toContain('must provide content to encrypt');
                    resolve();
                });
            });
        });
    });

    describe('mixed callback and Promise usage', () => {
        it('should use Promise without callback', async () => {
            const result = encrypt(TEST_CONTENT, baseOptions);
            expect(result).toBeInstanceOf(Promise);
            const encrypted = await result;
            expect(encrypted).toBeDefined();
        });

        it('should use callback when provided', () => {
            return new Promise((resolve, reject) => {
                const result = encrypt(TEST_CONTENT, baseOptions, (err, res) => {
                    if (err) reject(err);
                    expect(res).toBeDefined();
                    resolve();
                });
                expect(result).toBeUndefined(); // 有回调时返回 undefined
            });
        });
    });

    describe('security policy with async/await', () => {
        it('should reject insecure algorithm with async/await', async () => {
            const options = {
                rsa_pub: testKeys.publicKey,
                pem: testKeys.certificate,
                keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5',
                encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc',
                disallowInsecureEncryption: true,
                key: testKeys.privateKey
            };

            await expect(encrypt(TEST_CONTENT, options)).rejects.toThrow('AES-CBC encryption algorithm is not secure');
        });

        it('should reject insecure hash with async/await', async () => {
            const options = {
                rsa_pub: testKeys.publicKey,
                pem: testKeys.certificate,
                keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
                keyEncryptionDigest: 'sha1',
                encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes128-gcm',
                disallowInsecureHash: true,
                key: testKeys.privateKey
            };

            await expect(encrypt(TEST_CONTENT, options)).rejects.toThrow('SHA-1 hash algorithm is not secure');
        });
    });
});

// ============================================================================
// 性能对比测试 (仅供参考)
// ============================================================================

describe('Performance Tests (informational)', () => {
    const options = {
        rsa_pub: testKeys.publicKey,
        pem: testKeys.certificate,
        keyEncryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#rsa-oaep',
        keyEncryptionDigest: 'sha256',
        keyEncryptionMgf1: 'sha256',
        encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes128-gcm',
        key: testKeys.privateKey
    };

    it('should complete encryption/decryption in reasonable time (async)', async () => {
        const startTime = Date.now();
        const encrypted = await encrypt(TEST_CONTENT, options);
        const decrypted = await decrypt(encrypted, options);
        const endTime = Date.now();

        expect(decrypted.toString('utf8')).toBe(TEST_CONTENT);
        expect(endTime - startTime).toBeLessThan(1000); // 应在 1 秒内完成
        console.log(`Async encryption/decryption took ${endTime - startTime}ms`);
    });

    it('should complete encryption/decryption in reasonable time (callback)', () => {
        return new Promise((resolve, reject) => {
            const startTime = Date.now();
            encrypt(TEST_CONTENT, options, (err, encrypted) => {
                if (err) reject(err);
                decrypt(encrypted, options, (decryptErr, decrypted) => {
                    if (decryptErr) reject(decryptErr);
                    expect(decrypted.toString('utf8')).toBe(TEST_CONTENT);
                    const endTime = Date.now();
                    console.log(`Callback encryption/decryption took ${endTime - startTime}ms`);
                    resolve();
                });
            });
        });
    });
});
