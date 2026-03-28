import { describe, it, expect, beforeAll } from 'vitest';
import { encrypt, decrypt } from '../lib/index.js';
import forge from 'node-forge';

// ============================================================================
// 测试工具函数
// ============================================================================

/**
 * 生成测试用的 RSA 密钥对和证书
 * @returns {Object} 包含公钥、私钥和证书的测试密钥对象
 */
function generateTestKeys() {
    const keys = forge.pki.rsa.generateKeyPair(2048);
    const publicKeyPem = forge.pki.publicKeyToPem(keys.publicKey);
    const privateKeyPem = forge.pki.privateKeyToPem(keys.privateKey);
    
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
    
    const certPem = forge.pki.certificateToPem(cert);

    return {
        publicKey: publicKeyPem,
        privateKey: privateKeyPem,
        certificate: certPem
    };
}

// 生成测试密钥
const testKeys = generateTestKeys();

// 测试内容常量
const TEST_CONTENT = 'This is a test content for XML encryption';
const TEST_CONTENT_UNICODE = '测试中文内容 🚀 特殊字符：@#$%^&*()';
const TEST_CONTENT_LARGE = 'A'.repeat(10000) + '测试大数据' + 'B'.repeat(10000);

// ============================================================================
// RSA 1.5 加密算法测试 (XML Encryption 1.0)
// ============================================================================

describe('RSA-1_5 Encryption Algorithm Tests (XML Enc 1.0)', () => {
    const baseOptions = {
        rsa_pub: testKeys.publicKey,
        pem: testKeys.certificate,
        keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5',
        key: testKeys.privateKey
    };

    it('should encrypt and decrypt with rsa-1_5 and aes-128-cbc', async () => {
        const options = {
            ...baseOptions,
            encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc'
        };

        const encryptedXml = await runEncrypt(TEST_CONTENT, options);
        const decryptedContent = await runDecrypt(encryptedXml, options);
        
        expect(decryptedContent).toBe(TEST_CONTENT);
    });

    it('should encrypt and decrypt with rsa-1_5 and aes-256-gcm', async () => {
        const options = {
            ...baseOptions,
            encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes256-gcm'
        };

        const encryptedXml = await runEncrypt(TEST_CONTENT, options);
        const decryptedContent = await runDecrypt(encryptedXml, options);
        
        expect(decryptedContent).toBe(TEST_CONTENT);
    });

    it('should handle unicode content with rsa-1_5', async () => {
        const options = {
            ...baseOptions,
            encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes128-gcm'
        };

        const encryptedXml = await runEncrypt(TEST_CONTENT_UNICODE, options);
        const decryptedContent = await runDecrypt(encryptedXml, options);
        
        expect(decryptedContent).toBe(TEST_CONTENT_UNICODE);
    });

    it('should handle large content with rsa-1_5', async () => {
        const options = {
            ...baseOptions,
            encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes256-cbc'
        };

        const encryptedXml = await runEncrypt(TEST_CONTENT_LARGE, options);
        const decryptedContent = await runDecrypt(encryptedXml, options);
        
        expect(decryptedContent).toBe(TEST_CONTENT_LARGE);
    });
});

// ============================================================================
// RSA-OAEP-MGF1P 加密算法测试 (XML Encryption 1.0)
// ============================================================================

describe('RSA-OAEP-MGF1P Encryption Algorithm Tests (XML Enc 1.0)', () => {
    const baseOptions = {
        rsa_pub: testKeys.publicKey,
        pem: testKeys.certificate,
        keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
        key: testKeys.privateKey
    };

    const oaepHashes = ['sha1', 'sha256', 'sha384', 'sha512'];

    oaepHashes.forEach((hash) => {
        it(`should encrypt and decrypt with rsa-oaep-mgf1p using ${hash} digest`, async () => {
            const options = {
                ...baseOptions,
                keyEncryptionDigest: hash,
                encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc'
            };

            const encryptedXml = await runEncrypt(TEST_CONTENT, options);
            const decryptedContent = await runDecrypt(encryptedXml, options);
            
            expect(decryptedContent).toBe(TEST_CONTENT);
        });
    });

    it('should use default sha256 digest when not specified', async () => {
        const options = {
            ...baseOptions,
            encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes128-gcm'
            // keyEncryptionDigest 不指定，默认 sha256
        };

        const encryptedXml = await runEncrypt(TEST_CONTENT, options);
        const decryptedContent = await runDecrypt(encryptedXml, options);
        
        expect(decryptedContent).toBe(TEST_CONTENT);
    });

    it('should fail with unsupported hash algorithm', async () => {
        const options = {
            ...baseOptions,
            keyEncryptionDigest: 'sha224', // 不支持
            encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc'
        };

        await expect(runEncrypt(TEST_CONTENT, options)).rejects.toThrow('Unsupported OAEP hash');
    });
});

// ============================================================================
// RSA-OAEP 加密算法测试 (XML Encryption 1.1)
// ============================================================================

describe('RSA-OAEP Encryption Algorithm Tests (XML Enc 1.1)', () => {
    const baseOptions = {
        rsa_pub: testKeys.publicKey,
        pem: testKeys.certificate,
        keyEncryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#rsa-oaep',
        key: testKeys.privateKey
    };

    const oaepHashes = ['sha1', 'sha256', 'sha384', 'sha512'];
    const mgfHashes = ['sha1', 'sha256', 'sha384', 'sha512'];

    // 测试所有 OAEP 和 MGF1 组合
    oaepHashes.forEach((oaepHash) => {
        mgfHashes.forEach((mgfHash) => {
            it(`should encrypt and decrypt with ${oaepHash} OAEP and ${mgfHash} MGF1`, async () => {
                const options = {
                    ...baseOptions,
                    keyEncryptionDigest: oaepHash,
                    keyEncryptionMgf1: mgfHash,
                    encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes128-gcm'
                };

                const encryptedXml = await runEncrypt(TEST_CONTENT, options);
                const decryptedContent = await runDecrypt(encryptedXml, options);
                
                expect(decryptedContent).toBe(TEST_CONTENT);
            });
        });
    });

    it('should use default sha256 for both OAEP and MGF1 when not specified', async () => {
        const options = {
            ...baseOptions,
            encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes256-gcm'
        };

        const encryptedXml = await runEncrypt(TEST_CONTENT, options);
        const decryptedContent = await runDecrypt(encryptedXml, options);
        
        expect(decryptedContent).toBe(TEST_CONTENT);
    });

    it('should fail with unsupported OAEP hash', async () => {
        const options = {
            ...baseOptions,
            keyEncryptionDigest: 'sha224',
            keyEncryptionMgf1: 'sha256',
            encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc'
        };

        await expect(runEncrypt(TEST_CONTENT, options)).rejects.toThrow('Unsupported OAEP hash');
    });

    it('should fail with unsupported MGF1 hash', async () => {
        const options = {
            ...baseOptions,
            keyEncryptionDigest: 'sha256',
            keyEncryptionMgf1: 'sha224',
            encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc'
        };

        await expect(runEncrypt(TEST_CONTENT, options)).rejects.toThrow('Unsupported MGF1 hash');
    });
});

// ============================================================================
// AES 加密算法组合测试
// ============================================================================

describe('AES Encryption Algorithm Tests', () => {
    const aesAlgorithms = [
        { 
            name: 'AES-128-CBC', 
            uri: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc',
            isInsecure: true
        },
        { 
            name: 'AES-192-CBC', 
            uri: 'http://www.w3.org/2001/04/xmlenc#aes192-cbc',
            isInsecure: true
        },
        { 
            name: 'AES-256-CBC', 
            uri: 'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
            isInsecure: true
        },
        { 
            name: 'AES-128-GCM', 
            uri: 'http://www.w3.org/2009/xmlenc11#aes128-gcm',
            isInsecure: false
        },
        { 
            name: 'AES-192-GCM', 
            uri: 'http://www.w3.org/2009/xmlenc11#aes192-gcm',
            isInsecure: false
        },
        { 
            name: 'AES-256-GCM', 
            uri: 'http://www.w3.org/2009/xmlenc11#aes256-gcm',
            isInsecure: false
        }
    ];

    const rsaAlgorithm = 'http://www.w3.org/2009/xmlenc11#rsa-oaep';

    aesAlgorithms.forEach((aesAlg) => {
        it(`should encrypt and decrypt with ${aesAlg.name}`, async () => {
            const options = {
                rsa_pub: testKeys.publicKey,
                pem: testKeys.certificate,
                keyEncryptionAlgorithm: rsaAlgorithm,
                keyEncryptionDigest: 'sha256',
                keyEncryptionMgf1: 'sha256',
                encryptionAlgorithm: aesAlg.uri,
                key: testKeys.privateKey
            };

            const encryptedXml = await runEncrypt(TEST_CONTENT, options);
            const decryptedContent = await runDecrypt(encryptedXml, options);
            
            expect(decryptedContent).toBe(TEST_CONTENT);
        });
    });

    // 3DES 测试 (不安全算法)
    it('should encrypt and decrypt with 3DES-CBC (with warning)', async () => {
        const options = {
            rsa_pub: testKeys.publicKey,
            pem: testKeys.certificate,
            keyEncryptionAlgorithm: rsaAlgorithm,
            encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc',
            key: testKeys.privateKey,
            warnInsecureAlgorithm: true
        };

        const encryptedXml = await runEncrypt(TEST_CONTENT, options);
        const decryptedContent = await runDecrypt(encryptedXml, options);
        
        expect(decryptedContent).toBe(TEST_CONTENT);
    });
});

// ============================================================================
// 错误处理测试
// ============================================================================

describe('Error Handling Tests', () => {
    it('should fail when options is missing', async () => {
        await expect(runEncrypt(TEST_CONTENT, undefined))
            .rejects.toThrow('must provide options');
    });

    it('should fail when content is null', async () => {
        const options = {
            rsa_pub: testKeys.publicKey,
            pem: testKeys.certificate,
            keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5'
        };

        await expect(runEncrypt(null, options))
            .rejects.toThrow('must provide content to encrypt');
    });

    it('should fail when rsa_pub is missing', async () => {
        const options = {
            pem: testKeys.certificate,
            keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5'
        };

        await expect(runEncrypt(TEST_CONTENT, options))
            .rejects.toThrow('rsa_pub option is mandatory');
    });

    it('should fail when pem is missing', async () => {
        const options = {
            rsa_pub: testKeys.publicKey,
            keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5'
        };

        await expect(runEncrypt(TEST_CONTENT, options))
            .rejects.toThrow('pem option is mandatory');
    });

    it('should fail when keyEncryptionAlgorithm is missing', async () => {
        const options = {
            rsa_pub: testKeys.publicKey,
            pem: testKeys.certificate,
            encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc' // 需要提供 encryptionAlgorithm 才能触发正确错误
        };

        // 当缺少 keyEncryptionAlgorithm 时，会在 encryptKeyInfo 中抛出错误
        await expect(runEncrypt(TEST_CONTENT, options))
            .rejects.toThrow();
    });

    it('should fail with unsupported encryption algorithm', async () => {
        const options = {
            rsa_pub: testKeys.publicKey,
            pem: testKeys.certificate,
            keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5',
            encryptionAlgorithm: 'http://example.com/unsupported-algorithm'
        };

        await expect(runEncrypt(TEST_CONTENT, options))
            .rejects.toThrow('unsupported encryption algorithm');
    });

    it('should fail with unsupported key encryption algorithm', async () => {
        const options = {
            rsa_pub: testKeys.publicKey,
            pem: testKeys.certificate,
            keyEncryptionAlgorithm: 'http://example.com/unsupported',
            encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc'
        };

        await expect(runEncrypt(TEST_CONTENT, options))
            .rejects.toThrow('encryption key algorithm not supported');
    });

    it('should fail during decryption when key is missing', async () => {
        const encryptOptions = {
            rsa_pub: testKeys.publicKey,
            pem: testKeys.certificate,
            keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5',
            encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc'
        };

        const encryptedXml = await runEncrypt(TEST_CONTENT, encryptOptions);
        
        const decryptOptions = { ...encryptOptions };
        delete decryptOptions.key;

        await expect(runDecrypt(encryptedXml, decryptOptions))
            .rejects.toThrow('key option is mandatory');
    });

    it('should fail when XML is empty', async () => {
        const options = {
            key: testKeys.privateKey
        };

        await expect(runDecrypt('', options))
            .rejects.toThrow('must provide XML to decrypt');
    });

    it('should fail when XML is invalid', async () => {
        const options = {
            key: testKeys.privateKey
        };

        await expect(runDecrypt('not valid xml', options))
            .rejects.toThrow();
    });
});

// ============================================================================
// 不安全算法安全策略测试
// ============================================================================

describe('Security Policy Tests - Insecure Algorithms', () => {
    it('should allow insecure algorithms when disallowEncryptionWithInsecureAlgorithm is false', async () => {
        const options = {
            rsa_pub: testKeys.publicKey,
            pem: testKeys.certificate,
            keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5',
            encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc',
            disallowEncryptionWithInsecureAlgorithm: false,
            key: testKeys.privateKey
        };

        const encryptedXml = await runEncrypt(TEST_CONTENT, options);
        const decryptedContent = await runDecrypt(encryptedXml, options);
        
        expect(decryptedContent).toBe(TEST_CONTENT);
    });

    it('should reject insecure key encryption algorithm when disallowEncryptionWithInsecureAlgorithm is true', async () => {
        const options = {
            rsa_pub: testKeys.publicKey,
            pem: testKeys.certificate,
            keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5',
            encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes128-gcm',
            disallowEncryptionWithInsecureAlgorithm: true,
            key: testKeys.privateKey
        };

        await expect(runEncrypt(TEST_CONTENT, options))
            .rejects.toThrow('is not secure');
    });

    it('should reject insecure content encryption algorithm when disallowEncryptionWithInsecureAlgorithm is true', async () => {
        const options = {
            rsa_pub: testKeys.publicKey,
            pem: testKeys.certificate,
            keyEncryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#rsa-oaep',
            encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc',
            disallowEncryptionWithInsecureAlgorithm: true,
            key: testKeys.privateKey
        };

        await expect(runEncrypt(TEST_CONTENT, options))
            .rejects.toThrow('is not secure');
    });

    it('should reject insecure algorithm during decryption when disallowDecryptionWithInsecureAlgorithm is true', async () => {
        const encryptOptions = {
            rsa_pub: testKeys.publicKey,
            pem: testKeys.certificate,
            keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5',
            encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc',
            disallowEncryptionWithInsecureAlgorithm: false,
            key: testKeys.privateKey // 需要私钥
        };

        const encryptedXml = await runEncrypt(TEST_CONTENT, encryptOptions);
        
        const decryptOptions = {
            ...encryptOptions,
            disallowDecryptionWithInsecureAlgorithm: true
        };

        await expect(runDecrypt(encryptedXml, decryptOptions))
            .rejects.toThrow('is not secure, fail to decrypt');
    });
});

// ============================================================================
// 不安全哈希算法安全策略测试
// ============================================================================

describe('Security Policy Tests - Insecure Hash Algorithms', () => {
    it('should allow SHA-1 when disallowInsecureHash is false', async () => {
        const options = {
            rsa_pub: testKeys.publicKey,
            pem: testKeys.certificate,
            keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
            keyEncryptionDigest: 'sha1',
            encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc',
            disallowInsecureHash: false,
            key: testKeys.privateKey
        };

        const encryptedXml = await runEncrypt(TEST_CONTENT, options);
        const decryptedContent = await runDecrypt(encryptedXml, options);
        
        expect(decryptedContent).toBe(TEST_CONTENT);
    });

    it('should reject SHA-1 during encryption when disallowInsecureHash is true', async () => {
        const options = {
            rsa_pub: testKeys.publicKey,
            pem: testKeys.certificate,
            keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
            keyEncryptionDigest: 'sha1',
            encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc',
            disallowInsecureHash: true,
            key: testKeys.privateKey
        };

        await expect(runEncrypt(TEST_CONTENT, options))
            .rejects.toThrow('SHA-1 hash algorithm is not secure and has been disabled');
    });

    it('should allow SHA-256 when disallowInsecureHash is true', async () => {
        const options = {
            rsa_pub: testKeys.publicKey,
            pem: testKeys.certificate,
            keyEncryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#rsa-oaep',
            keyEncryptionDigest: 'sha256',
            keyEncryptionMgf1: 'sha256',
            encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes128-gcm',
            disallowInsecureHash: true,
            key: testKeys.privateKey
        };

        const encryptedXml = await runEncrypt(TEST_CONTENT, options);
        const decryptedContent = await runDecrypt(encryptedXml, options);
        
        expect(decryptedContent).toBe(TEST_CONTENT);
    });

    it('should reject SHA-1 during decryption when disallowInsecureHash is true', async () => {
        const encryptOptions = {
            rsa_pub: testKeys.publicKey,
            pem: testKeys.certificate,
            keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
            keyEncryptionDigest: 'sha1',
            encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc',
            disallowInsecureHash: false,
            key: testKeys.privateKey // 需要私钥
        };

        const encryptedXml = await runEncrypt(TEST_CONTENT, encryptOptions);
        
        const decryptOptions = {
            ...encryptOptions,
            disallowInsecureHash: true
        };

        await expect(runDecrypt(encryptedXml, decryptOptions))
            .rejects.toThrow('SHA-1 hash algorithm is not secure and has been disabled');
    });
});

// ============================================================================
// 不安全加密算法安全策略测试
// ============================================================================

describe('Security Policy Tests - Insecure Encryption Algorithms', () => {
    it('should allow AES-CBC when disallowInsecureEncryption is false', async () => {
        const options = {
            rsa_pub: testKeys.publicKey,
            pem: testKeys.certificate,
            keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5',
            encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc',
            disallowInsecureEncryption: false,
            key: testKeys.privateKey
        };

        const encryptedXml = await runEncrypt(TEST_CONTENT, options);
        const decryptedContent = await runDecrypt(encryptedXml, options);
        
        expect(decryptedContent).toBe(TEST_CONTENT);
    });

    it('should reject AES-CBC during encryption when disallowInsecureEncryption is true', async () => {
        const options = {
            rsa_pub: testKeys.publicKey,
            pem: testKeys.certificate,
            keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5',
            encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc',
            disallowInsecureEncryption: true,
            key: testKeys.privateKey
        };

        await expect(runEncrypt(TEST_CONTENT, options))
            .rejects.toThrow('AES-CBC encryption algorithm is not secure and has been disabled');
    });

    it('should allow AES-GCM when disallowInsecureEncryption is true', async () => {
        const options = {
            rsa_pub: testKeys.publicKey,
            pem: testKeys.certificate,
            keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5',
            encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes128-gcm',
            disallowInsecureEncryption: true,
            key: testKeys.privateKey
        };

        const encryptedXml = await runEncrypt(TEST_CONTENT, options);
        const decryptedContent = await runDecrypt(encryptedXml, options);
        
        expect(decryptedContent).toBe(TEST_CONTENT);
    });

    it('should reject AES-CBC during decryption when disallowInsecureEncryption is true', async () => {
        const encryptOptions = {
            rsa_pub: testKeys.publicKey,
            pem: testKeys.certificate,
            keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5',
            encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc',
            disallowInsecureEncryption: false,
            key: testKeys.privateKey // 需要私钥
        };

        const encryptedXml = await runEncrypt(TEST_CONTENT, encryptOptions);
        
        const decryptOptions = {
            ...encryptOptions,
            disallowInsecureEncryption: true
        };

        await expect(runDecrypt(encryptedXml, decryptOptions))
            .rejects.toThrow('AES-CBC encryption algorithm is not secure and has been disabled');
    });
});

// ============================================================================
// XML 结构验证测试
// ============================================================================

describe('XML Structure Validation Tests', () => {
    it('should generate valid XML Encryption 1.0 structure with RSA-1_5', async () => {
        const options = {
            rsa_pub: testKeys.publicKey,
            pem: testKeys.certificate,
            keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5',
            encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc',
            key: testKeys.privateKey
        };

        const encryptedXml = await runEncrypt(TEST_CONTENT, options);

        // 验证 XML 结构
        expect(encryptedXml).toContain('<xenc:EncryptedData');
        expect(encryptedXml).toContain('xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"');
        expect(encryptedXml).toContain('<xenc:EncryptionMethod');
        expect(encryptedXml).toContain('<KeyInfo');
        expect(encryptedXml).toContain('<e:EncryptedKey');
        expect(encryptedXml).toContain('<xenc:CipherData>');
        expect(encryptedXml).toContain('<xenc:CipherValue>');
    });

    it('should generate valid XML Encryption 1.1 structure with RSA-OAEP', async () => {
        const options = {
            rsa_pub: testKeys.publicKey,
            pem: testKeys.certificate,
            keyEncryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#rsa-oaep',
            keyEncryptionDigest: 'sha256',
            keyEncryptionMgf1: 'sha256',
            encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes128-gcm',
            key: testKeys.privateKey
        };

        const encryptedXml = await runEncrypt(TEST_CONTENT, options);

        // 验证 XML Enc 1.1 结构
        expect(encryptedXml).toContain('<xenc:EncryptedData');
        expect(encryptedXml).toContain('<ds:DigestMethod');
        expect(encryptedXml).toContain('http://www.w3.org/2001/04/xmlenc#sha256');
        expect(encryptedXml).toContain('<MGF');
        expect(encryptedXml).toContain('http://www.w3.org/2009/xmlenc11#mgf1sha256');
    });

    it('should not include DigestMethod for SHA-1 (default) in XML Enc 1.1', async () => {
        const options = {
            rsa_pub: testKeys.publicKey,
            pem: testKeys.certificate,
            keyEncryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#rsa-oaep',
            keyEncryptionDigest: 'sha1',
            keyEncryptionMgf1: 'sha1',
            encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes128-gcm',
            key: testKeys.privateKey
        };

        const encryptedXml = await runEncrypt(TEST_CONTENT, options);

        // SHA-1 是默认值，不应包含 DigestMethod 和 MGF
        expect(encryptedXml).not.toContain('<ds:DigestMethod');
        expect(encryptedXml).not.toContain('<MGF');
    });

    it('should include X509Certificate in KeyInfo', async () => {
        const options = {
            rsa_pub: testKeys.publicKey,
            pem: testKeys.certificate,
            keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5',
            encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc',
            key: testKeys.privateKey
        };

        const encryptedXml = await runEncrypt(TEST_CONTENT, options);

        expect(encryptedXml).toContain('<X509Data>');
        expect(encryptedXml).toContain('<X509Certificate>');
    });
});

// ============================================================================
// 跨算法兼容性测试
// ============================================================================

describe('Cross-Algorithm Compatibility Tests', () => {
    it('should decrypt RSA-1_5 encrypted data with different AES algorithms', async () => {
        const aesAlgorithms = [
            'http://www.w3.org/2001/04/xmlenc#aes128-cbc',
            'http://www.w3.org/2009/xmlenc11#aes128-gcm',
            'http://www.w3.org/2009/xmlenc11#aes256-gcm'
        ];

        for (const encryptionAlgorithm of aesAlgorithms) {
            const options = {
                rsa_pub: testKeys.publicKey,
                pem: testKeys.certificate,
                keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5',
                encryptionAlgorithm,
                key: testKeys.privateKey
            };

            const encryptedXml = await runEncrypt(TEST_CONTENT, options);
            const decryptedContent = await runDecrypt(encryptedXml, options);
            
            expect(decryptedContent).toBe(TEST_CONTENT);
        }
    });

    it('should decrypt RSA-OAEP-MGF1P encrypted data with different hash algorithms', async () => {
        const hashes = ['sha256', 'sha384', 'sha512'];

        for (const hash of hashes) {
            const options = {
                rsa_pub: testKeys.publicKey,
                pem: testKeys.certificate,
                keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
                keyEncryptionDigest: hash,
                encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes128-gcm',
                key: testKeys.privateKey
            };

            const encryptedXml = await runEncrypt(TEST_CONTENT, options);
            const decryptedContent = await runDecrypt(encryptedXml, options);
            
            expect(decryptedContent).toBe(TEST_CONTENT);
        }
    });

    it('should decrypt RSA-OAEP 1.1 encrypted data with different hash combinations', async () => {
        const combinations = [
            { oaep: 'sha256', mgf: 'sha256' },
            { oaep: 'sha256', mgf: 'sha512' },
            { oaep: 'sha512', mgf: 'sha256' },
            { oaep: 'sha512', mgf: 'sha512' }
        ];

        for (const { oaep, mgf } of combinations) {
            const options = {
                rsa_pub: testKeys.publicKey,
                pem: testKeys.certificate,
                keyEncryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#rsa-oaep',
                keyEncryptionDigest: oaep,
                keyEncryptionMgf1: mgf,
                encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes256-gcm',
                key: testKeys.privateKey
            };

            const encryptedXml = await runEncrypt(TEST_CONTENT, options);
            const decryptedContent = await runDecrypt(encryptedXml, options);
            
            expect(decryptedContent).toBe(TEST_CONTENT);
        }
    });
});

// ============================================================================
// 辅助函数
// ============================================================================

/**
 * 执行加密并返回 Promise
 * @param {string} content - 待加密内容
 * @param {Object} options - 加密选项
 * @returns {Promise<string>} 加密后的 XML
 */
function runEncrypt(content, options) {
    return new Promise((resolve, reject) => {
        encrypt(content, options, (err, result) => {
            if (err) reject(err);
            else resolve(result);
        });
    });
}

/**
 * 执行解密并返回 Promise
 * @param {string} xml - 加密的 XML
 * @param {Object} options - 解密选项
 * @returns {Promise<string>} 解密后的内容
 */
function runDecrypt(xml, options) {
    return new Promise((resolve, reject) => {
        decrypt(xml, options, (err, result) => {
            if (err) reject(err);
            else resolve(result.toString('utf8'));
        });
    });
}
