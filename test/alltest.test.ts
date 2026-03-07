import { describe, it, expect } from 'vitest';
import { encrypt, decrypt } from '/lib/index.js'; // 替换为实际导入路径
import forge from 'node-forge';

// 生成测试用的RSA密钥对
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
    const attrs = [{
        name: 'commonName',
        value: 'test'
    }];
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

const testKeys = generateTestKeys();

describe('XML Encryption/Decryption Test Suite', () => {
    const testContent = 'This is a test content for XML encryption';

    // RSA 1.5 测试用例 (不支持任何hash和mgf)
    describe('RSA 1.5 Encryption Algorithm Tests', () => {
        it('should encrypt and decrypt with rsa-1_5 algorithm', (done) => {
            const options = {
                rsa_pub: testKeys.publicKey,
                pem: testKeys.certificate,
                keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5',
                encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc',
                key: testKeys.privateKey
            };

            encrypt(testContent, options, (encryptErr, encryptedXml) => {
                if (encryptErr) {
                console.log(encryptErr)
                    return;
                }

                decrypt(encryptedXml, options, (decryptErr, decryptedContent) => {
                    if (encryptErr) {
                        console.log(encryptErr)
                        return;
                    }else{
                        expect(decryptedContent).toBe(testContent);

                    }


                  
                });
            });
        });
    });

    // RSA-OAEP-MGF1P 测试用例 (支持SHA1, SHA256, SHA384, SHA512 with MGF1 SHA1)
    describe('RSA-OAEP-MGF1P Encryption Algorithm Tests', () => {
        const oaepHashes = ['sha1', 'sha256', 'sha384', 'sha512'];

        oaepHashes.forEach((hash) => {
            it(`should encrypt and decrypt with rsa-oaep-mgf1p algorithm using ${hash} hash`, (done) => {
                const options = {
                    rsa_pub: testKeys.publicKey,
                    pem: testKeys.certificate,
                    keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
                    keyEncryptionDigest: hash,
                    encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc',
                    key: testKeys.privateKey
                };

                encrypt(testContent, options, (encryptErr, encryptedXml) => {
                    if (encryptErr) {
                        console.log(encryptErr)
                        return;
                    }

                    decrypt(encryptedXml, options, (decryptErr, decryptedContent) => {
                        if (decryptErr) {
                            console.log(encryptErr)
                            return;
                        }

                        expect(decryptedContent).toBe(testContent);
                      
                    });
                });
            });
        });

        // 测试不支持的hash值应该失败
        it('should fail with unsupported hash algorithm in rsa-oaep-mgf1p', (done) => {
            const options = {
                rsa_pub: testKeys.publicKey,
                pem: testKeys.certificate,
                keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
                keyEncryptionDigest: 'sha224', // Not supported
                encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc',
                key: testKeys.privateKey
            };

            encrypt(testContent, options, (encryptErr) => {
                expect(encryptErr).toBeDefined();
              
            });
        });
    });

    // RSA-OAEP 1.1 测试用例 (支持自定义MGF1函数，支持SHA1, SHA256, SHA384, SHA512 OAEP函数，MGF1 SHA1, SHA256, SHA384, SHA512组合)
    describe('RSA-OAEP 1.1 Encryption Algorithm Tests', () => {
        const oaepHashes = ['sha1', 'sha256', 'sha384', 'sha512'];
        const mgfHashes = ['sha1', 'sha256', 'sha384', 'sha512'];

        // 测试所有支持的OAEP和MGF1组合
        oaepHashes.forEach((oaepHash) => {
            mgfHashes.forEach((mgfHash) => {
                it(`should encrypt and decrypt with rsa-oaep algorithm using ${oaepHash} OAEP and ${mgfHash} MGF1`, (done) => {
                    const options = {
                        rsa_pub: testKeys.publicKey,
                        pem: testKeys.certificate,
                        keyEncryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#rsa-oaep',
                        keyEncryptionDigest: oaepHash,
                        keyEncryptionMgf1: mgfHash,
                        encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc',
                        key: testKeys.privateKey
                    };

                    encrypt(testContent, options, (encryptErr, encryptedXml) => {
                        if (encryptErr) {
                            console.log(encryptErr)
                            return;
                        }

                        decrypt(encryptedXml, options, (decryptErr, decryptedContent) => {
                            if (decryptErr) {
                                console.log(encryptErr)
                                return;
                            }

                            expect(decryptedContent).toBe(testContent);
                          
                        });
                    });
                });
            });
        });

        // 测试不支持的hash值应该失败
        it('should fail with unsupported OAEP hash algorithm in rsa-oaep', (done) => {
            const options = {
                rsa_pub: testKeys.publicKey,
                pem: testKeys.certificate,
                keyEncryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#rsa-oaep',
                keyEncryptionDigest: 'sha224', // Not supported
                keyEncryptionMgf1: 'sha1',
                encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc',
                key: testKeys.privateKey
            };

            encrypt(testContent, options, (encryptErr) => {
                expect(encryptErr).toBeDefined();
              
            });
        });

        it('should fail with unsupported MGF1 hash algorithm in rsa-oaep', (done) => {
            const options = {
                rsa_pub: testKeys.publicKey,
                pem: testKeys.certificate,
                keyEncryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#rsa-oaep',
                keyEncryptionDigest: 'sha1',
                keyEncryptionMgf1: 'sha224', // Not supported
                encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc',
                key: testKeys.privateKey
            };

            encrypt(testContent, options, (encryptErr) => {
                expect(encryptErr).toBeDefined();
              
            });
        });
    });

    // 测试各种AES加密算法与不同的RSA密钥加密算法组合
    describe('AES Encryption Algorithm Combinations', () => {
        const aesAlgorithms = [
            'http://www.w3.org/2001/04/xmlenc#aes128-cbc',
            'http://www.w3.org/2001/04/xmlenc#aes192-cbc',
            'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
            'http://www.w3.org/2009/xmlenc11#aes128-gcm',
            'http://www.w3.org/2009/xmlenc11#aes192-gcm',
            'http://www.w3.org/2009/xmlenc11#aes256-gcm'
        ];

        const rsaAlgorithms = [
            {
                name: 'RSA 1.5',
                algorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5',
                options: {}
            },
            {
                name: 'RSA-OAEP-MGF1P SHA256',
                algorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
                options: { keyEncryptionDigest: 'sha256' }
            },
            {
                name: 'RSA-OAEP 1.1 SHA256+MGF1-SHA256',
                algorithm: 'http://www.w3.org/2009/xmlenc11#rsa-oaep',
                options: { keyEncryptionDigest: 'sha256', keyEncryptionMgf1: 'sha256' }
            }
        ];

        aesAlgorithms.forEach((aesAlg) => {
            rsaAlgorithms.forEach((rsaAlg) => {
                it(`should encrypt and decrypt with ${aesAlg} and ${rsaAlg.name}`, (done) => {
                    const options = {
                        rsa_pub: testKeys.publicKey,
                        pem: testKeys.certificate,
                        keyEncryptionAlgorithm: rsaAlg.algorithm,
                        encryptionAlgorithm: aesAlg,
                        key: testKeys.privateKey,
                        ...rsaAlg.options
                    };

                    encrypt(testContent, options, (encryptErr, encryptedXml) => {
                        if (encryptErr) {
                            console.log(encryptErr)
                            return;
                        }

                        decrypt(encryptedXml, options, (decryptErr, decryptedContent) => {
                            if (decryptErr) {
                                console.log(encryptErr)
                                return;
                            }

                            expect(decryptedContent).toBe(testContent);
                          
                        });
                    });
                });
            });
        });
    });

    // 错误处理测试
    describe('Error Handling Tests', () => {
        it('should fail when missing required options', (done) => {
            encrypt(testContent, undefined, (err) => {
                expect(err).toBeDefined();
                expect(err.message).toContain('must provide options');
              
            });
        });

        it('should fail when missing content to encrypt', (done) => {
            const options = {
                rsa_pub: testKeys.publicKey,
                pem: testKeys.certificate,
                keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5',
                encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc'
            };

            encrypt(null, options, (err) => {
                expect(err).toBeDefined();
                expect(err.message).toContain('must provide content to encrypt');
              
            });
        });

        it('should fail when missing RSA public key', (done) => {
            const options = {
                pem: testKeys.certificate,
                keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5',
                encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc'
            };

            encrypt(testContent, options, (err) => {
                expect(err).toBeDefined();
                expect(err.message).toContain('rsa_pub option is mandatory');
              
            });
        });

        it('should fail when missing PEM certificate', (done) => {
            const options = {
                rsa_pub: testKeys.publicKey,
                keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5',
                encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc'
            };

            encrypt(testContent, options, (err) => {
                expect(err).toBeDefined();
                expect(err.message).toContain('pem option is mandatory');
              
            });
        });

        it('should fail during decryption when missing private key', (done) => {
            const options = {
                rsa_pub: testKeys.publicKey,
                pem: testKeys.certificate,
                keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5',
                encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc'
            };

            encrypt(testContent, options, (encryptErr, encryptedXml) => {
                if (encryptErr) {
                    console.log(encryptErr)
                    return;
                }

                // 移除私钥选项
                const decryptOptions = { ...options };
                delete decryptOptions?.key;

                decrypt(encryptedXml, decryptOptions, (err) => {
                    expect(err).toBeDefined();
                    expect(err.message).toContain('key option is mandatory');
                  
                });
            });
        });

        it('should fail with unsupported encryption algorithm', (done) => {
            const options = {
                rsa_pub: testKeys.publicKey,
                pem: testKeys.certificate,
                keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5',
                encryptionAlgorithm: 'http://example.com/unsupported-algorithm', // Unsupported
                key: testKeys.privateKey
            };

            encrypt(testContent, options, (err) => {
                expect(err).toBeDefined();
                expect(err.message).toContain('unsupported encryption algorithm');
              
            });
        });

        it('should fail with unsupported key encryption algorithm', (done) => {
            const options = {
                rsa_pub: testKeys.publicKey,
                pem: testKeys.certificate,
                keyEncryptionAlgorithm: 'http://example.com/unsupported-key-algorithm', // Unsupported
                encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc',
                key: testKeys.privateKey
            };

            encrypt(testContent, options, (err) => {
                expect(err).toBeDefined();
                expect(err.message).toContain('encryption key algorithm not supported');
              
            });
        });
    });

    // 不安全算法测试
    describe('Insecure Algorithm Tests', () => {
        it('should allow insecure algorithm when disallow flag is false', (done) => {
            const options = {
                rsa_pub: testKeys.publicKey,
                pem: testKeys.certificate,
                keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5', // Insecure
                encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc', // Insecure
                disallowEncryptionWithInsecureAlgorithm: false,
                key: testKeys.privateKey
            };

            encrypt(testContent, options, (encryptErr, encryptedXml) => {
                if (encryptErr) {
                    console.log(encryptErr)
                    return;
                }

                // 测试解密也应允许不安全算法
                decrypt(encryptedXml, options, (decryptErr, decryptedContent) => {
                    if (decryptErr) {
                        console.log(encryptErr?.message)
                        return;
                    }

                    expect(decryptedContent).toBe(testContent);
                  
                });
            });
        });

        it('should reject insecure algorithm when disallow flag is true', (done) => {
            const options = {
                rsa_pub: testKeys.publicKey,
                pem: testKeys.certificate,
                keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5', // Insecure
                encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc', // Insecure
                disallowEncryptionWithInsecureAlgorithm: true,
                key: testKeys.privateKey
            };

            encrypt(testContent, options, (err) => {
                expect(err).toBeDefined();
                expect(err.message).toContain('is not secure');
              
            });
        });
    });
});
