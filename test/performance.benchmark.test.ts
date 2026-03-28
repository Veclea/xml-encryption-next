/**
 * XML Encryption 性能基准测试
 * 测试加密/解密性能并生成报告
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { encrypt, decrypt } from '../lib/index.js';
import forge from 'node-forge';

// ============================================================================
// 测试工具
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

// 性能测试配置
const SIZES = [
    { name: 'Small (100B)', size: 100 },
    { name: 'Medium (1KB)', size: 1024 },
    { name: 'Large (10KB)', size: 10240 },
    { name: 'Extra Large (100KB)', size: 102400 }
];

const ALGORITHMS = [
    {
        name: 'AES-128-GCM + RSA-OAEP',
        options: {
            encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes128-gcm',
            keyEncryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#rsa-oaep',
            keyEncryptionDigest: 'sha256',
            keyEncryptionMgf1: 'sha256'
        }
    },
    {
        name: 'AES-256-GCM + RSA-OAEP',
        options: {
            encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes256-gcm',
            keyEncryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#rsa-oaep',
            keyEncryptionDigest: 'sha256',
            keyEncryptionMgf1: 'sha256'
        }
    },
    {
        name: 'AES-128-CBC + RSA-OAEP',
        options: {
            encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc',
            keyEncryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#rsa-oaep',
            keyEncryptionDigest: 'sha256',
            keyEncryptionMgf1: 'sha256'
        }
    },
    {
        name: 'AES-256-CBC + RSA-1_5',
        options: {
            encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
            keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5'
        }
    }
];

// 性能统计
const performanceStats = {
    results: [],
    summary: []
};

// ============================================================================
// 性能基准测试
// ============================================================================

describe('Performance Benchmark Tests', () => {
    const baseOptions = {
        rsa_pub: testKeys.publicKey,
        pem: testKeys.certificate,
        key: testKeys.privateKey
    };

    // 单次加密/解密性能测试
    describe('Single Operation Performance', () => {
        it('should measure encrypt performance for different sizes', async () => {
            const results = [];

            for (const { name, size } of SIZES) {
                const content = 'A'.repeat(size);
                const options = {
                    ...baseOptions,
                    ...ALGORITHMS[0].options
                };

                const start = performance.now();
                const encrypted = await encrypt(content, options);
                const end = performance.now();

                const duration = end - start;
                results.push({ name, size, duration });
                console.log(`Encrypt ${name}: ${duration.toFixed(2)}ms`);
            }

            performanceStats.results.push({
                test: 'encrypt_sizes',
                results
            });
        });

        it('should measure decrypt performance for different sizes', async () => {
            const results = [];
            const content = 'A'.repeat(1024); // 固定 1KB 测试

            for (const { name } of SIZES) {
                const options = {
                    ...baseOptions,
                    ...ALGORITHMS[0].options
                };

                const encrypted = await encrypt(content, options);

                const start = performance.now();
                const decrypted = await decrypt(encrypted, options);
                const end = performance.now();

                const duration = end - start;
                results.push({ name, size: content.length, duration });
                console.log(`Decrypt ${name}: ${duration.toFixed(2)}ms`);
            }

            performanceStats.results.push({
                test: 'decrypt_sizes',
                results
            });
        });
    });

    // 算法性能对比测试
    describe('Algorithm Performance Comparison', () => {
        it('should compare encryption performance across algorithms', async () => {
            const content = 'A'.repeat(1024); // 1KB
            const results = [];

            for (const alg of ALGORITHMS) {
                const options = {
                    ...baseOptions,
                    ...alg.options
                };

                const start = performance.now();
                const encrypted = await encrypt(content, options);
                const end = performance.now();

                const duration = end - start;
                results.push({
                    algorithm: alg.name,
                    duration,
                    encryptedSize: encrypted.length
                });
                console.log(`${alg.name} encrypt: ${duration.toFixed(2)}ms (${encrypted.length} bytes)`);
            }

            performanceStats.results.push({
                test: 'algorithm_comparison_encrypt',
                results
            });
        });

        it('should compare decryption performance across algorithms', async () => {
            const content = 'A'.repeat(1024); // 1KB
            const results = [];

            for (const alg of ALGORITHMS) {
                const options = {
                    ...baseOptions,
                    ...alg.options
                };

                const encrypted = await encrypt(content, options);

                const start = performance.now();
                const decrypted = await decrypt(encrypted, options);
                const end = performance.now();

                const duration = end - start;
                results.push({
                    algorithm: alg.name,
                    duration,
                    decryptedSize: decrypted.length
                });
                console.log(`${alg.name} decrypt: ${duration.toFixed(2)}ms`);
            }

            performanceStats.results.push({
                test: 'algorithm_comparison_decrypt',
                results
            });
        });
    });

    // 并发性能测试
    describe('Concurrency Performance', () => {
        it('should handle concurrent encryptions', async () => {
            const content = 'A'.repeat(1024);
            const options = {
                ...baseOptions,
                ...ALGORITHMS[0].options
            };
            const concurrency = 10;

            const start = performance.now();
            const promises = Array.from({ length: concurrency }, () =>
                encrypt(content, options)
            );
            await Promise.all(promises);
            const end = performance.now();

            const totalDuration = end - start;
            const avgDuration = totalDuration / concurrency;
            console.log(`Concurrent encrypt (${concurrency} ops): ${totalDuration.toFixed(2)}ms total, ${avgDuration.toFixed(2)}ms avg`);

            performanceStats.results.push({
                test: 'concurrent_encrypt',
                results: [{ concurrency, totalDuration, avgDuration }]
            });
        });

        it('should handle concurrent decryptions', async () => {
            const content = 'A'.repeat(1024);
            const options = {
                ...baseOptions,
                ...ALGORITHMS[0].options
            };
            const concurrency = 10;

            // 先加密 10 份
            const encryptedList = await Promise.all(
                Array.from({ length: concurrency }, () => encrypt(content, options))
            );

            // 并发解密
            const start = performance.now();
            const promises = encryptedList.map(encrypted =>
                decrypt(encrypted, options)
            );
            await Promise.all(promises);
            const end = performance.now();

            const totalDuration = end - start;
            const avgDuration = totalDuration / concurrency;
            console.log(`Concurrent decrypt (${concurrency} ops): ${totalDuration.toFixed(2)}ms total, ${avgDuration.toFixed(2)}ms avg`);

            performanceStats.results.push({
                test: 'concurrent_decrypt',
                results: [{ concurrency, totalDuration, avgDuration }]
            });
        });
    });

    // 吞吐量测试
    describe('Throughput Test', () => {
        it('should measure encryption throughput', async () => {
            const content = 'A'.repeat(1024 * 1024); // 1MB
            const options = {
                ...baseOptions,
                ...ALGORITHMS[0].options
            };

            const start = performance.now();
            const encrypted = await encrypt(content, options);
            const end = performance.now();

            const duration = (end - start) / 1000; // 转换为秒
            const throughput = content.length / duration / 1024 / 1024; // MB/s
            console.log(`Encryption throughput: ${throughput.toFixed(2)} MB/s`);

            performanceStats.results.push({
                test: 'throughput_encrypt',
                results: [{ size: content.length, duration, throughput }]
            });
        });

        it('should measure decryption throughput', async () => {
            const content = 'A'.repeat(1024 * 1024); // 1MB
            const options = {
                ...baseOptions,
                ...ALGORITHMS[0].options
            };

            const encrypted = await encrypt(content, options);

            const start = performance.now();
            const decrypted = await decrypt(encrypted, options);
            const end = performance.now();

            const duration = (end - start) / 1000;
            const throughput = decrypted.length / duration / 1024 / 1024; // MB/s
            console.log(`Decryption throughput: ${throughput.toFixed(2)} MB/s`);

            performanceStats.results.push({
                test: 'throughput_decrypt',
                results: [{ size: decrypted.length, duration, throughput }]
            });
        });
    });

    // 内存使用测试 (估算)
    describe('Memory Usage Test', () => {
        it('should measure memory usage for encryption', async () => {
            const content = 'A'.repeat(1024 * 1024); // 1MB
            const options = {
                ...baseOptions,
                ...ALGORITHMS[0].options
            };

            const startMem = process.memoryUsage().heapUsed;
            const encrypted = await encrypt(content, options);
            const endMem = process.memoryUsage().heapUsed;

            const memoryUsed = (endMem - startMem) / 1024 / 1024; // MB
            console.log(`Encryption memory usage: ${memoryUsed.toFixed(2)} MB`);

            performanceStats.results.push({
                test: 'memory_encrypt',
                results: [{ contentSize: content.length, memoryUsed }]
            });
        });

        it('should measure memory usage for decryption', async () => {
            const content = 'A'.repeat(1024 * 1024); // 1MB
            const options = {
                ...baseOptions,
                ...ALGORITHMS[0].options
            };

            const encrypted = await encrypt(content, options);

            const startMem = process.memoryUsage().heapUsed;
            const decrypted = await decrypt(encrypted, options);
            const endMem = process.memoryUsage().heapUsed;

            const memoryUsed = (endMem - startMem) / 1024 / 1024; // MB
            console.log(`Decryption memory usage: ${memoryUsed.toFixed(2)} MB`);

            performanceStats.results.push({
                test: 'memory_decrypt',
                results: [{ contentSize: decrypted.length, memoryUsed }]
            });
        });
    });
});

// ============================================================================
// 性能报告生成
// ============================================================================

afterAll(() => {
    // 生成性能报告
    console.log('\n========================================');
    console.log('PERFORMANCE BENCHMARK REPORT');
    console.log('========================================\n');

    performanceStats.results.forEach(({ test, results }) => {
        console.log(`\n### ${test}`);
        console.table(results);
    });

    console.log('\n========================================');
    console.log('END OF REPORT');
    console.log('========================================\n');
});
