import crypto from 'crypto';
import { DOMParser } from '@xmldom/xmldom';
import xpath from 'xpath';
import { renderTemplate, pemToCert, warnInsecureAlgorithm } from './utils.js';
import forge from 'node-forge';

// ============================================================================
// 常量定义 - 不安全算法列表 (根据 NIST 和 W3C 建议)
// ============================================================================

const insecureAlgorithms = [
    'http://www.w3.org/2001/04/xmlenc#rsa-1_5',
    'http://www.w3.org/2001/04/xmlenc#tripledes-cbc'
];

const insecureHashAlgorithms = [
    'http://www.w3.org/2000/09/xmldsig#sha1',
    'http://www.w3.org/2001/04/xmlenc#sha1'
];

const insecureEncryptionAlgorithms = [
    'http://www.w3.org/2001/04/xmlenc#aes128-cbc',
    'http://www.w3.org/2001/04/xmlenc#aes192-cbc',
    'http://www.w3.org/2001/04/xmlenc#aes256-cbc'
];

const hashObject = {
    keyEncryptionDigest: {
        'sha1': 'http://www.w3.org/2000/09/xmldsig#sha1',
        'sha256': 'http://www.w3.org/2001/04/xmlenc#sha256',
        'sha384': 'http://www.w3.org/2001/04/xmlenc#sha384',
        'sha512': 'http://www.w3.org/2001/04/xmlenc#sha512'
    },
    mgfAlgorithm: {
        'sha1': 'http://www.w3.org/2009/xmlenc11#mgf1sha1',
        'sha224': 'http://www.w3.org/2009/xmlenc11#mgf1sha224',
        'sha256': 'http://www.w3.org/2009/xmlenc11#mgf1sha256',
        'sha384': 'http://www.w3.org/2009/xmlenc11#mgf1sha384',
        'sha512': 'http://www.w3.org/2009/xmlenc11#mgf1sha512'
    }
};

// ============================================================================
// 工具函数 - Promise 化
// ============================================================================

/**
 * 将回调函数转换为 Promise
 * @param {Function} fn - 接受回调的函数
 * @returns {Function} 返回 Promise 的函数
 */
function promisify(fn) {
    return function (...args) {
        // 如果最后一个参数是回调函数，则使用 Promise
        if (typeof args[args.length - 1] === 'function') {
            return fn.apply(this, args);
        }
        return new Promise((resolve, reject) => {
            fn.apply(this, [...args, (err, result) => {
                if (err) reject(err);
                else resolve(result);
            }]);
        });
    };
}

/**
 * Promise 版本的 randomBytes
 * @param {number} size - 字节数
 * @returns {Promise<Buffer>}
 */
function randomBytesAsync(size) {
    return new Promise((resolve, reject) => {
        crypto.randomBytes(size, (err, buf) => {
            if (err) reject(err);
            else resolve(buf);
        });
    });
}

// ============================================================================
// 辅助函数 - 加密/解密原语
// ============================================================================

/**
 * 使用指定算法加密内容
 * @param {string} algorithm - OpenSSL 算法名称
 * @param {Buffer} key - 对称密钥
 * @param {number} ivLength - IV 长度
 * @param {string|Buffer} content - 待加密内容
 * @param {string} inputEncoding - 输入编码
 * @returns {Buffer} 加密后的数据
 */
function encryptWithAlgorithm(algorithm, key, ivLength, content, inputEncoding) {
    const iv = crypto.randomBytes(ivLength);
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    const contentBuffer = Buffer.isBuffer(content) ? content : Buffer.from(content, inputEncoding);

    let encrypted = cipher.update(contentBuffer);
    encrypted = Buffer.concat([encrypted, cipher.final()]);

    // 对于 GCM 模式，需要附加认证标签和 IV
    if (algorithm.includes('gcm')) {
        const authTag = cipher.getAuthTag();
        return Buffer.concat([iv, encrypted, authTag]);
    }
    // CBC 模式：IV + EncryptedData
    return Buffer.concat([iv, encrypted]);
}

/**
 * 使用指定算法解密内容
 * @param {string} algorithm - OpenSSL 算法名称
 * @param {Buffer} key - 对称密钥
 * @param {number} ivLength - IV 长度
 * @param {Buffer} encrypted - 已加密内容
 * @returns {Buffer} 解密后的数据
 */
function decryptWithAlgorithm(algorithm, key, ivLength, encrypted) {
    if (algorithm.includes('gcm')) {
        const iv = encrypted.slice(0, ivLength);
        const authTag = encrypted.slice(encrypted.length - 16);
        const content = encrypted.slice(ivLength, encrypted.length - 16);

        const decipher = crypto.createDecipheriv(algorithm, key, iv);
        decipher.setAuthTag(authTag);

        let decrypted = decipher.update(content);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return decrypted;
    }
    // CBC 模式：IV + EncryptedData
    const iv = encrypted.slice(0, ivLength);
    const content = encrypted.slice(ivLength);

    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    decipher.setAutoPadding(false);
    let decrypted = decipher.update(content);
    decrypted = Buffer.concat([decrypted, decipher.final()]);

    const paddingLength = decrypted[decrypted.length - 1];
    if (paddingLength < 1 || paddingLength > ivLength) {
        throw new Error('invalid padding length');
    }

    return decrypted.slice(0, decrypted.length - paddingLength);
}

// ============================================================================
// 密钥加密 - EncryptKeyInfo
// ============================================================================

/**
 * 创建 forge 的 MD 对象
 * @param {string} hashType - 哈希类型
 * @returns {Object} forge md 对象
 */
function createForgeMD(hashType) {
    switch (hashType) {
        case 'sha1': return forge.md.sha1.create();
        case 'sha256': return forge.md.sha256.create();
        case 'sha384': return forge.md.sha384.create();
        case 'sha512': return forge.md.sha512.create();
        default: throw new Error('Unsupported OAEP hash: ' + hashType);
    }
}

function createNodeBackedMD(hashType) {
    const digestLengths = {
        sha224: 28
    };

    if (!digestLengths[hashType]) {
        throw new Error('Unsupported OAEP hash: ' + hashType);
    }

    let hash = crypto.createHash(hashType);

    return {
        algorithm: hashType,
        digestLength: digestLengths[hashType],
        start() {
            hash = crypto.createHash(hashType);
            return this;
        },
        update(bytes, encoding = 'utf8') {
            const buffer = Buffer.isBuffer(bytes)
                ? bytes
                : Buffer.from(bytes, encoding === 'raw' ? 'binary' : encoding);
            hash.update(buffer);
            return this;
        },
        digest() {
            return forge.util.createBuffer(hash.digest().toString('binary'));
        }
    };
}

function createMGF1MD(hashType) {
    if (hashType === 'sha224') {
        return createNodeBackedMD(hashType);
    }
    return createForgeMD(hashType);
}

function normalizeBase64Value(value, optionName) {
    const normalized = value.replace(/\s+/g, '');
    const isBase64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(normalized);
    if (!isBase64) {
        throw new Error(optionName + ' must be a base64 string');
    }
    return normalized;
}

function getOAEPParamsOption(options) {
    return options.keyEncryptionOAEPParams ?? options.keyEncryptionOAEPparams ?? null;
}

function getOAEPLabelBufferFromOptionValue(value, optionName) {
    if (value == null) {
        return null;
    }
    if (Buffer.isBuffer(value)) {
        return Buffer.from(value);
    }
    if (value instanceof Uint8Array) {
        return Buffer.from(value);
    }
    if (typeof value === 'string') {
        return Buffer.from(normalizeBase64Value(value, optionName), 'base64');
    }
    throw new Error(optionName + ' must be a base64 string, Buffer, or Uint8Array');
}

function getOAEPLabelBufferFromOptions(options) {
    return getOAEPLabelBufferFromOptionValue(
        getOAEPParamsOption(options),
        'keyEncryptionOAEPParams'
    );
}

function getOAEPLabelBinary(labelBuffer) {
    if (!labelBuffer || labelBuffer.length === 0) {
        return undefined;
    }
    return labelBuffer.toString('binary');
}

function getSerializedOAEPParams(labelBuffer) {
    if (!labelBuffer || labelBuffer.length === 0) {
        return null;
    }
    return labelBuffer.toString('base64');
}

function parseDigestMethodAlgorithm(algorithm) {
    switch (algorithm) {
        case 'http://www.w3.org/2000/09/xmldsig#sha1':
        case 'http://www.w3.org/2001/04/xmlenc#sha1':
            return 'sha1';
        case 'http://www.w3.org/2000/09/xmldsig#sha256':
        case 'http://www.w3.org/2001/04/xmlenc#sha256':
            return 'sha256';
        case 'http://www.w3.org/2001/04/xmlenc#sha384':
            return 'sha384';
        case 'http://www.w3.org/2001/04/xmlenc#sha512':
            return 'sha512';
        default:
            throw new Error('Unsupported DigestMethod algorithm: ' + algorithm);
    }
}

function parseMGFAlgorithm(algorithm) {
    switch (algorithm) {
        case 'http://www.w3.org/2009/xmlenc11#mgf1sha1':
            return 'sha1';
        case 'http://www.w3.org/2009/xmlenc11#mgf1sha224':
            return 'sha224';
        case 'http://www.w3.org/2009/xmlenc11#mgf1sha256':
            return 'sha256';
        case 'http://www.w3.org/2009/xmlenc11#mgf1sha384':
            return 'sha384';
        case 'http://www.w3.org/2009/xmlenc11#mgf1sha512':
            return 'sha512';
        default:
            throw new Error('Unsupported MGF1 algorithm: ' + algorithm);
    }
}

function normalizeSymmetricKeyBytes(decrypted) {
    const rawBytes = Buffer.from(decrypted, 'binary');
    if ([8, 16, 24, 32].includes(rawBytes.length)) {
        return rawBytes;
    }

    const normalized = typeof decrypted === 'string' ? decrypted.replace(/\s+/g, '') : '';
    if (normalized && /^[A-Za-z0-9+/=]+$/.test(normalized)) {
        const legacyBytes = Buffer.from(normalized, 'base64');
        if ([8, 16, 24, 32].includes(legacyBytes.length)) {
            return legacyBytes;
        }
    }

    return rawBytes;
}

/**
 * 使用指定方案加密对称密钥 (内部实现)
 * @param {Object} params - 参数对象
 * @param {string} params.symmetricKey - 对称密钥
 * @param {Object} params.options - 加密选项
 * @param {number} params.padding - RSA 填充模式
 * @returns {string} KeyInfo XML
 */
function encryptKeyInfoWithSchemeInternal({ symmetricKey, options, padding }) {
    const symmetricKeyBuffer = Buffer.isBuffer(symmetricKey)
        ? Buffer.from(symmetricKey)
        : Buffer.from(symmetricKey, 'utf-8');
    const oaepLabelBuffer = getOAEPLabelBufferFromOptions(options);
    const oaepLabelBinary = getOAEPLabelBinary(oaepLabelBuffer);
    const serializedOAEPParams = getSerializedOAEPParams(oaepLabelBuffer);

    // 安全检查
    if (options.disallowInsecureHash && options.keyEncryptionDigest === 'sha1') {
        throw new Error('SHA-1 hash algorithm is not secure and has been disabled');
    }

    const publicKey = forge.pki.publicKeyFromPem(options.rsa_pub.toString());
    let encrypted;
    let params;

    // RSA-1_5 方案 (XML Enc 1.0)
    if (options.keyEncryptionAlgorithm === 'http://www.w3.org/2001/04/xmlenc#rsa-1_5') {
        encrypted = publicKey.encrypt(
            symmetricKeyBuffer.toString('binary'),
            'RSAES-PKCS1-V1_5'
        );

        params = {
            encryptedKey: Buffer.from(encrypted, 'binary').toString('base64'),
            encryptionPublicCert: '<X509Data><X509Certificate>' + pemToCert(options.pem.toString()) + '</X509Certificate></X509Data>',
            keyEncryptionMethod: options.keyEncryptionAlgorithm,
            keyEncryptionDigest: null,
            keyEncryptionMgf1: null,
            keyEncryptionOAEPParams: null
        };

        return renderTemplate('keyinfo', params);
    }

    // RSA-OAEP-MGF1P 方案 (XML Enc 1.0)
    if (options.keyEncryptionAlgorithm === 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p') {
        const md = createForgeMD(options.keyEncryptionDigest || 'sha1');

        encrypted = publicKey.encrypt(
            symmetricKeyBuffer.toString('binary'),
            'RSA-OAEP',
            {
                md: md,
                mgf1: { md: forge.md.sha1.create() },
                label: oaepLabelBinary
            }
        );

        params = {
            encryptedKey: Buffer.from(encrypted, 'binary').toString('base64'),
            encryptionPublicCert: '<X509Data><X509Certificate>' + pemToCert(options.pem.toString()) + '</X509Certificate></X509Data>',
            keyEncryptionMethod: options.keyEncryptionAlgorithm,
            keyEncryptionDigest: hashObject.keyEncryptionDigest[options.keyEncryptionDigest],
            keyEncryptionMgf1: null,
            keyEncryptionOAEPParams: serializedOAEPParams
        };

        return renderTemplate('keyinfo', params);
    }

    // RSA-OAEP 方案 (XML Enc 1.1)
    if (options.keyEncryptionAlgorithm === 'http://www.w3.org/2009/xmlenc11#rsa-oaep') {
        const md = createForgeMD(options.keyEncryptionDigest || 'sha1');
        let mgf1;
        
        // 单独处理 MGF1 哈希
        try {
            mgf1 = createMGF1MD(options.keyEncryptionMgf1 || 'sha1');
        } catch (e) {
            throw new Error('Unsupported MGF1 hash: ' + options.keyEncryptionMgf1);
        }

        encrypted = publicKey.encrypt(
            symmetricKeyBuffer.toString('binary'),
            'RSA-OAEP',
            { md: md, mgf1: { md: mgf1 }, label: oaepLabelBinary }
        );

        params = {
            encryptedKey: Buffer.from(encrypted, 'binary').toString('base64'),
            encryptionPublicCert: '<X509Data><X509Certificate>' + pemToCert(options.pem.toString()) + '</X509Certificate></X509Data>',
            keyEncryptionMethod: options.keyEncryptionAlgorithm,
            keyEncryptionDigest: options.keyEncryptionDigest === 'sha1' ? null : hashObject.keyEncryptionDigest[options.keyEncryptionDigest],
            keyEncryptionMgf1: options.keyEncryptionMgf1 === 'sha1' ? null : hashObject.mgfAlgorithm[options.keyEncryptionMgf1],
            keyEncryptionOAEPParams: serializedOAEPParams
        };

        return renderTemplate('keyinfo', params);
    }

    throw new Error('Unsupported keyEncryptionAlgorithm: ' + options.keyEncryptionAlgorithm);
}

/**
 * 加密对称密钥并生成 KeyInfo 元素
 * @param {string} symmetricKey - 对称密钥
 * @param {Object} options - 加密选项
 * @param {Function} [callback] - 回调函数
 * @returns {Promise<string>|void}
 */
function encryptKeyInfo(symmetricKey, options, callback) {
    // 验证参数
    if (!options) {
        const err = new Error('must provide options');
        return callback ? callback(err) : Promise.reject(err);
    }
    if (!options.rsa_pub) {
        const err = new Error('must provide options.rsa_pub with public key RSA');
        return callback ? callback(err) : Promise.reject(err);
    }
    if (!options.pem) {
        const err = new Error('must provide options.pem with certificate');
        return callback ? callback(err) : Promise.reject(err);
    }
    if (!options.keyEncryptionAlgorithm) {
        const err = new Error('encryption without encrypted key is not supported yet');
        return callback ? callback(err) : Promise.reject(err);
    }
    if (options.disallowEncryptionWithInsecureAlgorithm &&
        insecureAlgorithms.indexOf(options.keyEncryptionAlgorithm) >= 0) {
        const err = new Error('encryption algorithm ' + options.keyEncryptionAlgorithm + ' is not secure');
        return callback ? callback(err) : Promise.reject(err);
    }

    // 包装执行函数
    const execute = () => {
        switch (options.keyEncryptionAlgorithm) {
            case 'http://www.w3.org/2001/04/xmlenc#rsa-1_5':
                warnInsecureAlgorithm(options.keyEncryptionAlgorithm, options.warnInsecureAlgorithm);
                options.keyEncryptionDigest = null;
                options.keyEncryptionMgf1 = null;
                return encryptKeyInfoWithSchemeInternal({
                    symmetricKey, options, padding: crypto.constants.RSA_PKCS1_PADDING
                });

            case 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p':
                options.keyEncryptionDigest = options.keyEncryptionDigest || 'sha1';
                options.keyEncryptionMgf1 = 'sha1';
                return encryptKeyInfoWithSchemeInternal({
                    symmetricKey, options, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
                });

            case 'http://www.w3.org/2009/xmlenc11#rsa-oaep':
                options.keyEncryptionDigest = options.keyEncryptionDigest || 'sha1';
                options.keyEncryptionMgf1 = options.keyEncryptionMgf1 || 'sha1';
                return encryptKeyInfoWithSchemeInternal({
                    symmetricKey, options, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
                });

            default:
                throw new Error('encryption key algorithm not supported: ' + options.keyEncryptionAlgorithm);
        }
    };

    try {
        const result = execute();
        return callback ? callback(null, result) : Promise.resolve(result);
    } catch (err) {
        return callback ? callback(err) : Promise.reject(err);
    }
}

// ============================================================================
// 内容加密 - Encrypt
// ============================================================================

/**
 * 获取对称密钥长度和 IV 长度
 * @param {string} algorithm - 加密算法 URI
 * @returns {Object} 密钥长度和 IV 长度
 */
function getKeyAndIVLength(algorithm) {
    switch (algorithm) {
        case 'http://www.w3.org/2001/04/xmlenc#aes128-cbc':
            return { keyLength: 16, ivLength: 16 };
        case 'http://www.w3.org/2001/04/xmlenc#aes192-cbc':
            return { keyLength: 24, ivLength: 16 };
        case 'http://www.w3.org/2001/04/xmlenc#aes256-cbc':
            return { keyLength: 32, ivLength: 16 };
        case 'http://www.w3.org/2009/xmlenc11#aes128-gcm':
            return { keyLength: 16, ivLength: 12 }; // GCM 使用 12 字节 IV
        case 'http://www.w3.org/2009/xmlenc11#aes192-gcm':
            return { keyLength: 24, ivLength: 12 };
        case 'http://www.w3.org/2009/xmlenc11#aes256-gcm':
            return { keyLength: 32, ivLength: 12 };
        case 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc':
            return { keyLength: 24, ivLength: 8 }; // 3DES 使用 8 字节 IV
        default:
            throw new Error('unsupported encryption algorithm: ' + algorithm);
    }
}

/**
 * 获取 OpenSSL 算法名称
 * @param {string} algorithm - 加密算法 URI
 * @returns {string} OpenSSL 算法名称
 */
function getOpenSSLAlgorithm(algorithm) {
    switch (algorithm) {
        case 'http://www.w3.org/2001/04/xmlenc#aes128-cbc': return 'aes-128-cbc';
        case 'http://www.w3.org/2001/04/xmlenc#aes192-cbc': return 'aes-192-cbc';
        case 'http://www.w3.org/2001/04/xmlenc#aes256-cbc': return 'aes-256-cbc';
        case 'http://www.w3.org/2009/xmlenc11#aes128-gcm': return 'aes-128-gcm';
        case 'http://www.w3.org/2009/xmlenc11#aes192-gcm': return 'aes-192-gcm';
        case 'http://www.w3.org/2009/xmlenc11#aes256-gcm': return 'aes-256-gcm';
        case 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc': return 'des-ede3-cbc';
        default:
            throw new Error('encryption algorithm not supported: ' + algorithm);
    }
}

/**
 * 加密内容 (内部实现)
 * @param {string|Buffer} content - 待加密内容
 * @param {Object} options - 加密选项
 * @returns {string} 加密后的 XML
 */
function encryptInternal(content, options) {
    // 验证参数
    if (!options) throw new Error('must provide options');
    if (!content) throw new Error('must provide content to encrypt');
    if (!options.rsa_pub) throw new Error('rsa_pub option is mandatory and you should provide a valid RSA public key');
    if (!options.pem) throw new Error('pem option is mandatory and you should provide a valid x509 certificate encoded as PEM');

    // 安全检查
    if (options.disallowInsecureEncryption &&
        options.encryptionAlgorithm &&
        insecureEncryptionAlgorithms.includes(options.encryptionAlgorithm)) {
        throw new Error('AES-CBC encryption algorithm is not secure and has been disabled');
    }

    if (options.disallowEncryptionWithInsecureAlgorithm &&
        (insecureAlgorithms.indexOf(options.keyEncryptionAlgorithm) >= 0 ||
         insecureAlgorithms.indexOf(options.encryptionAlgorithm) >= 0)) {
        throw new Error('encryption algorithm ' + options.keyEncryptionAlgorithm + ' is not secure');
    }

    options.input_encoding = options.input_encoding || 'utf8';

    // 1. 生成对称密钥
    const { keyLength, ivLength } = getKeyAndIVLength(options.encryptionAlgorithm);
    const symmetricKey = crypto.randomBytes(keyLength);

    // 2. 加密内容
    const opensslAlg = getOpenSSLAlgorithm(options.encryptionAlgorithm);
    const encryptedContent = encryptWithAlgorithm(
        opensslAlg, symmetricKey, ivLength, content, options.input_encoding
    );

    // 3. 加密密钥并生成 KeyInfo
    const keyInfo = (() => {
        const encryptKeyInfoOptions = { ...options };
        switch (options.keyEncryptionAlgorithm) {
            case 'http://www.w3.org/2001/04/xmlenc#rsa-1_5':
                encryptKeyInfoOptions.keyEncryptionDigest = null;
                encryptKeyInfoOptions.keyEncryptionMgf1 = null;
                // 发出警告
                warnInsecureAlgorithm(options.keyEncryptionAlgorithm, options.warnInsecureAlgorithm);
                return encryptKeyInfoWithSchemeInternal({
                    symmetricKey, options: encryptKeyInfoOptions, padding: crypto.constants.RSA_PKCS1_PADDING
                });
            case 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p':
                encryptKeyInfoOptions.keyEncryptionDigest = encryptKeyInfoOptions.keyEncryptionDigest || 'sha1';
                encryptKeyInfoOptions.keyEncryptionMgf1 = 'sha1';
                return encryptKeyInfoWithSchemeInternal({
                    symmetricKey, options: encryptKeyInfoOptions, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
                });
            case 'http://www.w3.org/2009/xmlenc11#rsa-oaep':
                encryptKeyInfoOptions.keyEncryptionDigest = encryptKeyInfoOptions.keyEncryptionDigest || 'sha1';
                encryptKeyInfoOptions.keyEncryptionMgf1 = encryptKeyInfoOptions.keyEncryptionMgf1 || 'sha1';
                return encryptKeyInfoWithSchemeInternal({
                    symmetricKey, options: encryptKeyInfoOptions, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
                });
            default:
                throw new Error('encryption key algorithm not supported: ' + options.keyEncryptionAlgorithm);
        }
    })();

    // 4. 组装最终结果
    return renderTemplate('encrypted-key', {
        encryptedContent: encryptedContent.toString('base64'),
        keyInfo: keyInfo,
        contentEncryptionMethod: options.encryptionAlgorithm
    });
}

/**
 * 加密内容
 * @param {string|Buffer} content - 待加密内容
 * @param {Object} options - 加密选项
 * @param {Function} [callback] - 回调函数
 * @returns {Promise<string>|void}
 */
function encrypt(content, options, callback) {
    // 如果提供了回调函数，使用回调模式
    if (typeof callback === 'function') {
        try {
            const result = encryptInternal(content, options);
            callback(null, result);
        } catch (err) {
            callback(err);
        }
        return;
    }

    // 否则返回 Promise
    return new Promise((resolve, reject) => {
        try {
            const result = encryptInternal(content, options);
            resolve(result);
        } catch (err) {
            reject(err);
        }
    });
}

// ============================================================================
// 解密 - Decrypt
// ============================================================================

/**
 * 解密 XML 加密数据
 * @param {string|Document} xml - 加密的 XML
 * @param {Object} options - 解密选项
 * @param {Function} [callback] - 回调函数
 * @returns {Promise<Buffer>|void}
 */
function decrypt(xml, options, callback) {
    // 验证参数
    if (!options) {
        const err = new Error('must provide options');
        return callback ? callback(err) : Promise.reject(err);
    }
    if (!xml) {
        const err = new Error('must provide XML to decrypt');
        return callback ? callback(err) : Promise.reject(err);
    }
    if (!options.key) {
        const err = new Error('key option is mandatory and you should provide a valid RSA private key');
        return callback ? callback(err) : Promise.reject(err);
    }

    try {
        const doc = typeof xml === 'string' ? new DOMParser().parseFromString(xml) : xml;
        const symmetricKey = decryptKeyInfo(doc, options);

        const encryptionMethod = xpath.select("//*[local-name(.)='EncryptedData']/*[local-name(.)='EncryptionMethod']", doc)[0];
        const encryptionAlgorithm = encryptionMethod.getAttribute('Algorithm');

        // 安全检查
        if (options.disallowInsecureEncryption &&
            insecureEncryptionAlgorithms.includes(encryptionAlgorithm)) {
            const err = new Error('AES-CBC encryption algorithm is not secure and has been disabled');
            return callback ? callback(err) : Promise.reject(err);
        }

        if (options.disallowDecryptionWithInsecureAlgorithm &&
            insecureAlgorithms.indexOf(encryptionAlgorithm) >= 0) {
            const err = new Error('encryption algorithm ' + encryptionAlgorithm + ' is not secure, fail to decrypt');
            return callback ? callback(err) : Promise.reject(err);
        }

        const encryptedContentNode = xpath.select(
            "//*[local-name(.)='EncryptedData']/*[local-name(.)='CipherData']/*[local-name(.)='CipherValue']",
            doc
        )[0];

        if (!encryptedContentNode?.textContent) {
            const err = new Error('does not have encryptedContent');
            return callback ? callback(err) : Promise.reject(err);
        }

        const encrypted = Buffer.from(encryptedContentNode.textContent, 'base64');
        let result;

        switch (encryptionAlgorithm) {
            case 'http://www.w3.org/2001/04/xmlenc#aes128-cbc':
                result = decryptWithAlgorithm('aes-128-cbc', symmetricKey, 16, encrypted);
                break;
            case 'http://www.w3.org/2001/04/xmlenc#aes192-cbc':
                result = decryptWithAlgorithm('aes-192-cbc', symmetricKey, 16, encrypted);
                break;
            case 'http://www.w3.org/2001/04/xmlenc#aes256-cbc':
                result = decryptWithAlgorithm('aes-256-cbc', symmetricKey, 16, encrypted);
                break;
            case 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc':
                warnInsecureAlgorithm(encryptionAlgorithm, options.warnInsecureAlgorithm);
                result = decryptWithAlgorithm('des-ede3-cbc', symmetricKey, 8, encrypted);
                break;
            case 'http://www.w3.org/2009/xmlenc11#aes128-gcm':
                result = decryptWithAlgorithm('aes-128-gcm', symmetricKey, 12, encrypted);
                break;
            case 'http://www.w3.org/2009/xmlenc11#aes192-gcm':
                result = decryptWithAlgorithm('aes-192-gcm', symmetricKey, 12, encrypted);
                break;
            case 'http://www.w3.org/2009/xmlenc11#aes256-gcm':
                result = decryptWithAlgorithm('aes-256-gcm', symmetricKey, 12, encrypted);
                break;
            default:
                const err = new Error('encryption algorithm ' + encryptionAlgorithm + ' not supported');
                return callback ? callback(err) : Promise.reject(err);
        }

        return callback ? callback(null, result) : Promise.resolve(result);
    } catch (err) {
        return callback ? callback(err) : Promise.reject(err);
    }
}

// ============================================================================
// 密钥解密 - DecryptKeyInfo
// ============================================================================

/**
 * 从 XML 中解密对称密钥
 * @param {Document|string} doc - XML 文档
 * @param {Object} options - 解密选项
 * @returns {Buffer} 解密后的对称密钥
 */
function decryptKeyInfo(doc, options) {
    if (typeof doc === 'string') doc = new DOMParser().parseFromString(doc);

    const encryptedData = xpath.select("//*[local-name(.)='EncryptedData']", doc)[0];
    if (!encryptedData) {
        throw new Error('cannot find EncryptedData');
    }

    let keyInfo = xpath.select(
        "./*[local-name(.)='KeyInfo' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
        encryptedData
    )[0];

    if (!keyInfo) {
        keyInfo = xpath.select("./*[local-name(.)='KeyInfo']", encryptedData)[0];
    }

    if (!keyInfo) {
        throw new Error('cannot find KeyInfo');
    }

    let encryptedKey = xpath.select("./*[local-name(.)='EncryptedKey']", keyInfo)[0];
    if (!encryptedKey) {
        const keyRetrievalMethod = xpath.select(
            "./*[local-name(.)='RetrievalMethod']",
            keyInfo
        )[0];
        const keyRetrievalMethodUri = keyRetrievalMethod ? keyRetrievalMethod.getAttribute('URI') : null;
        if (!keyRetrievalMethodUri) {
            throw new Error('cannot find encrypted key');
        }
        if (!keyRetrievalMethodUri.startsWith('#')) {
            throw new Error('unsupported RetrievalMethod URI');
        }

        const encryptedKeyId = keyRetrievalMethodUri.substring(1);
        if (encryptedKeyId.includes('"') || encryptedKeyId.includes("'")) {
            throw new Error('unsupported RetrievalMethod URI');
        }

        encryptedKey = xpath.select(
            "//*[local-name(.)='EncryptedKey' and @Id='" + encryptedKeyId + "']",
            doc
        )[0];
    }

    if (!encryptedKey) {
        throw new Error('cannot find encrypted key');
    }

    const keyEncryptionMethod = xpath.select(
        "./*[local-name(.)='EncryptionMethod']",
        encryptedKey
    )[0];

    if (!keyEncryptionMethod) {
        throw new Error('cannot find encryption algorithm');
    }

    const keyEncryptionAlgorithm = keyEncryptionMethod.getAttribute('Algorithm');

    // 解析 OAEP hash 和 MGF1 hash
    let oaepHash = 'sha1';
    let mgfHash = 'sha1';

    const keyDigestMethod = xpath.select(
        "./*[local-name(.)='DigestMethod']",
        keyEncryptionMethod
    )[0];

    const mgfDigestMethod = xpath.select(
        "./*[local-name(.)='MGF']",
        keyEncryptionMethod
    )[0];

    if (keyDigestMethod) {
        oaepHash = parseDigestMethodAlgorithm(keyDigestMethod.getAttribute('Algorithm'));
    }

    if (mgfDigestMethod) {
        const parsedMgfHash = parseMGFAlgorithm(mgfDigestMethod.getAttribute('Algorithm'));
        if (keyEncryptionAlgorithm === 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p') {
            if (parsedMgfHash !== 'sha1') {
                throw new Error('MGF algorithm is fixed to MGF1 with SHA-1 for rsa-oaep-mgf1p');
            }
        } else {
            mgfHash = parsedMgfHash;
        }
    }

    const oaepParamsNode = xpath.select(
        "./*[local-name(.)='OAEPparams']",
        keyEncryptionMethod
    )[0];
    const oaepLabel = oaepParamsNode
        ? getOAEPLabelBufferFromOptionValue(oaepParamsNode.textContent || '', 'OAEPparams')
        : null;

    // 安全检查
    if (options.disallowInsecureHash &&
        keyDigestMethod &&
        insecureHashAlgorithms.includes(keyDigestMethod.getAttribute('Algorithm'))) {
        throw new Error('SHA-1 hash algorithm is not secure and has been disabled');
    }

    if (options.disallowDecryptionWithInsecureAlgorithm &&
        insecureAlgorithms.indexOf(keyEncryptionAlgorithm) >= 0) {
        throw new Error('encryption algorithm ' + keyEncryptionAlgorithm + ' is not secure, fail to decrypt');
    }

    const encryptedKeyNode = xpath.select(
        "./*[local-name(.)='CipherData']/*[local-name(.)='CipherValue']",
        encryptedKey
    )[0];

    if (!encryptedKeyNode?.textContent) {
        throw new Error('cannot find encrypted key data');
    }

    // 解密对称密钥
    return decryptKeyInfoWithSchemeInternal({
        keyEncryptionAlgorithm,
        encryptedKeyNode,
        options,
        oaepHash,
        mgfHash,
        oaepLabel
    });
}

/**
 * 使用指定方案解密对称密钥 (内部实现)
 * @param {Object} params - 参数对象
 * @param {string} params.keyEncryptionAlgorithm - 密钥加密算法
 * @param {Element} params.encryptedKeyNode - 加密密钥的 XML 元素
 * @param {Object} params.options - 解密选项
 * @param {string} params.oaepHash - OAEP 哈希算法
 * @param {string} params.mgfHash - MGF1 哈希算法
 * @returns {Buffer} 解密后的对称密钥
 */
function decryptKeyInfoWithSchemeInternal({ keyEncryptionAlgorithm, encryptedKeyNode, options, oaepHash, mgfHash, oaepLabel }) {
    // 安全检查
    if (options.disallowInsecureHash && oaepHash === 'sha1') {
        throw new Error('SHA-1 hash algorithm is not secure and has been disabled');
    }

    const encryptedKeyBytes = Buffer.from(encryptedKeyNode.textContent, 'base64');
    const privateKey = forge.pki.privateKeyFromPem(options.key.toString());

    try {
        let decrypted;

        if (keyEncryptionAlgorithm === 'http://www.w3.org/2001/04/xmlenc#rsa-1_5') {
            // RSA-1_5
            decrypted = privateKey.decrypt(encryptedKeyBytes.toString('binary'), 'RSAES-PKCS1-V1_5');
        } else if (
            keyEncryptionAlgorithm === 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p' &&
            oaepHash === 'sha1'
        ) {
            try {
                const nodeCryptoDecrypted = crypto.privateDecrypt(
                    {
                        key: options.key,
                        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                        oaepHash: 'sha1',
                        oaepLabel: oaepLabel && oaepLabel.length > 0 ? oaepLabel : undefined
                    },
                    encryptedKeyBytes
                );
                return normalizeSymmetricKeyBytes(nodeCryptoDecrypted.toString('binary'));
            } catch (_nodeCryptoError) {
                // Fall back to forge for keys/providers that Node cannot handle directly.
            }
        } else {
            // RSA-OAEP
            const md = oaepHash ? createForgeMD(oaepHash) : forge.md.sha1.create();
            const mgf1 = mgfHash ? createMGF1MD(mgfHash) : forge.md.sha1.create();

            decrypted = privateKey.decrypt(
                encryptedKeyBytes.toString('binary'),
                'RSA-OAEP',
                {
                    md: md,
                    mgf1: { md: mgf1 },
                    label: getOAEPLabelBinary(oaepLabel)
                }
            );
        }

        return normalizeSymmetricKeyBytes(decrypted);
    } catch (e) {
        throw new Error('unable to decrypt key: ' + e.message);
    }
}

// ============================================================================
// 导出 - 同时支持回调和 Promise/async-await
// ============================================================================

export {
    encrypt,
    decrypt,
    encryptKeyInfo,
    decryptKeyInfo,
    encryptWithAlgorithm,
    decryptWithAlgorithm
};
