import crypto from 'crypto';
import { DOMParser } from '@xmldom/xmldom';
import xpath from 'xpath';
import { renderTemplate, pemToCert, warnInsecureAlgorithm } from './utils.js';

// 尝试动态导入 node-forge 以处理复杂的 OAEP 情况 (OAEP Hash != MGF1 Hash)

import  forge from 'node-forge'


const insecureAlgorithms = [
    'http://www.w3.org/2001/04/xmlenc#rsa-1_5',
    'http://www.w3.org/2001/04/xmlenc#tripledes-cbc'
];

// 算法 URI 到 OpenSSL/Forge 哈希名称的映射
const digestUriToNameMap = {
    'http://www.w3.org/2000/09/xmldsig#sha1': 'sha1',
    'http://www.w3.org/2001/04/xmlenc#sha256': 'sha256', // 注意 xmlenc core 1.0 sha256 uri
    'http://www.w3.org/2000/09/xmldsig#sha256': 'sha256',
    'http://www.w3.org/2001/04/xmlenc#sha512': 'sha512',
    'http://www.w3.org/2000/09/xmldsig#sha512': 'sha512',
    'http://www.w3.org/2001/04/xmlenc#sha224': 'sha224',
    'http://www.w3.org/2000/09/xmldsig#sha224': 'sha224',
    'http://www.w3.org/2001/04/xmlenc#sha384': 'sha384',
    'http://www.w3.org/2000/09/xmldsig#sha384': 'sha384',
};

// XML Enc 1.1 MGF1 URI 映射
const mgfUriToNameMap = {
    'http://www.w3.org/2009/xmlenc11#mgf1sha1': 'sha1',
    'http://www.w3.org/2009/xmlenc11#mgf1sha224': 'sha224',
    'http://www.w3.org/2009/xmlenc11#mgf1sha256': 'sha256',
    'http://www.w3.org/2009/xmlenc11#mgf1sha384': 'sha384',
    'http://www.w3.org/2009/xmlenc11#mgf1sha512': 'sha512',
};

function getDigestNameFromUri(uri) {
    return digestUriToNameMap[uri] || 'sha1';
}

function getMgfNameFromUri(uri) {
    return mgfUriToNameMap[uri];
}

function encryptKeyInfoWithScheme(symmetricKey, options, padding, oaepHash, callback) {
    const symmetricKeyBuffer = Buffer.isBuffer(symmetricKey) ? symmetricKey : Buffer.from(symmetricKey, 'utf-8');

    try {
        let encrypted = crypto.publicEncrypt({
            key: options.rsa_pub,
            oaepHash: padding === crypto.constants.RSA_PKCS1_OAEP_PADDING ? oaepHash : undefined,
            padding: padding
        }, symmetricKeyBuffer);
        let base64EncodedEncryptedKey = encrypted.toString('base64');

        let params = {
            encryptedKey: base64EncodedEncryptedKey,
            encryptionPublicCert: '<X509Data><X509Certificate>' + pemToCert(options.pem.toString()) + '</X509Certificate></X509Data>',
            keyEncryptionMethod: options.keyEncryptionAlgorithm,
            keyEncryptionDigest: getDigestNameFromUri(options.keyEncryptionDigest),
        };

        let result = renderTemplate('keyinfo', params);
        callback(null, result);
    } catch (e) {
        callback(e);
    }
}

function encryptKeyInfo(symmetricKey, options, callback) {
    if (!options) return callback(new Error('must provide options'));
    if (!options.rsa_pub) return callback(new Error('must provide options.rsa_pub with public key RSA'));
    if (!options.pem) return callback(new Error('must provide options.pem with certificate'));
    if (!options.keyEncryptionAlgorithm) return callback(new Error('encryption without encrypted key is not supported yet'));

    if (options.disallowEncryptionWithInsecureAlgorithm && insecureAlgorithms.indexOf(options.keyEncryptionAlgorithm) >= 0) {
        return callback(new Error('encryption algorithm ' + options.keyEncryptionAlgorithm + ' is not secure'));
    }

    // 默认 Digest
    options.keyEncryptionDigest = options.keyEncryptionDigest || 'http://www.w3.org/2000/09/xmldsig#sha1';

    switch (options.keyEncryptionAlgorithm) {
        case 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p':
        case 'http://www.w3.org/2009/xmlenc11#rsa-oaep': // 支持新 URI
            const standardDigest = getDigestNameFromUri(options.keyEncryptionDigest);
            // 注意：加密时如果未指定 MGF1，通常默认与 OAEP Hash 相同。
            // 如果需要生成特定的 MGF1 (不同于 OAEP Hash)，需要更复杂的逻辑，此处暂按标准处理
            return encryptKeyInfoWithScheme(symmetricKey, options, crypto.constants.RSA_PKCS1_OAEP_PADDING, standardDigest, callback);

        case 'http://www.w3.org/2001/04/xmlenc#rsa-1_5':
            warnInsecureAlgorithm(options.keyEncryptionAlgorithm, options.warnInsecureAlgorithm);
            return encryptKeyInfoWithScheme(symmetricKey, options, crypto.constants.RSA_PKCS1_PADDING, 'sha1', callback);

        default:
            return callback(new Error('encryption key algorithm not supported: ' + options.keyEncryptionAlgorithm));
    }
}
function encrypt(content, options, callback) {
    if (!options)
        return callback(new Error('must provide options'));
    if (!content)
        return callback(new Error('must provide content to encrypt'));
    if (!options.rsa_pub)
        return callback(new Error('rsa_pub option is mandatory and you should provide a valid RSA public key'));
    if (!options.pem)
        return callback(new Error('pem option is mandatory and you should provide a valid x509 certificate encoded as PEM'));
    if (options.disallowEncryptionWithInsecureAlgorithm
        && (insecureAlgorithms.indexOf(options.keyEncryptionAlgorithm) >= 0
            || insecureAlgorithms.indexOf(options.encryptionAlgorithm) >= 0)) {
        return callback(new Error('encryption algorithm ' + options.keyEncryptionAlgorithm + ' is not secure'));
    }
    options.input_encoding = options.input_encoding || 'utf8';

    function generate_symmetric_key(cb) {
        switch (options.encryptionAlgorithm) {
            case 'http://www.w3.org/2001/04/xmlenc#aes128-cbc':
                crypto.randomBytes(16, cb); // generate a symmetric random key 16 bytes length
                break;
            case 'http://www.w3.org/2001/04/xmlenc#aes192-cbc':
                crypto.randomBytes(24, cb); // generate a symmetric random key 24 bytes length
                break;
            case 'http://www.w3.org/2001/04/xmlenc#aes256-cbc':
                crypto.randomBytes(32, cb); // generate a symmetric random key 32 bytes length
                break;
            case 'http://www.w3.org/2009/xmlenc11#aes128-gcm':
                crypto.randomBytes(16, cb); // generate a symmetric random key 16 bytes length
                break;
            case 'http://www.w3.org/2009/xmlenc11#aes192-gcm':
                crypto.randomBytes(24, cb); // generate a symmetric random key 24 bytes length
                break;
            case 'http://www.w3.org/2009/xmlenc11#aes256-gcm':
                crypto.randomBytes(32, cb); // generate a symmetric random key 32 bytes length
                break;
            case 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc':
                warnInsecureAlgorithm(options.encryptionAlgorithm, options.warnInsecureAlgorithm);
                crypto.randomBytes(24, cb); // generate a symmetric random key 24 bytes (192 bits) length
                break;
            default:
                crypto.randomBytes(32, cb); // generate a symmetric random key 32 bytes length
        }
    }

    function encrypt_content(symmetricKey, cb) {
        switch (options.encryptionAlgorithm) {
            case 'http://www.w3.org/2001/04/xmlenc#aes128-cbc':
                encryptWithAlgorithm('aes-128-cbc', symmetricKey, 16, content, options.input_encoding, function (err, encryptedContent) {
                    if (err) return cb(err);
                    cb(null, encryptedContent);
                });
                break;
            case 'http://www.w3.org/2001/04/xmlenc#aes192-cbc':
                encryptWithAlgorithm('aes-192-cbc', symmetricKey, 16, content, options.input_encoding, function (err, encryptedContent) {
                    if (err) return cb(err);
                    cb(null, encryptedContent);
                });
                break;
            case 'http://www.w3.org/2001/04/xmlenc#aes256-cbc':
                encryptWithAlgorithm('aes-256-cbc', symmetricKey, 16, content, options.input_encoding, function (err, encryptedContent) {
                    if (err) return cb(err);
                    cb(null, encryptedContent);
                });
                break;
            case 'http://www.w3.org/2009/xmlenc11#aes128-gcm':
                encryptWithAlgorithm('aes-128-gcm', symmetricKey, 12, content, options.input_encoding, function (err, encryptedContent) {
                    if (err) return cb(err);
                    cb(null, encryptedContent);
                });
                break;
            case 'http://www.w3.org/2009/xmlenc11#aes192-gcm':
                encryptWithAlgorithm('aes-192-gcm', symmetricKey, 12, content, options.input_encoding, function (err, encryptedContent) {
                    if (err) return cb(err);
                    cb(null, encryptedContent);
                });
                break;
            case 'http://www.w3.org/2009/xmlenc11#aes256-gcm':
                encryptWithAlgorithm('aes-256-gcm', symmetricKey, 12, content, options.input_encoding, function (err, encryptedContent) {
                    if (err) return cb(err);
                    cb(null, encryptedContent);
                });
                break;
            case 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc':
                warnInsecureAlgorithm(options.encryptionAlgorithm, options.warnInsecureAlgorithm);
                encryptWithAlgorithm('des-ede3-cbc', symmetricKey, 8, content, options.input_encoding, function (err, encryptedContent) {
                    if (err) return cb(err);
                    cb(null, encryptedContent);
                });
                break;
            default:
                cb(new Error('encryption algorithm not supported'));
        }
    }

    function encrypt_key(symmetricKey, encryptedContent, cb) {
        encryptKeyInfo(symmetricKey, options, function(err, keyInfo) {
            if (err) return cb(err);
            let result = renderTemplate('encrypted-key', {
                encryptedContent: encryptedContent.toString('base64'),
                keyInfo: keyInfo,
                contentEncryptionMethod: options.encryptionAlgorithm
            });

            cb(null, result);
        });
    }


    generate_symmetric_key(function (genKeyError, symmetricKey) {
        if (genKeyError) {
            return callback(genKeyError);
        }

        encrypt_content(symmetricKey, function(encryptContentError, encryptedContent) {
            if (encryptContentError) {
                return callback(encryptContentError);
            }

            encrypt_key(symmetricKey, encryptedContent, function (encryptKeyError, result) {
                if (encryptKeyError) {
                    return callback(encryptKeyError);
                }

                callback(null, result);
            });

        });

    });
}
// ... (encrypt 函数保持不变，略) ...
// 为了简洁，假设 encrypt 函数逻辑不需要大改，主要是 decrypt 部分

function decrypt(xml, options, callback) {
    if (!options) return callback(new Error('must provide options'));
    if (!xml) return callback(new Error('must provide XML to encrypt'));
    if (!options.key) return callback(new Error('key option is mandatory and you should provide a valid RSA private key'));

    try {
        let doc = typeof xml === 'string' ? new DOMParser().parseFromString(xml) : xml;

        // 1. 解密 Key Info 获取对称密钥
        let symmetricKey;
        try {
            symmetricKey = decryptKeyInfo(doc, options);
        } catch (keyErr) {
            return callback(keyErr);
        }

        // 2. 获取内容加密算法
        let encryptionMethod = xpath.select("//*[local-name(.)='EncryptedData']/*[local-name(.)='EncryptionMethod']", doc)[0];
        if (!encryptionMethod) {
            // 尝试在 EncryptedAssertion 下找
            encryptionMethod = xpath.select("//*[local-name(.)='EncryptedAssertion']//*[local-name(.)='EncryptedData']/*[local-name(.)='EncryptionMethod']", doc)[0];
        }

        if (!encryptionMethod) return callback(new Error('Cannot find EncryptionMethod for content'));

        let encryptionAlgorithm = encryptionMethod.getAttribute('Algorithm');

        if (options.disallowDecryptionWithInsecureAlgorithm && insecureAlgorithms.indexOf(encryptionAlgorithm) >= 0) {
            return callback(new Error('encryption algorithm ' + encryptionAlgorithm + ' is not secure, fail to decrypt'));
        }

        // 3. 获取加密内容 (处理 EncryptedAssertion 嵌套情况)
        let encryptedDataElem = xpath.select("//*[local-name(.)='EncryptedData' and namespace-uri(.)='http://www.w3.org/2001/04/xmlenc#']", doc)[0];
        // 如果是 EncryptedAssertion，可能需要找内部的 EncryptedData，上面的 xpath 应该能抓到最外层的 EncryptedData

        let cipherValueElem = xpath.select(".//*[local-name(.)='CipherValue']", encryptedDataElem)[0];

        if (!cipherValueElem) return callback(new Error('Cannot find CipherValue'));

        let encrypted = Buffer.from(cipherValueElem.textContent, 'base64');

        // 4. 执行内容解密
        switch (encryptionAlgorithm) {
            case 'http://www.w3.org/2001/04/xmlenc#aes128-cbc':
                return callback(null, decryptWithAlgorithm('aes-128-cbc', symmetricKey, 16, encrypted));
            case 'http://www.w3.org/2001/04/xmlenc#aes192-cbc':
                return callback(null, decryptWithAlgorithm('aes-192-cbc', symmetricKey, 16, encrypted));
            case 'http://www.w3.org/2001/04/xmlenc#aes256-cbc':
                return callback(null, decryptWithAlgorithm('aes-256-cbc', symmetricKey, 16, encrypted));
            case 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc':
                warnInsecureAlgorithm(encryptionAlgorithm, options.warnInsecureAlgorithm);
                return callback(null, decryptWithAlgorithm('des-ede3-cbc', symmetricKey, 8, encrypted));
            case 'http://www.w3.org/2009/xmlenc11#aes128-gcm':
                return callback(null, decryptWithAlgorithm('aes-128-gcm', symmetricKey, 12, encrypted));
            case 'http://www.w3.org/2009/xmlenc11#aes192-gcm':
                return callback(null, decryptWithAlgorithm('aes-192-gcm', symmetricKey, 12, encrypted));
            case 'http://www.w3.org/2009/xmlenc11#aes256-gcm':
                return callback(null, decryptWithAlgorithm('aes-256-gcm', symmetricKey, 12, encrypted));
            default:
                return callback(new Error('content encryption algorithm ' + encryptionAlgorithm + ' not supported'));
        }
    } catch (e) {
        return callback(e);
    }
}

function decryptKeyInfo(doc, options) {
    if (typeof doc === 'string') doc = new DOMParser().parseFromString(doc);

    let keyInfo = xpath.select("//*[local-name(.)='KeyInfo' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']", doc)[0];
    if (!keyInfo) {
        keyInfo = xpath.select("//*[local-name(.)='EncryptedData']/*[local-name(.)='KeyInfo']", doc)[0];
    }
    if (!keyInfo) {
        // 尝试在 EncryptedAssertion -> EncryptedData -> KeyInfo
        keyInfo = xpath.select("//*[local-name(.)='EncryptedAssertion']//*[local-name(.)='EncryptedData']/*[local-name(.)='KeyInfo']", doc)[0];
    }

    if (!keyInfo) throw new Error('cant find KeyInfo');

    let keyEncryptionMethod = xpath.select("./*[local-name(.)='EncryptedKey']/*[local-name(.)='EncryptionMethod']", keyInfo)[0];

    // 兼容 RetrievalMethod 逻辑 (原有代码保留)
    if (!keyEncryptionMethod) {
        let keyRetrievalMethod = xpath.select("./*[local-name(.)='RetrievalMethod']", keyInfo)[0];
        let keyRetrievalMethodUri = keyRetrievalMethod ? keyRetrievalMethod.getAttribute('URI') : null;
        keyEncryptionMethod = keyRetrievalMethodUri ? xpath.select("//*[local-name(.)='EncryptedKey' and @Id='" + keyRetrievalMethodUri.substring(1) + "']/*[local-name(.)='EncryptionMethod']", doc)[0] : null;
    }

    if (!keyEncryptionMethod) throw new Error('cant find encryption algorithm');

    let keyEncryptionAlgorithm = keyEncryptionMethod.getAttribute('Algorithm');

    // 解析 OAEP Hash (DigestMethod)
    let oaepHash = 'sha1';
    const keyDigestMethod = xpath.select("./*[local-name(.)='DigestMethod']", keyEncryptionMethod)[0];
    if (keyDigestMethod) {
        const uri = keyDigestMethod.getAttribute('Algorithm');
        oaepHash = getDigestNameFromUri(uri);
    }

    // 解析 MGF1 Algorithm (XML Enc 1.1 特有)
    let mgf1Hash = oaepHash; // 默认与 OAEP Hash 相同
    const mgfElement = xpath.select("./*[local-name(.)='MGF']", keyEncryptionMethod)[0];
    if (mgfElement) {
        const mgfUri = mgfElement.getAttribute('Algorithm');
        const mappedMgf = getMgfNameFromUri(mgfUri);
        if (mappedMgf) {
            mgf1Hash = mappedMgf;
        }
    }

    if (options.disallowDecryptionWithInsecureAlgorithm && insecureAlgorithms.indexOf(keyEncryptionAlgorithm) >= 0) {
        throw new Error('encryption algorithm ' + keyEncryptionAlgorithm + ' is not secure, fail to decrypt');
    }

    let encryptedKeyElem;
    // 查找 EncryptedKey 的 CipherValue
    // 逻辑：先找直接的 EncryptedKey/CipherData/CipherValue，或者通过 RetrievalMethod
    let keyRetrievalMethodUri = null;
    let rm = xpath.select("./*[local-name(.)='RetrievalMethod']", keyInfo)[0];
    if(rm) keyRetrievalMethodUri = rm.getAttribute('URI');

    if (keyRetrievalMethodUri) {
        encryptedKeyElem = xpath.select("//*[local-name(.)='EncryptedKey' and @Id='" + keyRetrievalMethodUri.substring(1) + "']/*[local-name(.)='CipherData']/*[local-name(.)='CipherValue']", doc)[0];
    } else {
        encryptedKeyElem = xpath.select("./*[local-name(.)='EncryptedKey']/*[local-name(.)='CipherData']/*[local-name(.)='CipherValue']", keyInfo)[0];
    }

    if (!encryptedKeyElem) throw new Error('cant find encrypted key value');

    // 根据算法选择解密策略
    switch (keyEncryptionAlgorithm) {
        case 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p':
            // 旧标准，通常 MGF1 == OAEP Hash，直接使用 crypto
            return decryptKeyInfoWithSchemeNative(encryptedKeyElem, options, crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash);

        case 'http://www.w3.org/2009/xmlenc11#rsa-oaep':
            // 新标准，检查 MGF1 是否一致
            if (mgf1Hash === oaepHash) {
                // 一致时使用原生 crypto
                return decryptKeyInfoWithSchemeNative(encryptedKeyElem, options, crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash);
            } else {
                // 不一致 (混合哈希)，必须使用 node-forge
                if (!forge) {
                    throw new Error(`Detected RSA-OAEP with mismatched hashes (OAEP: ${oaepHash}, MGF1: ${mgf1Hash}). Node.js native crypto does not support this combination. Please install 'node-forge'.`);
                }
                return decryptKeyInfoWithSchemeForge(encryptedKeyElem, options, oaepHash, mgf1Hash);
            }

        case 'http://www.w3.org/2001/04/xmlenc#rsa-1_5':
            warnInsecureAlgorithm(keyEncryptionAlgorithm, options.warnInsecureAlgorithm);
            return decryptKeyInfoWithSchemeNative(encryptedKeyElem, options, crypto.constants.RSA_PKCS1_PADDING, 'sha1');

        default:
            throw new Error('key encryption algorithm ' + keyEncryptionAlgorithm + ' not supported');
    }
}

// 原生 Crypto 解密 (适用于 MGF1 == OAEP Hash)
function decryptKeyInfoWithSchemeNative(encryptedKeyElem, options, padding, oaepHash) {
    const key = Buffer.from(encryptedKeyElem.textContent, 'base64');
    try {
        const decrypted = crypto.privateDecrypt({
            key: options.key,
            padding,
            oaepHash
        }, key);
        return Buffer.from(decrypted, 'binary');
    } catch (e) {
        throw new Error('Failed to decrypt key with native crypto: ' + e.message);
    }
}

// Forge 解密 (适用于 MGF1 != OAEP Hash)
function decryptKeyInfoWithSchemeForge(encryptedKeyElem, options, oaepHashAlg, mgf1HashAlg) {
    const encryptedKeyBase64 = encryptedKeyElem.textContent;
    const privateKeyPem = options.key; // 期望是 PEM 字符串

    // 转换私钥
    const pkey = forge.pki.privateKeyFromPem(privateKeyPem);

    // 转换密文
    const encrypted = forge.util.decode64(encryptedKeyBase64);

    // 执行 RSA-OAEP 解密
    // forge 允许明确指定 md 和 mgf1
    const md = forge.md[oaepHashAlg].create();
    const mgf1 = forge.mgf.mgf1.create(forge.md[mgf1HashAlg].create());

    try {
        const decrypted = pkey.decrypt(encrypted, 'RSA-OAEP', {
            md: md,
            mgf1: mgf1
        });
        return Buffer.from(decrypted, 'binary'); // forge 返回的是 binary string
    } catch (e) {
        throw new Error('Failed to decrypt key with node-forge: ' + e.message);
    }
}

// ... (encryptWithAlgorithm 和 decryptWithAlgorithm 保持不变) ...
function encryptWithAlgorithm(algorithm, symmetricKey, ivLength, content, encoding, callback) {
    crypto.randomBytes(ivLength, function(err, iv) {
        if (err) return callback(err);
        let cipher = crypto.createCipheriv(algorithm, symmetricKey, iv);
        let encrypted = cipher.update(content, encoding, 'binary') + cipher.final('binary');
        let authTag = algorithm.slice(-3) === "gcm" ? cipher.getAuthTag() : Buffer.from("");
        let r = Buffer.concat([iv, Buffer.from(encrypted, 'binary'), authTag]);
        return callback(null, r);
    });
}

function decryptWithAlgorithm(algorithm, symmetricKey, ivLength, content) {
    let decipher = crypto.createDecipheriv(algorithm, symmetricKey, content.slice(0, ivLength));
    decipher.setAutoPadding(false);

    if (algorithm.slice(-3) === "gcm") {
        decipher.setAuthTag(content.slice(-16));
        content = content.slice(0, -16);
    }
    let decrypted = decipher.update(content.slice(ivLength), null, 'binary') + decipher.final('binary');

    if (algorithm.slice(-3) !== "gcm") {
        let padding = decrypted.charCodeAt(decrypted.length - 1);
        if (1 <= padding && padding <= ivLength) {
            decrypted = decrypted.substr(0, decrypted.length - padding);
        } else {
            throw new Error('padding length invalid');
        }
    }
    return Buffer.from(decrypted, 'binary').toString('utf8');
}

export {
    decrypt,
    encrypt,
    encryptKeyInfo,
    decryptKeyInfo
};