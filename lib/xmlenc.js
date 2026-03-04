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
    if (!options) return callback(/* @__PURE__ */ new Error("must provide options"));
    if (!xml) return callback(/* @__PURE__ */ new Error("must provide XML to decrypt"));
    if (!options.key) return callback(/* @__PURE__ */ new Error("key option is mandatory (RSA private key PEM)"));

    try {
        const doc = typeof xml === "string" ? new DOMParser().parseFromString(xml) : xml;

        // 1. 解密对称密钥（已使用 local-name）
        let symmetricKey;
        try {
            symmetricKey = decryptKeyInfo(doc, options);
        } catch (e) {
            return callback(/* @__PURE__ */ new Error("Failed to decrypt symmetric key: " + e.message));
        }

        // 2. 查找 EncryptedData —— 使用 local-name()，不再用 nsResolver
        let encData = xpath.select1("//*[local-name()='EncryptedData']", doc);
        if (!encData) {
            encData = xpath.select1("//*[local-name()='EncryptedAssertion']//*[local-name()='EncryptedData']", doc);
        }
        if (!encData) {
            return callback(/* @__PURE__ */ new Error("Cannot find EncryptedData"));
        }

        // 3. 获取内容加密算法
        const encMethod = xpath.select1(".//*[local-name()='EncryptionMethod']", encData);
        if (!encMethod) {
            return callback(/* @__PURE__ */ new Error("Cannot find content EncryptionMethod"));
        }
        const contentAlg = encMethod.getAttribute("Algorithm");

        if (options.disallowDecryptionWithInsecureAlgorithm && insecureAlgorithms.includes(contentAlg)) {
            return callback(/* @__PURE__ */ new Error(`Content encryption algorithm ${contentAlg} is insecure`));
        }

        // 4. 获取密文
        const cipherValue = xpath.select1(".//*[local-name()='CipherValue']", encData);
        if (!cipherValue) {
            return callback(/* @__PURE__ */ new Error("Cannot find content CipherValue"));
        }
        const encryptedContent = Buffer.from(cipherValue.textContent.trim(), "base64");

        // 5. 解密内容
        let result;
        switch (contentAlg) {
            case "http://www.w3.org/2001/04/xmlenc#aes128-cbc":
                result = decryptWithAlgorithm("aes-128-cbc", symmetricKey, 16, encryptedContent);
                break;
            case "http://www.w3.org/2001/04/xmlenc#aes192-cbc":
                result = decryptWithAlgorithm("aes-192-cbc", symmetricKey, 16, encryptedContent);
                break;
            case "http://www.w3.org/2001/04/xmlenc#aes256-cbc":
                result = decryptWithAlgorithm("aes-256-cbc", symmetricKey, 16, encryptedContent);
                break;
            case "http://www.w3.org/2009/xmlenc11#aes128-gcm":
                result = decryptWithAlgorithm("aes-128-gcm", symmetricKey, 12, encryptedContent);
                break;
            case "http://www.w3.org/2009/xmlenc11#aes192-gcm":
                result = decryptWithAlgorithm("aes-192-gcm", symmetricKey, 12, encryptedContent);
                break;
            case "http://www.w3.org/2009/xmlenc11#aes256-gcm":
                result = decryptWithAlgorithm("aes-256-gcm", symmetricKey, 12, encryptedContent);
                break;
            case "http://www.w3.org/2001/04/xmlenc#tripledes-cbc":
                warnInsecureAlgorithm(contentAlg, options.warnInsecureAlgorithm);
                result = decryptWithAlgorithm("des-ede3-cbc", symmetricKey, 8, encryptedContent);
                break;
            default:
                return callback(/* @__PURE__ */ new Error(`Unsupported content encryption algorithm: ${contentAlg}`));
        }

        callback(null, result);
    } catch (e) {
        callback(e);
    }
}

function decryptKeyInfo(doc, options) {
    console.log("999999999999999999到这里1111111111111");
    if (typeof doc === "string") {
        doc = new DOMParser().parseFromString(doc);
    }

    // ✅ 不再使用 nsResolver，全部用 local-name()
    let keyInfo = xpath.select1("//*[local-name()='KeyInfo']", doc);
    console.log("2222222222222222999999999999999999到这里1111111111111");
    if (!keyInfo) {
        keyInfo = xpath.select1("//*[local-name()='EncryptedData']/*[local-name()='KeyInfo']", doc);
    }
    if (!keyInfo) {
        keyInfo = xpath.select1("//*[local-name()='EncryptedAssertion']//*[local-name()='EncryptedData']/*[local-name()='KeyInfo']", doc);
    }
    if (!keyInfo) {
        throw new Error("Cannot find KeyInfo");
    }
    console.log("2222222222222来到这里1111111111111");

    let encryptedKeyNode = xpath.select1("./*[local-name()='EncryptedKey']", keyInfo);
    if (!encryptedKeyNode) {
        const retrieval = xpath.select1("./*[local-name()='RetrievalMethod']", keyInfo);
        if (retrieval) {
            const uri = retrieval.getAttribute("URI");
            if (uri && uri.startsWith("#")) {
                const id = uri.substring(1);
                encryptedKeyNode = xpath.select1(`//*[@Id='${id}'][local-name()='EncryptedKey']`, doc);
                // 注意：有些文档用 xml:id 而非 Id，但 SAML 通常用 Id 属性
                if (!encryptedKeyNode) {
                    encryptedKeyNode = xpath.select1(`//*[@*[local-name()='Id']='${id}'][local-name()='EncryptedKey']`, doc);
                }
            }
        }
    }
    if (!encryptedKeyNode) {
        throw new Error("Cannot find EncryptedKey");
    }

    const encryptionMethod = xpath.select1("./*[local-name()='EncryptionMethod']", encryptedKeyNode);
    if (!encryptionMethod) {
        throw new Error("Cannot find EncryptionMethod in EncryptedKey");
    }
    const algUri = encryptionMethod.getAttribute("Algorithm");
    console.log("555555555555555555来到这里1111111111111");

    if (options.disallowDecryptionWithInsecureAlgorithm && insecureAlgorithms.includes(algUri)) {
        throw new Error(`Key encryption algorithm ${algUri} is insecure and disallowed.`);
    }

    const cipherValueElem = xpath.select1("./*[local-name()='CipherData']/*[local-name()='CipherValue']", encryptedKeyNode);
    if (!cipherValueElem || !cipherValueElem.textContent) {
        throw new Error("Cannot find CipherValue in EncryptedKey");
    }
    const encryptedKeyBase64 = cipherValueElem.textContent.trim();

    if (algUri === "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p") {
        console.log("[decryptKeyInfo] Using legacy rsa-oaep-mgf1p → forcing SHA-1");
        return decryptKeyInfoWithForge(encryptedKeyBase64, options.key, "sha1", "sha1");
    } else if (algUri === "http://www.w3.org/2009/xmlenc11#rsa-oaep") {
        console.log("来到这里1111111111111");
        let oaepHash = "sha1";
        let mgf1Hash = "sha1";

        const digestMethod = xpath.select1("./*[local-name()='DigestMethod']", encryptionMethod);
        if (digestMethod) {
            oaepHash = getDigestNameFromUri(digestMethod.getAttribute("Algorithm"));
        }

        const mgfElem = xpath.select1("./*[local-name()='MGF']", encryptionMethod);
        if (mgfElem) {
            const resolvedMgf = getMgfNameFromUri(mgfElem.getAttribute("Algorithm"));
            if (resolvedMgf) {
                mgf1Hash = resolvedMgf;
            } else {
                mgf1Hash = oaepHash;
            }
        }

        console.log(`[decryptKeyInfo] Using RSA-OAEP with Digest=${oaepHash}, MGF1=${mgf1Hash}`);
        return decryptKeyInfoWithForge(encryptedKeyBase64, options.key, oaepHash, mgf1Hash);
    } else if (algUri === "http://www.w3.org/2001/04/xmlenc#rsa-1_5") {
        warnInsecureAlgorithm(algUri, options.warnInsecureAlgorithm);
        const keyBuf = Buffer.from(encryptedKeyBase64, "base64");
        try {
            const decrypted = crypto.privateDecrypt({
                key: options.key,
                padding: crypto.constants.RSA_PKCS1_PADDING
            }, keyBuf);
            return Buffer.from(decrypted, "binary");
        } catch (e) {
            throw new Error("Failed to decrypt RSA-1_5 key: " + e.message);
        }
    } else {
        throw new Error(`Unsupported key encryption algorithm: ${algUri}`);
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