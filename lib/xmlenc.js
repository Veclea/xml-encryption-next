import crypto from 'crypto';
import { DOMParser } from '@xmldom/xmldom';
import xpath from 'xpath';
import { renderTemplate, pemToCert, warnInsecureAlgorithm } from './utils.js';

// 强制使用 node-forge 处理所有 OAEP（包括 hash 不一致的情况）
import forge from 'node-forge';

const insecureAlgorithms = [
    'http://www.w3.org/2001/04/xmlenc#rsa-1_5',
    'http://www.w3.org/2001/04/xmlenc#tripledes-cbc'
];

// Digest URI 映射
const digestUriToNameMap = {
    'http://www.w3.org/2000/09/xmldsig#sha1': 'sha1',
    'http://www.w3.org/2001/04/xmlenc#sha256': 'sha256',
    'http://www.w3.org/2000/09/xmldsig#sha256': 'sha256',
    'http://www.w3.org/2001/04/xmlenc#sha512': 'sha512',
    'http://www.w3.org/2000/09/xmldsig#sha512': 'sha512',
    'http://www.w3.org/2001/04/xmlenc#sha224': 'sha224',
    'http://www.w3.org/2000/09/xmldsig#sha224': 'sha224',
    'http://www.w3.org/2001/04/xmlenc#sha384': 'sha384',
    'http://www.w3.org/2000/09/xmldsig#sha384': 'sha384',
};

// MGF1 URI 映射 (XML Encryption 1.1)
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

// ======================
// Forge-based OAEP 解密
// ======================
function decryptKeyInfoWithForge(encryptedKeyBase64, privateKeyPem, oaepHashAlg, mgf1HashAlg) {
    if (!forge) {
        throw new Error('node-forge is required for RSA-OAEP decryption but not available.');
    }

    try {
        const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
        const encrypted = forge.util.decode64(encryptedKeyBase64);

        const md = forge.md[oaepHashAlg]?.create();
        const mgf1 = forge.mgf.mgf1.create(forge.md[mgf1HashAlg]?.create());

        if (!md || !mgf1) {
            throw new Error(`Unsupported hash algorithm: OAEP=${oaepHashAlg}, MGF1=${mgf1HashAlg}`);
        }

        const decryptedBinary = privateKey.decrypt(encrypted, 'RSA-OAEP', {
            md: md,
            mgf1: mgf1
        });

        return Buffer.from(decryptedBinary, 'binary');
    } catch (e) {
        throw new Error(`Forge RSA-OAEP decryption failed: ${e.message}`);
    }
}

// ======================
// KeyInfo 解密主函数
// ======================
function decryptKeyInfo(doc, options) {
    if (typeof doc === 'string') {
        doc = new DOMParser().parseFromString(doc);
    }

    // 命名空间映射
    const nsResolver = {
        lookupNamespaceURI(prefix) {
            switch (prefix) {
                case 'ds': return 'http://www.w3.org/2000/09/xmldsig#';
                case 'xenc': return 'http://www.w3.org/2001/04/xmlenc#';
                case 'xenc11': return 'http://www.w3.org/2009/xmlenc11#';
                default: return null;
            }
        }
    };

    // 查找 KeyInfo
    let keyInfo = xpath.select1("//ds:KeyInfo", doc, nsResolver);
    if (!keyInfo) {
        keyInfo = xpath.select1("//xenc:EncryptedData/ds:KeyInfo", doc, nsResolver);
    }
    if (!keyInfo) {
        keyInfo = xpath.select1("//xenc:EncryptedAssertion//xenc:EncryptedData/ds:KeyInfo", doc, nsResolver);
    }
    if (!keyInfo) {
        throw new Error('Cannot find KeyInfo');
    }

    // 查找 EncryptedKey
    let encryptedKeyNode = xpath.select1("./xenc:EncryptedKey", keyInfo, nsResolver);
    if (!encryptedKeyNode) {
        // 尝试 RetrievalMethod
        const retrieval = xpath.select1("./ds:RetrievalMethod", keyInfo, nsResolver);
        if (retrieval) {
            const uri = retrieval.getAttribute('URI');
            if (uri && uri.startsWith('#')) {
                const id = uri.substring(1);
                encryptedKeyNode = xpath.select1(`//xenc:EncryptedKey[@Id='${id}']`, doc, nsResolver);
            }
        }
    }
    if (!encryptedKeyNode) {
        throw new Error('Cannot find EncryptedKey');
    }

    const encryptionMethod = xpath.select1("./xenc:EncryptionMethod", encryptedKeyNode, nsResolver);
    if (!encryptionMethod) {
        throw new Error('Cannot find EncryptionMethod in EncryptedKey');
    }

    const algUri = encryptionMethod.getAttribute('Algorithm');

    if (options.disallowDecryptionWithInsecureAlgorithm && insecureAlgorithms.includes(algUri)) {
        throw new Error(`Key encryption algorithm ${algUri} is insecure and disallowed.`);
    }

    const cipherValueElem = xpath.select1("./xenc:CipherData/xenc:CipherValue", encryptedKeyNode, nsResolver);
    if (!cipherValueElem || !cipherValueElem.textContent) {
        throw new Error('Cannot find CipherValue in EncryptedKey');
    }

    const encryptedKeyBase64 = cipherValueElem.textContent.trim();

    // ===== 根据算法 URI 分支处理 =====
    if (algUri === 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p') {
        // 旧标准：强制 SHA-1
        console.log('[decryptKeyInfo] Using legacy rsa-oaep-mgf1p → forcing SHA-1');
        return decryptKeyInfoWithForge(encryptedKeyBase64, options.key, 'sha1', 'sha1');
    } else if (algUri === 'http://www.w3.org/2009/xmlenc11#rsa-oaep') {
        // 新标准：解析 DigestMethod 和 MGF
        let oaepHash = 'sha1';
        let mgf1Hash = 'sha1';

        const digestMethod = xpath.select1("./ds:DigestMethod", encryptionMethod, nsResolver);
        if (digestMethod) {
            const digestUri = digestMethod.getAttribute('Algorithm');
            oaepHash = getDigestNameFromUri(digestUri);
        }

        const mgfElem = xpath.select1("./xenc11:MGF", encryptionMethod, nsResolver);
        if (mgfElem) {
            const mgfUri = mgfElem.getAttribute('Algorithm');
            const resolvedMgf = getMgfNameFromUri(mgfUri);
            if (resolvedMgf) mgf1Hash = resolvedMgf;
            else mgf1Hash = oaepHash; // fallback
        }

        console.log(`[decryptKeyInfo] Using RSA-OAEP with Digest=${oaepHash}, MGF1=${mgf1Hash}`);
        return decryptKeyInfoWithForge(encryptedKeyBase64, options.key, oaepHash, mgf1Hash);
    } else if (algUri === 'http://www.w3.org/2001/04/xmlenc#rsa-1_5') {
        warnInsecureAlgorithm(algUri, options.warnInsecureAlgorithm);
        // RSA-1_5 仍用原生 crypto（简单且 forge 非必需）
        const keyBuf = Buffer.from(encryptedKeyBase64, 'base64');
        try {
            const decrypted = crypto.privateDecrypt({
                key: options.key,
                padding: crypto.constants.RSA_PKCS1_PADDING
            }, keyBuf);
            return Buffer.from(decrypted, 'binary');
        } catch (e) {
            throw new Error('Failed to decrypt RSA-1_5 key: ' + e.message);
        }
    } else {
        throw new Error(`Unsupported key encryption algorithm: ${algUri}`);
    }
}

// ======================
// 内容解密辅助函数
// ======================
function decryptWithAlgorithm(algorithm, symmetricKey, ivLength, content) {
    let decipher = crypto.createDecipheriv(algorithm, symmetricKey, content.slice(0, ivLength));
    decipher.setAutoPadding(false);

    if (algorithm.endsWith('gcm')) {
        // GCM: 最后 16 字节是 auth tag
        decipher.setAuthTag(content.slice(-16));
        content = content.slice(0, -16);
    }

    let decrypted = decipher.update(content.slice(ivLength), null, 'binary') + decipher.final('binary');

    if (!algorithm.endsWith('gcm')) {
        // CBC/PKCS#7 unpadding
        const padding = decrypted.charCodeAt(decrypted.length - 1);
        if (padding >= 1 && padding <= ivLength) {
            decrypted = decrypted.substring(0, decrypted.length - padding);
        } else {
            throw new Error('Invalid PKCS#7 padding');
        }
    }

    return Buffer.from(decrypted, 'binary').toString('utf8');
}

// ======================
// 主 decrypt 函数（保持不变，仅微调）
// ======================
function decrypt(xml, options, callback) {
    if (!options) return callback(new Error('must provide options'));
    if (!xml) return callback(new Error('must provide XML to decrypt'));
    if (!options.key) return callback(new Error('key option is mandatory (RSA private key PEM)'));

    try {
        const doc = typeof xml === 'string' ? new DOMParser().parseFromString(xml) : xml;

        // 1. 解密对称密钥
        let symmetricKey;
        try {
            symmetricKey = decryptKeyInfo(doc, options);
        } catch (e) {
            return callback(new Error('Failed to decrypt symmetric key: ' + e.message));
        }

        // 2. 获取内容加密算法
        const nsResolver = prefix => {
            if (prefix === 'xenc') return 'http://www.w3.org/2001/04/xmlenc#';
            return null;
        };
        let encData = xpath.select1("//xenc:EncryptedData", doc, nsResolver);
        if (!encData) {
            encData = xpath.select1("//xenc:EncryptedAssertion//xenc:EncryptedData", doc, nsResolver);
        }
        if (!encData) return callback(new Error('Cannot find EncryptedData'));

        const encMethod = xpath.select1(".//xenc:EncryptionMethod", encData, nsResolver);
        if (!encMethod) return callback(new Error('Cannot find content EncryptionMethod'));
        const contentAlg = encMethod.getAttribute('Algorithm');

        if (options.disallowDecryptionWithInsecureAlgorithm && insecureAlgorithms.includes(contentAlg)) {
            return callback(new Error(`Content encryption algorithm ${contentAlg} is insecure`));
        }

        // 3. 获取密文
        const cipherValue = xpath.select1(".//xenc:CipherValue", encData, nsResolver);
        if (!cipherValue) return callback(new Error('Cannot find content CipherValue'));
        const encryptedContent = Buffer.from(cipherValue.textContent.trim(), 'base64');

        // 4. 解密内容
        let result;
        switch (contentAlg) {
            case 'http://www.w3.org/2001/04/xmlenc#aes128-cbc':
                result = decryptWithAlgorithm('aes-128-cbc', symmetricKey, 16, encryptedContent);
                break;
            case 'http://www.w3.org/2001/04/xmlenc#aes192-cbc':
                result = decryptWithAlgorithm('aes-192-cbc', symmetricKey, 16, encryptedContent);
                break;
            case 'http://www.w3.org/2001/04/xmlenc#aes256-cbc':
                result = decryptWithAlgorithm('aes-256-cbc', symmetricKey, 16, encryptedContent);
                break;
            case 'http://www.w3.org/2009/xmlenc11#aes128-gcm':
                result = decryptWithAlgorithm('aes-128-gcm', symmetricKey, 12, encryptedContent);
                break;
            case 'http://www.w3.org/2009/xmlenc11#aes192-gcm':
                result = decryptWithAlgorithm('aes-192-gcm', symmetricKey, 12, encryptedContent);
                break;
            case 'http://www.w3.org/2009/xmlenc11#aes256-gcm':
                result = decryptWithAlgorithm('aes-256-gcm', symmetricKey, 12, encryptedContent);
                break;
            case 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc':
                warnInsecureAlgorithm(contentAlg, options.warnInsecureAlgorithm);
                result = decryptWithAlgorithm('des-ede3-cbc', symmetricKey, 8, encryptedContent);
                break;
            default:
                return callback(new Error(`Unsupported content encryption algorithm: ${contentAlg}`));
        }

        callback(null, result);
    } catch (e) {
        callback(e);
    }
}

// ======================
// 加密相关函数（保持原样，仅用于完整性）
// ======================
function encryptWithAlgorithm(algorithm, symmetricKey, ivLength, content, encoding, callback) {
    crypto.randomBytes(ivLength, (err, iv) => {
        if (err) return callback(err);
        const cipher = crypto.createCipheriv(algorithm, symmetricKey, iv);
        let encrypted = cipher.update(content, encoding, 'binary') + cipher.final('binary');
        const authTag = algorithm.endsWith('gcm') ? cipher.getAuthTag() : Buffer.alloc(0);
        const result = Buffer.concat([iv, Buffer.from(encrypted, 'binary'), authTag]);
        callback(null, result);
    });
}

function encryptKeyInfoWithScheme(symmetricKey, options, padding, oaepHash, callback) {
    const symmetricKeyBuffer = Buffer.isBuffer(symmetricKey) ? symmetricKey : Buffer.from(symmetricKey, 'utf-8');
    try {
        let encrypted = crypto.publicEncrypt({
            key: options.rsa_pub,
            oaepHash: padding === crypto.constants.RSA_PKCS1_OAEP_PADDING ? oaepHash : undefined,
            padding
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
    if (!options.rsa_pub) return callback(new Error('must provide options.rsa_pub'));
    if (!options.pem) return callback(new Error('must provide options.pem'));
    if (!options.keyEncryptionAlgorithm) return callback(new Error('key encryption algorithm required'));

    if (options.disallowEncryptionWithInsecureAlgorithm && insecureAlgorithms.includes(options.keyEncryptionAlgorithm)) {
        return callback(new Error('insecure key encryption algorithm disallowed'));
    }

    options.keyEncryptionDigest = options.keyEncryptionDigest || 'http://www.w3.org/2000/09/xmldsig#sha1';

    switch (options.keyEncryptionAlgorithm) {
        case 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p':
        case 'http://www.w3.org/2009/xmlenc11#rsa-oaep':
            const digest = getDigestNameFromUri(options.keyEncryptionDigest);
            return encryptKeyInfoWithScheme(symmetricKey, options, crypto.constants.RSA_PKCS1_OAEP_PADDING, digest, callback);
        case 'http://www.w3.org/2001/04/xmlenc#rsa-1_5':
            warnInsecureAlgorithm(options.keyEncryptionAlgorithm, options.warnInsecureAlgorithm);
            return encryptKeyInfoWithScheme(symmetricKey, options, crypto.constants.RSA_PKCS1_PADDING, 'sha1', callback);
        default:
            return callback(new Error('unsupported key encryption algorithm: ' + options.keyEncryptionAlgorithm));
    }
}

function encrypt(content, options, callback) {
    if (!options) return callback(new Error('must provide options'));
    if (!content) return callback(new Error('must provide content'));
    if (!options.rsa_pub) return callback(new Error('rsa_pub is mandatory'));
    if (!options.pem) return callback(new Error('pem is mandatory'));
    if (options.disallowEncryptionWithInsecureAlgorithm &&
        (insecureAlgorithms.includes(options.keyEncryptionAlgorithm) ||
            insecureAlgorithms.includes(options.encryptionAlgorithm))) {
        return callback(new Error('insecure algorithm disallowed'));
    }
    options.input_encoding = options.input_encoding || 'utf8';

    function generate_symmetric_key(cb) {
        switch (options.encryptionAlgorithm) {
            case 'http://www.w3.org/2001/04/xmlenc#aes128-cbc':
            case 'http://www.w3.org/2009/xmlenc11#aes128-gcm':
                crypto.randomBytes(16, cb);
                break;
            case 'http://www.w3.org/2001/04/xmlenc#aes192-cbc':
            case 'http://www.w3.org/2009/xmlenc11#aes192-gcm':
                crypto.randomBytes(24, cb);
                break;
            case 'http://www.w3.org/2001/04/xmlenc#aes256-cbc':
            case 'http://www.w3.org/2009/xmlenc11#aes256-gcm':
                crypto.randomBytes(32, cb);
                break;
            case 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc':
                warnInsecureAlgorithm(options.encryptionAlgorithm, options.warnInsecureAlgorithm);
                crypto.randomBytes(24, cb);
                break;
            default:
                crypto.randomBytes(32, cb);
        }
    }

    function encrypt_content(symmetricKey, cb) {
        switch (options.encryptionAlgorithm) {
            case 'http://www.w3.org/2001/04/xmlenc#aes128-cbc':
                encryptWithAlgorithm('aes-128-cbc', symmetricKey, 16, content, options.input_encoding, cb);
                break;
            case 'http://www.w3.org/2001/04/xmlenc#aes192-cbc':
                encryptWithAlgorithm('aes-192-cbc', symmetricKey, 16, content, options.input_encoding, cb);
                break;
            case 'http://www.w3.org/2001/04/xmlenc#aes256-cbc':
                encryptWithAlgorithm('aes-256-cbc', symmetricKey, 16, content, options.input_encoding, cb);
                break;
            case 'http://www.w3.org/2009/xmlenc11#aes128-gcm':
                encryptWithAlgorithm('aes-128-gcm', symmetricKey, 12, content, options.input_encoding, cb);
                break;
            case 'http://www.w3.org/2009/xmlenc11#aes192-gcm':
                encryptWithAlgorithm('aes-192-gcm', symmetricKey, 12, content, options.input_encoding, cb);
                break;
            case 'http://www.w3.org/2009/xmlenc11#aes256-gcm':
                encryptWithAlgorithm('aes-256-gcm', symmetricKey, 12, content, options.input_encoding, cb);
                break;
            case 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc':
                warnInsecureAlgorithm(options.encryptionAlgorithm, options.warnInsecureAlgorithm);
                encryptWithAlgorithm('des-ede3-cbc', symmetricKey, 8, content, options.input_encoding, cb);
                break;
            default:
                cb(new Error('unsupported content encryption algorithm'));
        }
    }

    function encrypt_key(symmetricKey, encryptedContent, cb) {
        encryptKeyInfo(symmetricKey, options, (err, keyInfo) => {
            if (err) return cb(err);
            const result = renderTemplate('encrypted-key', {
                encryptedContent: encryptedContent.toString('base64'),
                keyInfo,
                contentEncryptionMethod: options.encryptionAlgorithm
            });
            cb(null, result);
        });
    }

    generate_symmetric_key((genErr, symKey) => {
        if (genErr) return callback(genErr);
        encrypt_content(symKey, (encErr, encContent) => {
            if (encErr) return callback(encErr);
            encrypt_key(symKey, encContent, callback);
        });
    });
}

// ======================
// 导出
// ======================
export {
    decrypt,
    encrypt,
    encryptKeyInfo,
    decryptKeyInfo
};