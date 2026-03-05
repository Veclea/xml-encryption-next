import crypto from 'crypto';
import { DOMParser } from '@xmldom/xmldom';
import xpath from 'xpath';
import { renderTemplate, pemToCert, warnInsecureAlgorithm } from './utils.js';
import forge from 'node-forge'
const insecureAlgorithms = [
    //https://www.w3.org/TR/xmlenc-core1/#rsav15note
    'http://www.w3.org/2001/04/xmlenc#rsa-1_5',
    //https://csrc.nist.gov/News/2017/Update-to-Current-Use-and-Deprecation-of-TDEA
    'http://www.w3.org/2001/04/xmlenc#tripledes-cbc'];

function encryptKeyInfoWithScheme(symmetricKey, options, padding, callback) {
    const symmetricKeyBuffer = Buffer.isBuffer(symmetricKey) ? symmetricKey : Buffer.from(symmetricKey, 'utf-8');

    try {
        let encrypted = crypto.publicEncrypt({
            key: options.rsa_pub,
            oaepHash: padding == crypto.constants.RSA_PKCS1_OAEP_PADDING ? options.keyEncryptionDigest : undefined,
            padding: padding
        }, symmetricKeyBuffer);
        let base64EncodedEncryptedKey = encrypted.toString('base64');

        let params = {
            encryptedKey:  base64EncodedEncryptedKey,
            encryptionPublicCert: '<X509Data><X509Certificate>' + pemToCert(options.pem.toString()) + '</X509Certificate></X509Data>',
            keyEncryptionMethod: options.keyEncryptionAlgorithm,
            keyEncryptionDigest: options.keyEncryptionDigest,
        };

        let result = renderTemplate('keyinfo', params);
        callback(null, result);
    } catch (e) {
        callback(e);
    }
}

function encryptKeyInfo(symmetricKey, options, callback) {
    if (!options)
        return callback(new Error('must provide options'));
    if (!options.rsa_pub)
        return callback(new Error('must provide options.rsa_pub with public key RSA'));
    if (!options.pem)
        return callback(new Error('must provide options.pem with certificate'));

    if (!options.keyEncryptionAlgorithm)
        return callback(new Error('encryption without encrypted key is not supported yet'));
    if (options.disallowEncryptionWithInsecureAlgorithm
        && insecureAlgorithms.indexOf(options.keyEncryptionAlgorithm) >= 0) {
        return callback(new Error('encryption algorithm ' + options.keyEncryptionAlgorithm + 'is not secure'));
    }
    options.keyEncryptionDigest = options.keyEncryptionDigest || 'sha1';
    switch (options.keyEncryptionAlgorithm) {
        case 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p':
            return encryptKeyInfoWithScheme(symmetricKey, options, crypto.constants.RSA_PKCS1_OAEP_PADDING, callback);

        case 'http://www.w3.org/2001/04/xmlenc#rsa-1_5':
            warnInsecureAlgorithm(options.keyEncryptionAlgorithm, options.warnInsecureAlgorithm);
            return encryptKeyInfoWithScheme(symmetricKey, options, crypto.constants.RSA_PKCS1_PADDING, callback);

        default:
            return callback(new Error('encryption key algorithm not supported'));
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

function decrypt(xml, options, callback) {

    if (!options)
        return callback(new Error('must provide options'));
    if (!xml)
        return callback(new Error('must provide XML to encrypt'));
    if (!options.key)
        return callback(new Error('key option is mandatory and you should provide a valid RSA private key'));
    try {
        let doc = typeof xml === 'string' ? new DOMParser().parseFromString(xml) : xml;
        let symmetricKey = decryptKeyInfo(doc, options);
        let encryptionMethod = xpath.select("//*[local-name(.)='EncryptedData']/*[local-name(.)='EncryptionMethod']", doc)[0];
        let encryptionAlgorithm = encryptionMethod.getAttribute('Algorithm');

        if (options.disallowDecryptionWithInsecureAlgorithm
            && insecureAlgorithms.indexOf(encryptionAlgorithm) >= 0) {
            return callback(new Error('encryption algorithm ' + encryptionAlgorithm + ' is not secure, fail to decrypt'));
        }
        let encryptedContent = xpath.select("//*[local-name(.)='EncryptedData']/*[local-name(.)='CipherData']/*[local-name(.)='CipherValue']", doc)[0];

        let encrypted = Buffer.from(encryptedContent.textContent, 'base64');
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
                return callback(new Error('encryption algorithm ' + encryptionAlgorithm + ' not supported'));
        }
    } catch (e) {
        return callback(e);
    }
}

function decryptKeyInfo(doc, options) {
    if (typeof doc === 'string') doc = new DOMParser().parseFromString(doc);

    let keyRetrievalMethodUri;
    let keyInfo = xpath.select("//*[local-name(.)='KeyInfo' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']", doc)[0];
    if (!keyInfo) {
        keyInfo = xpath.select("//*[local-name(.)='EncryptedData']/*[local-name(.)='KeyInfo']", doc)[0];
    }
    let keyEncryptionMethod = xpath.select("//*[local-name(.)='KeyInfo']/*[local-name(.)='EncryptedKey']/*[local-name(.)='EncryptionMethod']", doc)[0];
    if (!keyEncryptionMethod) { // try with EncryptedData->KeyInfo->RetrievalMethod
        let keyRetrievalMethod = xpath.select("//*[local-name(.)='EncryptedData']/*[local-name(.)='KeyInfo']/*[local-name(.)='RetrievalMethod']", doc)[0];
        keyRetrievalMethodUri = keyRetrievalMethod ? keyRetrievalMethod.getAttribute('URI') : null;
        keyEncryptionMethod = keyRetrievalMethodUri ? xpath.select("//*[local-name(.)='EncryptedKey' and @Id='" + keyRetrievalMethodUri.substring(1) + "']/*[local-name(.)='EncryptionMethod']", doc)[0] : null;
    }

    if (!keyEncryptionMethod) {
        throw new Error('cant find encryption algorithm');
    }

    let oaepHash = 'sha1';
    let mgfHash = null;
    const keyDigestMethod = xpath.select("//*[local-name(.)='KeyInfo']/*[local-name(.)='EncryptedKey']/*[local-name(.)='EncryptionMethod']/*[local-name(.)='DigestMethod']", doc)[0];
    const MgfDigestMethod = xpath.select("//*[local-name(.)='KeyInfo']/*[local-name(.)='EncryptedKey']/*[local-name(.)='EncryptionMethod']/*[local-name(.)='MGF']", doc)[0];
    if (keyDigestMethod) {
        const keyDigestMethodAlgorithm = keyDigestMethod.getAttribute('Algorithm');
        switch (keyDigestMethodAlgorithm) {
            case 'http://www.w3.org/2001/04/xmlenc#sha256':
            case 'http://www.w3.org/2000/09/xmldsig#sha256':
                oaepHash = 'sha256';
                break;
            case 'http://www.w3.org/2001/04/xmlenc#sha512':
            case 'http://www.w3.org/2000/09/xmldsig#sha512':
                oaepHash = 'sha512';
                break;
        }
    }
    if (MgfDigestMethod) {
        const MgfDigestMethodAlgorithm = MgfDigestMethod.getAttribute('Algorithm');
        switch (MgfDigestMethodAlgorithm) {
            case 'http://www.w3.org/2009/xmlenc11#mgf1sha224':
                mgfHash = 'sha224';
                break;
            case 'http://www.w3.org/2009/xmlenc11#mgf1sha256':
            case 'http://www.w3.org/2001/04/xmlenc#sha256':
            case 'http://www.w3.org/2000/09/xmldsig#sha256':
                mgfHash = 'sha256';
                break;
            case 'http://www.w3.org/2009/xmlenc11#mgf1sha384':
                mgfHash = 'sha384';
                break;
            case 'http://www.w3.org/2009/xmlenc11#mgf1sha512':
            case 'http://www.w3.org/2001/04/xmlenc#sha512':
            case 'http://www.w3.org/2000/09/xmldsig#sha512':
                mgfHash = 'sha512';
                break;
        }
    }
    let keyEncryptionAlgorithm = keyEncryptionMethod.getAttribute('Algorithm');
    if (options.disallowDecryptionWithInsecureAlgorithm
        && insecureAlgorithms.indexOf(keyEncryptionAlgorithm) >= 0) {
        throw new Error('encryption algorithm ' + keyEncryptionAlgorithm + ' is not secure, fail to decrypt');
    }
    let encryptedKey = keyRetrievalMethodUri ?
        xpath.select("//*[local-name(.)='EncryptedKey' and @Id='" + keyRetrievalMethodUri.substring(1) + "']/*[local-name(.)='CipherData']/*[local-name(.)='CipherValue']", keyInfo)[0] :
        xpath.select("//*[local-name(.)='CipherValue']", keyInfo)[0];
    switch (keyEncryptionAlgorithm) {
        case 'http://www.w3.org/2009/xmlenc11#rsa-oaep':
            return decryptKeyInfoWithScheme(encryptedKey, options, crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash,mgfHash);
        case 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p':
            return decryptKeyInfoWithScheme(encryptedKey, options, crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash,mgfHash);
        case 'http://www.w3.org/2001/04/xmlenc#rsa-1_5':
            warnInsecureAlgorithm(keyEncryptionAlgorithm, options.warnInsecureAlgorithm);
            return decryptKeyInfoWithScheme(encryptedKey, options, crypto.constants.RSA_PKCS1_PADDING);
        default:
            throw new Error('key encryption algorithm ' + keyEncryptionAlgorithm + ' not supported');
    }
}

function decryptKeyInfoWithScheme(encryptedKey, options, padding, oaepHash,mgfHash) {
    // 将加密的密钥从 Base64 转换为二进制数据
    const encryptedKeyBase64 = encryptedKey.textContent;
    const encryptedKeyBytes = forge.util.decode64(encryptedKeyBase64);

    // 从 PEM 格式的私钥中加载密钥
    const privateKey = forge.pki.privateKeyFromPem(options.key);  // 传入 PEM 格式的私钥

    try {
        // 创建相应的 hash 算法
        let md;
        let mgf;
        switch (oaepHash) {
            case 'sha1':
                md = forge.md.sha1.create();  // 使用 SHA-1
                break;
            case 'sha256':
                md = forge.md.sha256.create();  // 使用 SHA-256
                break;
            case 'sha512':
                md = forge.md.sha512.create();  // 使用 SHA-512
                break;
            default:
                throw new Error('Unsupported OAEP hash algorithm');
        }
        switch (mgfHash) {
            case 'sha1':
                mgf = forge.md.sha1.create();  // 使用 SHA-1
                break;
            case 'sha224':
                mgf = forge.md.sha224.create();  // 使用 SHA-256
                break;
            case 'sha256':
                mgf = forge.md.sha256.create();  // 使用 SHA-256
                break;
            case 'sha384':
                mgf = forge.md.sha384.create();  // 使用 SHA-512
                break;
            case 'sha512':
                mgf = forge.md.sha512.create();  // 使用 SHA-512
                break;
            default:
                break;
        }
        // 配置 OAEP 填充并解密
        if(mgfHash){
            const decrypted = privateKey.decrypt(encryptedKeyBytes, 'RSA-OAEP', {
                md: md,  // 设置用于 OAEP 的哈希算法,
                mgf1: {
                    md:mgf
                }
            });

            return Buffer.from(decrypted, 'binary');
        }else{
            const decrypted = privateKey.decrypt(encryptedKeyBytes, 'RSA-OAEP', {
                md: md,  // 设置用于 OAEP 的哈希算法,
                mgf1: {
                    md: forge.md.sha1.create()
                }
            });

            return Buffer.from(decrypted, 'binary');
        }

    } catch (err) {
        console.log('解密错误:', err);
        console.log("看一下====");
        throw new Error('Decryption failed');
    }
}
function encryptWithAlgorithm(algorithm, symmetricKey, ivLength, content, encoding, callback) {
    // create a random iv for algorithm
    crypto.randomBytes(ivLength, function(err, iv) {
        if (err) return callback(err);

        let cipher = crypto.createCipheriv(algorithm, symmetricKey, iv);
        // encrypted content
        let encrypted = cipher.update(content, encoding, 'binary') + cipher.final('binary');
        let authTag = algorithm.slice(-3) === "gcm" ? cipher.getAuthTag() : Buffer.from("");
        //Format mentioned: https://www.w3.org/TR/xmlenc-core1/#sec-AES-GCM
        let r = Buffer.concat([iv, Buffer.from(encrypted, 'binary'), authTag]);
        return callback(null, r);
    });
}

function decryptWithAlgorithm(algorithm, symmetricKey, ivLength, content) {
    console.log(symmetricKey?.length)
    console.log("symmetricKey length")
    let decipher = crypto.createDecipheriv(algorithm, symmetricKey, content.slice(0,ivLength));
    decipher.setAutoPadding(false);

    if (algorithm.slice(-3) === "gcm") {
        decipher.setAuthTag(content.slice(-16));
        content = content.slice(0,-16);
    }
    let decrypted = decipher.update(content.slice(ivLength), null, 'binary') + decipher.final('binary');

    if (algorithm.slice(-3) !== "gcm") {
        console.log("开始了===")
        // Remove padding bytes equal to the value of the last byte of the returned data.
        // Padding for GCM not required per: https://www.w3.org/TR/xmlenc-core1/#sec-AES-GCM
        let padding = decrypted.charCodeAt(decrypted.length - 1);
        if (1 <= padding && padding <= ivLength) {
            decrypted = decrypted.substr(0, decrypted.length - padding);
        } else {
            throw new Error('padding length invalid');
        }
    }
    console.log( Buffer.from(decrypted, 'binary').toString('utf8'))
    console.log("成功后的")
    return Buffer.from(decrypted, 'binary').toString('utf8');
}

export {
    decrypt,
    encrypt,
    encryptKeyInfo,
    decryptKeyInfo
};
