import crypto from 'crypto';
import {DOMParser} from '@xmldom/xmldom';
import xpath from 'xpath';
import {renderTemplate, pemToCert, warnInsecureAlgorithm} from './utils.js';
import forge from 'node-forge'

const insecureAlgorithms = [//https://www.w3.org/TR/xmlenc-core1/#rsav15note
    'http://www.w3.org/2001/04/xmlenc#rsa-1_5', //https://csrc.nist.gov/News/2017/Update-to-Current-Use-and-Deprecation-of-TDEA
    'http://www.w3.org/2001/04/xmlenc#tripledes-cbc'];
let hashObject = {
    keyEncryptionDigest: {
        'sha1': "http://www.w3.org/2000/09/xmldsig#sha1",
        'sha256': "http://www.w3.org/2001/04/xmlenc#sha256",
        'sha384': "http://www.w3.org/2001/04/xmlenc#sha384",
        'sha512': "http://www.w3.org/2001/04/xmlenc#sha512",
    }, mgfAlgorithm: {
        'sha1': "http://www.w3.org/2009/xmlenc11#mgf1sha1",
        'sha224': "http://www.w3.org/2009/xmlenc11#mgf1sha224",
        'sha256': "http://www.w3.org/2009/xmlenc11#mgf1sha256",
        'sha384': "http://www.w3.org/2009/xmlenc11#mgf1sha384",
        'sha512': "http://www.w3.org/2009/xmlenc11#mgf1sha512",
    }
}

function encryptKeyInfoWithScheme({symmetricKey, options, padding, callback}) {
    const symmetricKeyBuffer = Buffer.from(symmetricKey, 'utf-8');


    const publicKey = forge.pki.publicKeyFromPem(options.rsa_pub.toString());
    if (options.keyEncryptionAlgorithm === 'http://www.w3.org/2001/04/xmlenc#rsa-1_5') {
        let encrypted = publicKey.encrypt(Buffer.from(symmetricKeyBuffer, 'binary').toString('base64'), 'RSAES-PKCS1-V1_5');
        let base64EncodedEncryptedKey = Buffer.from(encrypted, 'binary').toString('base64');

        let params = {
            encryptedKey: base64EncodedEncryptedKey,
            encryptionPublicCert: '<X509Data><X509Certificate>' + pemToCert(options.pem.toString()) + '</X509Certificate></X509Data>',
            keyEncryptionMethod: options.keyEncryptionAlgorithm
        };

        let result = renderTemplate('keyinfo', params);
        callback(null, result);
    }
    if (options.keyEncryptionAlgorithm === 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p') {
        let md;
        let mgf1 = forge.md.sha1.create()
        switch (options.keyEncryptionDigest) {
            case 'sha1':
                md = forge.md.sha1.create();
                break;
            case 'sha256':
                md = forge.md.sha256.create();
                break;
            /*case 'sha224': md = forge.md.sha224.create(); break;*/  //node-forge not supported
            case 'sha384':
                md = forge.md.sha384.create();
                break;
            case 'sha512':
                md = forge.md.sha512.create();
                break;
            default:
                return callback(new Error('Unsupported OAEP hash: ' + options.oaepHash));
        }

        const encrypted = publicKey.encrypt(Buffer.from(symmetricKeyBuffer, 'binary').toString('base64'), 'RSA-OAEP', {
            md: md,
            mgf1: {
                md: mgf1
            }
        });
        let base64EncodedEncryptedKey = Buffer.from(encrypted, 'binary').toString('base64');


        let params = {
            encryptedKey: base64EncodedEncryptedKey,
            encryptionPublicCert: '<X509Data><X509Certificate>' + pemToCert(options.pem.toString()) + '</X509Certificate></X509Data>',
            keyEncryptionMethod: options.keyEncryptionAlgorithm,
            keyEncryptionDigest:hashObject['keyEncryptionDigest'][options.keyEncryptionDigest]
        };

        let result = renderTemplate('keyinfo', params);
        callback(null, result);
    }
    if (options.keyEncryptionAlgorithm === 'http://www.w3.org/2009/xmlenc11#rsa-oaep') {
        let md;
        let mgf1;
        switch (options.keyEncryptionDigest) {
            case 'sha1':
                md = forge.md.sha1.create();
                break;
            case 'sha256':
                md = forge.md.sha256.create();
                break;
            /*case 'sha224': md = forge.md.sha224.create(); break;*/  //node-forge not supported
            case 'sha384':
                md = forge.md.sha384.create();
                break;
            case 'sha512':
                md = forge.md.sha512.create();
                break;
            default:
                return callback(new Error('Unsupported OAEP hash: ' + options.keyEncryptionDigest));
        }
        switch (options.keyEncryptionMgf1) {
            case 'sha1':
                mgf1 = forge.md.sha1.create();
                break;
            case 'sha256':
                mgf1 = forge.md.sha256.create();
                break;
            /*case 'sha224': md = forge.md.sha224.create(); break;*/  //node-forge not supported
            case 'sha384':
                mgf1 = forge.md.sha384.create();
                break;
            case 'sha512':
                mgf1 = forge.md.sha512.create();
                break;
            default:
                return callback(new Error('Unsupported Mgf1 hash: ' + options.keyEncryptionMgf1));
        }

        const encryptedData = publicKey.encrypt(Buffer.from(symmetricKeyBuffer, 'binary').toString('base64'), 'RSA-OAEP', {
            md: md, mgf1: {
                md: mgf1
            }
        });

        let base64EncodedEncryptedKey = Buffer.from(encryptedData, 'binary').toString('base64');
        let params = {
            encryptedKey: base64EncodedEncryptedKey,
            encryptionPublicCert: '<X509Data><X509Certificate>' + pemToCert(options.pem.toString()) + '</X509Certificate></X509Data>',
            keyEncryptionMethod: options.keyEncryptionAlgorithm,
            keyEncryptionDigest:options.keyEncryptionDigest === 'sha1'  ? null:hashObject['keyEncryptionDigest'][options.keyEncryptionDigest],
            keyEncryptionMgf1: options.keyEncryptionMgf1 === 'sha1' ? null :hashObject['mgfAlgorithm'][options.keyEncryptionMgf1]
        };

        let result = renderTemplate('keyinfo', params);
        callback(null, result);
    }

    return new Error('Unsupported keyEncryptionAlgorithm')
}

function encryptKeyInfo(symmetricKey, options, callback) {
    if (!options) return callback(new Error('must provide options'));
    if (!options.rsa_pub) return callback(new Error('must provide options.rsa_pub with public key RSA'));
    if (!options.pem) return callback(new Error('must provide options.pem with certificate'));

    if (!options.keyEncryptionAlgorithm) return callback(new Error('encryption without encrypted key is not supported yet'));
    if (options.disallowEncryptionWithInsecureAlgorithm && insecureAlgorithms.indexOf(options.keyEncryptionAlgorithm) >= 0) {
        return callback(new Error('encryption algorithm ' + options.keyEncryptionAlgorithm + 'is not secure'));
    }

    switch (options.keyEncryptionAlgorithm) {
        case 'http://www.w3.org/2001/04/xmlenc#rsa-1_5':
            warnInsecureAlgorithm(options.keyEncryptionAlgorithm, options.warnInsecureAlgorithm);
            options.keyEncryptionDigest = null;
            options.keyEncryptionMgf1 = null;
            return encryptKeyInfoWithScheme({
                symmetricKey, options, padding: crypto.constants.RSA_PKCS1_PADDING, callback
            });

        case 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p':
            options.keyEncryptionDigest = options.keyEncryptionDigest || 'sha1';
            options.keyEncryptionMgf1 = 'sha1'; //rsa-oaep-mgf1p fixed sha1
            return encryptKeyInfoWithScheme({
                symmetricKey, options, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, callback
            });
        case 'http://www.w3.org/2009/xmlenc11#rsa-oaep':
            options.keyEncryptionDigest = options.keyEncryptionDigest || 'sha1';
            options.keyEncryptionMgf1 = options.keyEncryptionMgf1 || 'sha1'; //rsa-oaep-mgf1p fixed sha1
            return encryptKeyInfoWithScheme({
                symmetricKey, options, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, callback
            });


        default:
            return callback(new Error('encryption key algorithm not supported'));
    }
}

function encrypt(content, options, callback) {
    if (!options) return callback(new Error('must provide options'));
    if (!content) return callback(new Error('must provide content to encrypt'));
    if (!options.rsa_pub) return callback(new Error('rsa_pub option is mandatory and you should provide a valid RSA public key'));
    if (!options.pem) return callback(new Error('pem option is mandatory and you should provide a valid x509 certificate encoded as PEM'));
    if (options.disallowEncryptionWithInsecureAlgorithm && (insecureAlgorithms.indexOf(options.keyEncryptionAlgorithm) >= 0 || insecureAlgorithms.indexOf(options.encryptionAlgorithm) >= 0)) {
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
                cb(new Error('unsupported encryption algorithm'))
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
        encryptKeyInfo(symmetricKey, options, function (err, keyInfo) {
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

        encrypt_content(symmetricKey, function (encryptContentError, encryptedContent) {
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

    if (!options) return callback(new Error('must provide options'));
    if (!xml) return callback(new Error('must provide XML to encrypt'));
    if (!options.key) return callback(new Error('key option is mandatory and you should provide a valid RSA private key'));
    try {
        let doc = typeof xml === 'string' ? new DOMParser().parseFromString(xml) : xml;
        let symmetricKey = decryptKeyInfo(doc, options);

        let encryptionMethod = xpath.select("//*[local-name(.)='EncryptedData']/*[local-name(.)='EncryptionMethod']", doc)[0];
        let encryptionAlgorithm = encryptionMethod.getAttribute('Algorithm');

        if (options.disallowDecryptionWithInsecureAlgorithm && insecureAlgorithms.indexOf(encryptionAlgorithm) >= 0) {
            return callback(new Error('encryption algorithm ' + encryptionAlgorithm + ' is not secure, fail to decrypt'));
        }
        let encryptedContent = xpath.select("//*[local-name(.)='EncryptedData']/*[local-name(.)='CipherData']/*[local-name(.)='CipherValue']", doc)[0];
        if (!encryptedContent?.textContent) {
            return callback(new Error('dont hava encryptedContent'));
        }

        let encrypted = Buffer.from(encryptedContent.textContent, 'base64')
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
    let mgfHash = 'sha1';
    const keyDigestMethod = xpath.select("//*[local-name(.)='KeyInfo']/*[local-name(.)='EncryptedKey']/*[local-name(.)='EncryptionMethod']/*[local-name(.)='DigestMethod']", doc)[0];
    const MgfDigestMethod = xpath.select("//*[local-name(.)='KeyInfo']/*[local-name(.)='EncryptedKey']/*[local-name(.)='EncryptionMethod']/*[local-name(.)='MGF']", doc)[0];
    if (keyDigestMethod) {
        const keyDigestMethodAlgorithm = keyDigestMethod.getAttribute('Algorithm');

        switch (keyDigestMethodAlgorithm) {
            case 'http://www.w3.org/2001/04/xmlenc#sha256':
            case 'http://www.w3.org/2000/09/xmldsig#sha256':
                oaepHash = 'sha256';
                break;
            case 'http://www.w3.org/2001/04/xmlenc#sha384':
                oaepHash = 'sha384';
                break;
            case 'http://www.w3.org/2001/04/xmlenc#sha512':
                oaepHash = 'sha512';
                break;
        }
    }
    if (MgfDigestMethod) {
        const MgfDigestMethodAlgorithm = MgfDigestMethod.getAttribute('Algorithm');
        switch (MgfDigestMethodAlgorithm) {
            /*            case 'http://www.w3.org/2009/xmlenc11#mgf1sha224':
                            mgfHash = 'sha224';
                            break;*/
            case 'http://www.w3.org/2009/xmlenc11#mgf1sha256':
                mgfHash = 'sha256';
                break;
            case 'http://www.w3.org/2009/xmlenc11#mgf1sha384':
                mgfHash = 'sha384';
                break;
            case 'http://www.w3.org/2009/xmlenc11#mgf1sha512':
                mgfHash = 'sha512';
                break;
        }
    }
    let keyEncryptionAlgorithm = keyEncryptionMethod.getAttribute('Algorithm');
    if (options.disallowDecryptionWithInsecureAlgorithm && insecureAlgorithms.indexOf(keyEncryptionAlgorithm) >= 0) {
        throw new Error('encryption algorithm ' + keyEncryptionAlgorithm + ' is not secure, fail to decrypt');
    }
    let encryptedKey = keyRetrievalMethodUri ? xpath.select("//*[local-name(.)='EncryptedKey' and @Id='" + keyRetrievalMethodUri.substring(1) + "']/*[local-name(.)='CipherData']/*[local-name(.)='CipherValue']", keyInfo)[0] : xpath.select("//*[local-name(.)='CipherValue']", keyInfo)[0];
    switch (keyEncryptionAlgorithm) {
        case 'http://www.w3.org/2001/04/xmlenc#rsa-1_5':
            warnInsecureAlgorithm(keyEncryptionAlgorithm, options.warnInsecureAlgorithm);
            return decryptKeyInfoWithScheme({
                keyEncryptionAlgorithm,
                encryptedKey,
                options,
                padding: crypto.constants.RSA_PKCS1_PADDING,
                oaepHash: null,
                mgfHash: null
            });
        case 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p':
            /* must dont hava mgf */
            if (MgfDigestMethod) {
                throw new Error('http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p  not support  MGF element');
            }
            return decryptKeyInfoWithScheme({
                keyEncryptionAlgorithm,
                encryptedKey,
                options,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash,
                mgfHash
            });
        case 'http://www.w3.org/2009/xmlenc11#rsa-oaep':

            return decryptKeyInfoWithScheme({
                keyEncryptionAlgorithm,
                encryptedKey,
                options,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash,
                mgfHash
            });


        default:
            throw new Error('key encryption algorithm ' + keyEncryptionAlgorithm + ' not supported');
    }
}

// 最简单的Base64检测（仅正则检查）
function isBase64Light(str) {
    if (!str || str.length % 4 !== 0) return false;
    return /^[A-Za-z0-9+/]*={0,2}$/.test(str);
}

function decryptKeyInfoWithScheme({keyEncryptionAlgorithm, encryptedKey, options, padding, oaepHash, mgfHash}) {
    try {
        // 将加密的密钥从 Base64 转换为二进制数据
        const encryptedKeyBase64Text = encryptedKey.textContent;

        const encryptedKeyBytes = Buffer.from(encryptedKeyBase64Text, 'base64').toString('binary');
        // 从 PEM 格式的私钥中加载密钥
        const privateKey = forge.pki.privateKeyFromPem(options.key);  // 传入 PEM 格式的私钥
        if (keyEncryptionAlgorithm === 'http://www.w3.org/2001/04/xmlenc#rsa-1_5') {
            let decrypted = privateKey.decrypt(encryptedKeyBytes, 'RSAES-PKCS1-V1_5');
            if (isBase64Light(decrypted)) {
                return Buffer.from(decrypted, 'base64');
            }
            return Buffer.from(decrypted, 'binary');
        }
        if (keyEncryptionAlgorithm === 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p') {
            let md;
            let mgf1 = forge.md.sha1.create();
            switch (oaepHash) {
                case 'sha1':
                    md = forge.md.sha1.create();  // 使用 SHA-1
                    break;
                case 'sha256':
                    md = forge.md.sha256.create();  // 使用 SHA-256
                    break;
                case 'sha384':
                    md = forge.md.sha384.create();  // 使用 SHA-256
                    break;
                case 'sha512':
                    md = forge.md.sha512.create();  // 使用 SHA-512
                    break;
                default:
                    throw new Error('Unsupported OAEP hash algorithm');
            }

            const decrypted = privateKey.decrypt(encryptedKeyBytes, 'RSA-OAEP', {
                md: md,  // 设置用于 OAEP 的哈希算法,，
                mgf1: {
                    mgf1
                }
            }); //会报错 Invalid RSAES-OAEP padding
            if (isBase64Light(decrypted)) {
                return Buffer.from(decrypted, 'base64');
            }
            return Buffer.from(decrypted, 'binary');

        }

        if (keyEncryptionAlgorithm === 'http://www.w3.org/2009/xmlenc11#rsa-oaep') {
            let md;
            let mgf1;
            switch (oaepHash) {
                case 'sha1':
                    md = forge.md.sha1.create();  // 使用 SHA-1
                    break;
                case 'sha256':
                    md = forge.md.sha256.create();  // 使用 SHA-256
                    break;
                case 'sha384':
                    md = forge.md.sha384.create();  // 使用 SHA-256
                    break;
                case 'sha512':
                    md = forge.md.sha512.create();  // 使用 SHA-512
                    break;
                default:
                    throw new Error('Unsupported OAEP hash algorithm');
            }
            switch (mgfHash) {
                case 'sha1':
                    mgf1 = forge.md.sha1.create();  // 使用 SHA-1
                    break;
                case 'sha256':
                    mgf1 = forge.md.sha256.create();  // 使用 SHA-256
                    break;
                case 'sha384':
                    mgf1 = forge.md.sha384.create();  // 使用 SHA-256
                    break;
                case 'sha512':
                    mgf1 = forge.md.sha512.create();  // 使用 SHA-512
                    break;
                default:
                    throw new Error('Unsupported Mgf1 hash algorithm');
            }
            const decrypted = privateKey.decrypt(encryptedKeyBytes, 'RSA-OAEP', {
                md: md,  // 设置用于 OAEP 的哈希算法,
                mgf1: {
                    md: mgf1
                }
            });

            if (isBase64Light(decrypted)) {
                return Buffer.from(decrypted, 'base64');
            }
            return Buffer.from(decrypted, 'binary');
        }
        throw new Error('not supported algorithm');
    } catch (e) {
        throw e;
    }

}

function encryptWithAlgorithm(algorithm, symmetricKey, ivLength, content, encoding, callback) {
    // create a random iv for algorithm
    crypto.randomBytes(ivLength, function (err, iv) {
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
    let decipher = crypto.createDecipheriv(algorithm, symmetricKey, content.slice(0, ivLength));
    decipher.setAutoPadding(false);
    if (algorithm.slice(-3) === "gcm") {
        decipher.setAuthTag(content.slice(-16));
        content = content.slice(0, -16);
    }
    let decrypted = decipher.update(content.slice(ivLength), null, 'binary') + decipher.final('binary');

    if (algorithm.slice(-3) !== "gcm") {
        // Remove padding bytes equal to the value of the last byte of the returned data.
        // Padding for GCM not required per: https://www.w3.org/TR/xmlenc-core1/#sec-AES-GCM
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
    decrypt, encrypt, encryptKeyInfo, decryptKeyInfo
};
