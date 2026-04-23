import { describe, it, expect } from 'vitest';
import { encrypt, decrypt } from '../lib/index.js';
import forge from 'node-forge';
import { DOMParser } from '@xmldom/xmldom';
import xpath from 'xpath';

function generateTestKeys() {
    const keys = forge.pki.rsa.generateKeyPair(2048);
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

    return {
        publicKey: forge.pki.publicKeyToPem(keys.publicKey),
        privateKey: forge.pki.privateKeyToPem(keys.privateKey),
        certificate: forge.pki.certificateToPem(cert)
    };
}

function encryptWithCallback(content, options) {
    return new Promise((resolve, reject) => {
        const returnValue = encrypt(content, options, (err, result) => {
            if (err) {
                reject(err);
                return;
            }
            resolve(result);
        });

        expect(returnValue).toBeUndefined();
    });
}

function decryptWithCallback(xml, options) {
    return new Promise((resolve, reject) => {
        const returnValue = decrypt(xml, options, (err, result) => {
            if (err) {
                reject(err);
                return;
            }
            resolve(result);
        });

        expect(returnValue).toBeUndefined();
    });
}

function buildExternalEncryptedAssertion(encryptedXml) {
    const doc = new DOMParser().parseFromString(encryptedXml, 'application/xml');
    const encryptedData = xpath.select1("//*[local-name(.)='EncryptedData']", doc);

    if (!encryptedData) {
        throw new Error('Missing EncryptedData in encrypted payload');
    }

    const keyInfo = xpath.select1("./*[local-name(.)='KeyInfo']", encryptedData);
    const encryptedKey = keyInfo && xpath.select1("./*[local-name(.)='EncryptedKey']", keyInfo);

    if (!keyInfo || !encryptedKey) {
        throw new Error('Missing inline EncryptedKey in encrypted payload');
    }

    const encryptedKeyId = encryptedKey.getAttribute('Id') || 'external-key';
    if (!encryptedKey.getAttribute('Id')) {
        encryptedKey.setAttribute('Id', encryptedKeyId);
    }

    const retrievalMethod = doc.createElementNS(
        'http://www.w3.org/2000/09/xmldsig#',
        'RetrievalMethod'
    );
    retrievalMethod.setAttribute('Type', 'http://www.w3.org/2001/04/xmlenc#EncryptedKey');
    retrievalMethod.setAttribute('URI', `#${encryptedKeyId}`);
    keyInfo.replaceChild(retrievalMethod, encryptedKey);

    return [
        '<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">',
        encryptedData.toString(),
        encryptedKey.toString(),
        '</saml:EncryptedAssertion>'
    ].join('');
}

const testKeys = generateTestKeys();
const TEST_CONTENT = 'This is a test content for XML encryption';
const TEST_CONTENT_UNICODE = 'Callback regression payload: 测试中文内容 🚀';

describe('Legacy Callback API Regression Tests', () => {
    it('encrypts and decrypts XML Enc 1.1 payloads through callbacks', async () => {
        const options = {
            rsa_pub: testKeys.publicKey,
            pem: testKeys.certificate,
            keyEncryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#rsa-oaep',
            keyEncryptionDigest: 'sha256',
            keyEncryptionMgf1: 'sha256',
            encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes128-gcm',
            key: testKeys.privateKey
        };

        const encryptedXml = await encryptWithCallback(TEST_CONTENT, options);
        const decryptedContent = await decryptWithCallback(encryptedXml, options);

        expect(Buffer.isBuffer(decryptedContent)).toBe(true);
        expect(decryptedContent.toString('utf8')).toBe(TEST_CONTENT);
    });

    it('decrypts RetrievalMethod-based EncryptedKey payloads through callbacks', async () => {
        const options = {
            rsa_pub: testKeys.publicKey,
            pem: testKeys.certificate,
            keyEncryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#rsa-oaep',
            keyEncryptionDigest: 'sha512',
            keyEncryptionMgf1: 'sha384',
            encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes256-gcm',
            key: testKeys.privateKey
        };

        const inlineEncryptedXml = await encryptWithCallback(TEST_CONTENT_UNICODE, options);
        const externalEncryptedXml = buildExternalEncryptedAssertion(inlineEncryptedXml);
        const decryptedContent = await decryptWithCallback(externalEncryptedXml, options);

        expect(decryptedContent.toString('utf8')).toBe(TEST_CONTENT_UNICODE);
    });

    it('keeps rsa-oaep-mgf1p SHA-1 callback decryption compatible', async () => {
        const options = {
            rsa_pub: testKeys.publicKey,
            pem: testKeys.certificate,
            keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
            keyEncryptionDigest: 'sha1',
            encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc',
            key: testKeys.privateKey,
            disallowInsecureHash: false
        };

        const encryptedXml = await encryptWithCallback(TEST_CONTENT, options);
        const decryptedContent = await decryptWithCallback(encryptedXml, options);

        expect(decryptedContent.toString('utf8')).toBe(TEST_CONTENT);
    });

    it('returns callback errors instead of silently logging them', async () => {
        await expect(encryptWithCallback(null, undefined)).rejects.toThrow('must provide options');
    });
});
