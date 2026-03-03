/*
// test/encrypt.test.js
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spy } from 'sinon';
// @ts-ignore
import { encrypt, decrypt, encryptKeyInfo, decryptKeyInfo } from '/lib/index.js';
import fs from 'node:fs';

describe('encrypt', function() {
    let consoleSpy = null;

    beforeEach(function() {
        consoleSpy = spy(console, 'warn');
    });

    afterEach(function() {
        // @ts-ignore
        consoleSpy.restore();
    });

    var algorithms = [{
        name: 'aes-256-cbc',
        encryptionOptions: {
            encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
            keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p'
        }
    }, {
        name: 'aes-128-cbc',
        encryptionOptions: {
            encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc',
            keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p'
        }
    }, {
        name: 'aes-192-cbc',
        encryptionOptions: {
            encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes192-cbc',
            keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p'
        }
    }, {
        name: 'aes-256-gcm',
        encryptionOptions: {
            encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes256-gcm',
            keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p'
        }
    }, {
        name: 'aes-128-gcm',
        encryptionOptions: {
            encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes128-gcm',
            keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p'
        }
    },
        {
            name: 'aes-192-gcm',
            encryptionOptions: {
                encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes192-gcm',
                keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p'
            }
        },
        {
            name: 'aes-128-gcm with sha256',
            encryptionOptions: {
                encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes128-gcm',
                keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
                keyEncryptionDigest: 'sha256'
            }
        }, {
            name: 'aes-128-gcm with sha512',
            encryptionOptions: {
                encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes128-gcm',
                keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
                keyEncryptionDigest: 'sha512'
            }
        }, {
            name: 'des-ede3-cbc',
            encryptionOptions: {
                encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc',
                keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5'
            }
        }];

    algorithms.forEach(function (algorithm) {
        describe(algorithm.name, function () {
            it('should encrypt and decrypt xml', function (done) {
                _shouldEncryptAndDecrypt('content to encrypt', algorithm.encryptionOptions, done);
            });

            it('should encrypt and decrypt xml with utf8 chars', function (done) {
                _shouldEncryptAndDecrypt('Gnügge Gnügge Gnügge Gnügge Gnügge Gnügge Gnügge Gnügge Gnügge Gnügge', algorithm.encryptionOptions, done);
            });
        });
    });

    function _shouldEncryptAndDecrypt(content, options, done) {
        // cert created with:
        // openssl req -x509 -new -newkey rsa:2048 -nodes -subj '/CN=auth0.auth0.com/O=Auth0 LLC/C=US/ST=Washington/L=Redmond' -keyout auth0.key -out auth0.pem
        // pub key extracted from (only the RSA public key between BEGIN PUBLIC KEY and END PUBLIC KEY)
        // openssl x509 -in "test-auth0.pem" -pubkey

        options.rsa_pub = fs.readFileSync('./test/test-auth0_rsa.pub'),
            options.pem = fs.readFileSync('./test/test-auth0.pem'),
            options.key = fs.readFileSync('./test/test-auth0.key'),
            options.warnInsecureAlgorithm = false;

        encrypt(content, options, function(err, result) {
            decrypt(result, { key: fs.readFileSync('./test/test-auth0.key'), warnInsecureAlgorithm: false}, function (err, decrypted) {
                if (err) {
                    console.log(err)
                    console.log("看一下")
                    return
                }

                if(decrypted !== content ){
                    console.log(decrypted)
                    console.log('----------------------------------------')
                    console.log(content)
                }
                expect(decrypted).toBe(content);

            });
        });
    }

    describe('des-ede3-cbc fails', function() {
        it('should fail encryption when disallowEncryptionWithInsecureAlgorithm is set', function(done) {
            const options = {
                rsa_pub: fs.readFileSync('./test/test-auth0_rsa.pub'),
                pem: fs.readFileSync('./test/test-auth0.pem'),
                key: fs.readFileSync('./test/test-auth0.key'),
                disallowEncryptionWithInsecureAlgorithm: true,
                encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc',
                keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p'
            }
            encrypt('encrypt me', options, function(err, result) {
                expect(err).toBeTruthy();
                expect(result).toBeFalsy();
                //should not pop up warns due to options.warnInsecureAlgorithm = false;
                // @ts-ignore
                expect(consoleSpy.called).toBe(false);
             
            });
        });

        it('should fail decryption when disallowDecryptionWithInsecureAlgorithm is set', function(done) {
            const options = {
                rsa_pub: fs.readFileSync('./test/test-auth0_rsa.pub'),
                pem: fs.readFileSync('./test/test-auth0.pem'),
                key: fs.readFileSync('./test/test-auth0.key'),
                encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc',
                keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p'
            }
            encrypt('encrypt me', options, function(err, result) {
                decrypt(result,
                    { key: fs.readFileSync('./test/test-auth0.key'),
                        disallowDecryptionWithInsecureAlgorithm: true},
                    function (err, decrypted) {
                        expect(err).toBeTruthy();
                        expect(decrypted).toBeFalsy();
                     
                    });
            });
        });
    });

    describe('rsa-1.5 fails', function() {
        it('should fail encryption when disallowEncryptionWithInsecureAlgorithm is set', function(done) {
            const options = {
                rsa_pub: fs.readFileSync('./test/test-auth0_rsa.pub'),
                pem: fs.readFileSync('./test/test-auth0.pem'),
                key: fs.readFileSync('./test/test-auth0.key'),
                disallowEncryptionWithInsecureAlgorithm: true,
                encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
                keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5'
            }
            encrypt('encrypt me', options, function(err, result) {
                expect(err).toBeTruthy();
                expect(result).toBeFalsy();
             
            });
        });

        it('should fail decryption when disallowDecryptionWithInsecureAlgorithm is set', function(done) {
            const options = {
                rsa_pub: fs.readFileSync('./test/test-auth0_rsa.pub'),
                pem: fs.readFileSync('./test/test-auth0.pem'),
                key: fs.readFileSync('./test/test-auth0.key'),
                encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
                keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5'
            }
            encrypt('encrypt me', options, function(err, result) {
                decrypt(result,
                    { key: fs.readFileSync('./test/test-auth0.key'),
                        disallowDecryptionWithInsecureAlgorithm: true},
                    function (err, decrypted) {
                        expect(err).toBeTruthy();
                        expect(decrypted).toBeFalsy();
                     
                    });
            });
        });
    });


    it('should encrypt and decrypt keyinfo', function (done) {
        var options = {
            rsa_pub: fs.readFileSync('./test/test-auth0_rsa.pub'),
            pem: fs.readFileSync('./test/test-auth0.pem'),
            keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p'
        };

        var plaintext = 'The quick brown fox jumps over the lazy dog';

        encryptKeyInfo(plaintext, options, function(err, encryptedKeyInfo) {
            if (err) { // @ts-ignore
                return done(err);
            }

            var decryptedKeyInfo = decryptKeyInfo(
                encryptedKeyInfo,
                {key: fs.readFileSync('./test/test-auth0.key')}
            );
            expect(decryptedKeyInfo.toString()).toBe(plaintext);

         
        });
    });

    it('should decrypt xml with odd padding (aes256-cbc)', function (done) {
        var encryptedContent = fs.readFileSync('./test/test-cbc256-padding.xml').toString()
        decrypt(encryptedContent, { key: fs.readFileSync('./test/test-auth0.key')}, function(err, decrypted) {
            expect(err).toBeFalsy();
            expect(decrypted).toBe('content');
         
        });
    });

    it('should catch error if padding length > 16', function (done) {
        var encryptedContent = fs.readFileSync('./test/test-padding-length.xml').toString();
        decrypt(encryptedContent, { key: fs.readFileSync('./test/test-auth0.key')}, function(err, decrypted) {
            expect(err).toBeTruthy();
         
        });
    });

    it('should fail encrypt when disallowEncryptionWithInsecureAlgorithm is set', function (done) {
        var options = {
            rsa_pub: fs.readFileSync('./test/test-auth0_rsa.pub'),
            pem: fs.readFileSync('./test/test-auth0.pem'),
            keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5',
            disallowEncryptionWithInsecureAlgorithm: true
        };

        var plaintext = 'The quick brown fox jumps over the lazy dog';
        encryptKeyInfo(plaintext, options, function(err, encryptedKeyInfo) {
            expect(err).toBeTruthy();
         
        });
    });

    it('should encrypt and fail decrypt due to insecure algorithms', function (done) {
        var options = {
            rsa_pub: fs.readFileSync('./test/test-auth0_rsa.pub'),
            pem: fs.readFileSync('./test/test-auth0.pem'),
            keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5'
        };

        var plaintext = 'The quick brown fox jumps over the lazy dog';

        encryptKeyInfo(plaintext, options, function(err, encryptedKeyInfo) {
            if (err) { // @ts-ignore
                return done(err);
            }
            // @ts-ignore
            expect(consoleSpy?.called).toBe(true);
            expect(() => {
                decryptKeyInfo(
                    encryptedKeyInfo,
                    {key: fs.readFileSync('./test/test-auth0.key'),
                        disallowDecryptionWithInsecureAlgorithm: true})
            }).toThrow(Error);

         
        });
    });
});
*/
