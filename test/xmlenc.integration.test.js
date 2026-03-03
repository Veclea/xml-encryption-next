// test/integration.test.js
import {describe, it, expect} from 'vitest';
import {decrypt} from '../lib/index.js';
import fs from 'node:fs';
import crypto from 'node:crypto';
import {DOMParser} from '@xmldom/xmldom';
import xpath from 'xpath';

describe('integration', function () {

    it('should decrypt assertion with aes128', function (done) {
        let result = fs.readFileSync('./test/assertion-sha1-128.xml').toString();
        decrypt(result, {key: fs.readFileSync('./test/test-cbc128.key')}, function (err, decrypted) {
            // decrypted content should finish with <saml2:Assertion>
            console.log(err)
            console.log(decrypted)
            console.log("这是合适呢么====")
            expect(/<\/saml2:Assertion>$/.test(decrypted)).toBe(true);

        });
    });

    /*    it('should decrypt Okta assertion', function (done) {
            var encryptedContent = fs.readFileSync('./test/test-okta-enc-response.xml').toString()
            decrypt(
                encryptedContent,
                {key: fs.readFileSync('./test/test-okta.pem', )},
                (err, res) => {
                    expect(err).toBeFalsy();


                }
            );
        });*/
});