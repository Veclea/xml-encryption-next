// test/integration.test.js

import {decrypt} from '../lib/index.js';
import fs from 'node:fs';
import crypto from 'node:crypto';
import {DOMParser} from '@xmldom/xmldom';
import xpath from 'xpath';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
describe('integration', function () {

    it('should decrypt assertion with aes128', function (done) {
        let result = fs.readFileSync('./test/assertion-sha1-128.xml').toString();
        decrypt(result, {key: fs.readFileSync('./test/test-cbc128.key')}, function (err, decrypted) {
            // decrypted content should finish with <saml2:Assertion>
            expect(/<\/saml2:Assertion>$/.test(decrypted)).toBe(true);

        });
    });

        it('should decrypt Okta assertion', function (done) {
            let encryptedContent = fs.readFileSync('./test/test-okta-enc-response.xml').toString()
            decrypt(
                encryptedContent,
                {key: fs.readFileSync('./test/test-okta.pem', )},
                (err, res) => {
                    console.log(err)
                    console.log("看下错误===========================")

                    expect(err).toBeFalsy();


                }
            );
        });
});
