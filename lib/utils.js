import path from 'node:path';
import fs from 'node:fs';

const templates = {
    'encrypted-key': (await import('./templates/encrypted-key.tpl.js')).default,
    'keyinfo': (await import('./templates/keyinfo.tpl.js')).default,
};

function renderTemplate(file, data) {
    return templates[file](data);
}

function pemToCert(pem) {
    const cert = /-----BEGIN CERTIFICATE-----([^-]*)-----END CERTIFICATE-----/g.exec(pem);
    if (cert && cert.length > 0) {
        return cert[1].replace(/[\n|\r\n]/g, '');
    }

    return null;
};

function warnInsecureAlgorithm(algorithm, enabled = true) {
    if (enabled) {
        console.warn(algorithm + " is no longer recommended due to security reasons. Please deprecate its use as soon as possible.")
    }
}

export {
    renderTemplate,
    pemToCert,
    warnInsecureAlgorithm
};
