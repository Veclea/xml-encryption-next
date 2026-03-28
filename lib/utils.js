import path from 'node:path';
import fs from 'node:fs';
import encryptedKeyTemplate from './templates/encrypted-key.tpl.xml.js';
import keyinfoTemplate from './templates/keyinfo.tpl.xml.js';

const templates = {
    'encrypted-key': encryptedKeyTemplate,
    'keyinfo': keyinfoTemplate
};

/**
 * 渲染 XML 模板
 * @param {string} file - 模板名称 ('encrypted-key' 或 'keyinfo')
 * @param {Object} data - 模板数据
 * @returns {string} 渲染后的 XML 字符串
 */
function renderTemplate(file, data) {
    const template = templates[file];
    if (!template) {
        throw new Error('Template not found: ' + file);
    }
    return template(data);
}

/**
 * 从 PEM 格式提取证书内容
 * @param {string} pem - PEM 格式的证书
 * @returns {string|null} Base64 编码的证书内容，如果提取失败则返回 null
 */
function pemToCert(pem) {
    if (!pem) return null;
    
    const cert = /-----BEGIN CERTIFICATE-----([^-]*)-----END CERTIFICATE-----/g.exec(pem);
    if (cert && cert.length > 0) {
        return cert[1].replace(/[\n|\r\n]/g, '');
    }

    return null;
}

/**
 * 对使用不安全算法发出警告
 * @param {string} algorithm - 算法 URI
 * @param {boolean} enabled - 是否启用警告 (默认 true)
 */
function warnInsecureAlgorithm(algorithm, enabled = true) {
    if (enabled) {
        console.warn(
            algorithm + ' is no longer recommended due to security reasons. ' +
            'Please deprecate its use as soon as possible.'
        );
    }
}

export {
    renderTemplate,
    pemToCert,
    warnInsecureAlgorithm
};
