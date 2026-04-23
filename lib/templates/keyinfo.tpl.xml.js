import escapeHtml from 'escape-html';

/**
 * XML Encryption KeyInfo 模板
 * 支持 XML Encryption 1.0 和 1.1 格式
 * @see https://www.w3.org/TR/xmlenc-core1/#sec-EncryptedKey
 * @see https://www.w3.org/TR/xmlenc-core1/#sec-RSA-OAEP
 * 
 * @param {Object} params - 模板参数
 * @param {string} params.encryptionPublicCert - X509 证书数据
 * @param {string} params.encryptedKey - Base64 编码的加密密钥
 * @param {string} params.keyEncryptionMethod - 密钥加密算法 URI
 * @param {string|null} params.keyEncryptionOAEPParams - OAEPparams 的 base64 文本
 * @param {string|null} params.keyEncryptionDigest - DigestMethod 算法 URI (XML Enc 1.1，非 sha1 时包含)
 * @param {string|null} params.keyEncryptionMgf1 - MGF 算法 URI (XML Enc 1.1，非 sha1 时包含)
 * @returns {string} KeyInfo XML 片段
 */
const keyInfoTemplate = ({ 
    encryptionPublicCert, 
    encryptedKey, 
    keyEncryptionMethod, 
    keyEncryptionOAEPParams,
    keyEncryptionDigest, 
    keyEncryptionMgf1 
}) => {
    // XML Enc 1.1: 仅当算法不是默认值 (sha1) 时才包含 DigestMethod 和 MGF 元素
    // 这符合规范建议的简化表示
    const oaepParamsBlock = keyEncryptionOAEPParams
        ? `\n      <e:OAEPparams>${escapeHtml(keyEncryptionOAEPParams)}</e:OAEPparams>`
        : '';

    const mgfBlock = keyEncryptionMgf1
        ? `\n      <xenc11:MGF xmlns:xenc11="http://www.w3.org/2009/xmlenc11#" Algorithm="${escapeHtml(keyEncryptionMgf1)}" />`
        : '';
    
    const digestBlock = keyEncryptionDigest
        ? `\n      <ds:DigestMethod xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Algorithm="${escapeHtml(keyEncryptionDigest)}" />`
        : '';

    return `
    <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
  <e:EncryptedKey xmlns:e="http://www.w3.org/2001/04/xmlenc#">
    <e:EncryptionMethod Algorithm="${escapeHtml(keyEncryptionMethod)}">${oaepParamsBlock}${digestBlock}${mgfBlock}
    </e:EncryptionMethod>
    <KeyInfo>
      ${encryptionPublicCert}
    </KeyInfo>
    <e:CipherData>
      <e:CipherValue>${escapeHtml(encryptedKey)}</e:CipherValue>
    </e:CipherData>
  </e:EncryptedKey>
</KeyInfo>
`;
};

export default keyInfoTemplate;
