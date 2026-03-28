import escapeHtml from 'escape-html';

/**
 * XML Encryption 1.0/1.1 EncryptedData 模板
 * @see https://www.w3.org/TR/xmlenc-core1/#sec-EncryptedData
 * 
 * @param {Object} params - 模板参数
 * @param {string} params.contentEncryptionMethod - 内容加密算法 URI
 * @param {string} params.keyInfo - KeyInfo XML 片段
 * @param {string} params.encryptedContent - Base64 编码的加密内容
 * @returns {string} EncryptedData XML 元素
 */
const encryptedKeyTemplate = ({ contentEncryptionMethod, keyInfo, encryptedContent }) => `
<xenc:EncryptedData Type="http://www.w3.org/2001/04/xmlenc#Element" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
  <xenc:EncryptionMethod Algorithm="${escapeHtml(contentEncryptionMethod)}" />
  ${keyInfo}
  <xenc:CipherData>
    <xenc:CipherValue>${escapeHtml(encryptedContent)}</xenc:CipherValue>
  </xenc:CipherData>
</xenc:EncryptedData>
`;

export default encryptedKeyTemplate;
