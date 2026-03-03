import escapeHtml from 'escape-html';

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