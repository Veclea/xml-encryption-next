import escapeHtml from 'escape-html';

const keyInfoTemplate = ({ encryptionPublicCert, encryptedKey, keyEncryptionMethod, keyEncryptionDigest }) => `
<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
  <e:EncryptedKey xmlns:e="http://www.w3.org/2001/04/xmlenc#">
    <e:EncryptionMethod Algorithm="${escapeHtml(keyEncryptionMethod)}">
      <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#${escapeHtml(keyEncryptionDigest)}" />
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

export default keyInfoTemplate;