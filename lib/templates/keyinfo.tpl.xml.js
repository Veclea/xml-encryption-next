import escapeHtml from 'escape-html';

const keyInfoTemplate = ({ encryptionPublicCert, encryptedKey, keyEncryptionMethod, keyEncryptionDigest, mgfAlgorithm }) => {
    // 如果有 mgfAlgorithm，说明是 XML Enc 1.1 格式
    const mgfBlock = mgfAlgorithm
        ? `<MGF Algorithm="${escapeHtml(mgfAlgorithm)}"></MGF>`
        : '';
    const  digestBlock  = keyEncryptionDigest ?
        `      <ds:DigestMethod xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Algorithm="${escapeHtml(keyEncryptionDigest)}" />`
        : '';

    // 根据算法 URI 决定 DigestMethod 的命名空间前缀或直接写死，这里简化处理
    // XML Enc 1.1 推荐在 EncryptionMethod 内直接包含 DigestMethod 和 MGF

    return `
<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
  <e:EncryptedKey xmlns:e="http://www.w3.org/2001/04/xmlenc#">
    <e:EncryptionMethod Algorithm="${escapeHtml(keyEncryptionMethod)}">
      ${digestBlock}
      ${mgfBlock}
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