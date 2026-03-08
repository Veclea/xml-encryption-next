适用于 Node.js 的 W3C XML 加密实现 (http://www.w3.org/TR/xmlenc-core/)

由于 https://github.com/nodejs/node/issues/52017，Node ,18+ 不再支持三重 DES (Triple DES) 算法。
## 声明

本库基于xml-encryption修改而来，原仓库 [Responsible Disclosure Program](https://github.com/auth0/node-xml-encryption) 
## Usage

    npm install xml-encryption-next

### 加密

~~~js
var xmlenc = require('xml-encryption');

var options = {
    rsa_pub: fs.readFileSync(__dirname + '/your_rsa.pub'), // 读取 RSA 公钥
    pem: fs.readFileSync(__dirname + '/your_public_cert.pem'), // 读取公共证书
    encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes256-cbc', // 加密算法
    keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p', // 密钥加密算法
    keyEncryptionDigest: 'sha256', // 密钥加密摘要
    keyEncryptionMgf1:"sha1",//http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p默认sha1 
    disallowEncryptionWithInsecureAlgorithm: true, // 禁止使用rsa-1_5  tripledes-cbc
    disallowInsecureEncryption:true,//禁aes cbc系列加密算法
    disallowInsecureHash:true, //禁止使用不安全的签名hash算法，不包括mgf1
    warnInsecureAlgorithm: true // 使用不安全算法时发出警告
};

xmlenc.encrypt('要加密的内容', options, function(err, result) {
    console.log(result);
}
~~~

结果:
~~~xml
<xenc:EncryptedData Type="http://www.w3.org/2001/04/xmlenc#Element" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
  <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes-256-cbc" />
    <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
      <e:EncryptedKey xmlns:e="http://www.w3.org/2001/04/xmlenc#">
        <e:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p">
          <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />
        </e:EncryptionMethod>
        <KeyInfo>
          <X509Data><X509Certificate>MIIEDzCCAveg... base64 cert... q3uaLvlAUo=</X509Certificate></X509Data>
        </KeyInfo>
        <e:CipherData>
          <e:CipherValue>sGH0hhzkjmLWYYY0gyQMampDM... encrypted symmetric key ...gewHMbtZafk1MHh9A==</e:CipherValue>
        </e:CipherData>
      </e:EncryptedKey>
    </KeyInfo>
    <xenc:CipherData>
        <xenc:CipherValue>V3Vb1vDl055Lp92zvK..... encrypted content.... kNzP6xTu7/L9EMAeU</xenc:CipherValue>
    </xenc:CipherData>
</xenc:EncryptedData>
~~~

### 解密

~~~js
var options = {
    key: fs.readFileSync(__dirname + '/your_private_key.key'),
    disallowInsecureEncryption:true,//开启会禁止解密使用aes cbc系列加密算法的xml
    disallowDecryptionWithInsecureAlgorithm: true,//开启会禁止解密使用rsa-1_5 tripledes-cbc加密算法的xml
    warnInsecureAlgorithm: true,
    disallowInsecureHash:true,//开启会禁止解密使用 hsa1系列 hash算法的xml
};

xmlenc.decrypt('<xenc:EncryptedData ..... </xenc:EncryptedData>', options, function(err, result) {
    console.log(result);
}

~~~

## 支持的算法

目前该库支持：

* 用于传输对称密钥的
    * http://www.w3.org/2009/xmlenc11#rsa-oaep
    * http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p
    * http://www.w3.org/2001/04/xmlenc#rsa-1_5 (不安全算法)

    
* 用于数据加密的:
    * http://www.w3.org/2001/04/xmlenc#aes128-cbc
    * http://www.w3.org/2001/04/xmlenc#aes192-cbc
    * http://www.w3.org/2001/04/xmlenc#aes256-cbc
    * http://www.w3.org/2009/xmlenc11#aes128-gcm
    * http://www.w3.org/2009/xmlenc11#aes192-gcm
    * http://www.w3.org/2009/xmlenc11#aes256-gcm
    * http://www.w3.org/2001/04/xmlenc#tripledes-cbc (不安全算法)


* 用于OAEP Hash和 MGF1 hASH:
    * http://www.w3.org/2000/09/xmldsig#sha1  (http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p 只能固定使用此sha1，传入参数会被覆盖)
    * http://www.w3.org/2001/04/xmlenc#sha256
    * http://www.w3.org/2001/04/xmlenc#sha384
    * http://www.w3.org/2001/04/xmlenc#sha512 

可以通过在加密/解密时设置  `disallowEncryptionWithInsecureAlgorithm`/`disallowDecryptionWithInsecureAlgorithm` 标志来禁用不安全算法。

默认情况下，当使用上述算法时，会通过 `console.warn()`输出警告 。可以通过 `warnInsecureAlgorithm` 标志禁用的此警告。



