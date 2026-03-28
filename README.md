# xml-encryption-next

适用于 Node.js 的 W3C XML 加密实现 (http://www.w3.org/TR/xmlenc-core/)

基于 [auth0/node-xml-encryption](https://github.com/auth0/node-xml-encryption) 修改和优化而来。

## ⚠️ 安全声明

- **RSA-1_5** 和 **3DES-CBC** 已被认为不安全，不推荐在新项目中使用
- **AES-CBC** 模式存在填充预言攻击风险，推荐使用 **AES-GCM** 模式
- **SHA-1** 哈希算法已不推荐，推荐使用 **SHA-256** 或更强算法
- 本库提供安全标志来禁用不安全的算法

## 安装

```bash
npm install xml-encryption-next
```

## 快速开始

### 加密

```javascript
import { encrypt } from 'xml-encryption-next';
import fs from 'fs';

const options = {
    rsa_pub: fs.readFileSync('./your_rsa.pub'),           // RSA 公钥
    pem: fs.readFileSync('./your_cert.pem'),              // X509 证书
    encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes256-gcm',  // 内容加密算法
    keyEncryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#rsa-oaep', // 密钥加密算法
    keyEncryptionDigest: 'sha256',                        // OAEP 哈希算法
    keyEncryptionMgf1: 'sha256',                          // MGF1 哈希算法
    disallowInsecureEncryption: true,                     // 禁用不安全的加密算法
    disallowInsecureHash: true,                           // 禁用不安全的哈希算法
    warnInsecureAlgorithm: true                           // 使用不安全算法时发出警告
};

encrypt('要加密的内容', options, function(err, encryptedXml) {
    if (err) {
        console.error('加密失败:', err);
        return;
    }
    console.log('加密后的 XML:', encryptedXml);
});
```

### 解密

```javascript
import { decrypt } from 'xml-encryption-next';
import fs from 'fs';

const options = {
    key: fs.readFileSync('./your_private_key.pem'),       // RSA 私钥
    disallowInsecureEncryption: true,                     // 禁用不安全的加密算法
    disallowInsecureHash: true,                           // 禁用不安全的哈希算法
    warnInsecureAlgorithm: true                           // 使用不安全算法时发出警告
};

decrypt(encryptedXml, options, function(err, decryptedContent) {
    if (err) {
        console.error('解密失败:', err);
        return;
    }
    console.log('解密后的内容:', decryptedContent.toString('utf8'));
});
```

## 支持的算法

### 密钥加密算法 (Key Encryption)

| 算法 | URI | 安全性 | 说明 |
|------|-----|--------|------|
| RSA-OAEP (XML Enc 1.1) | `http://www.w3.org/2009/xmlenc11#rsa-oaep` | ✅ 推荐 | 支持自定义 OAEP 和 MGF1 哈希 |
| RSA-OAEP-MGF1P (XML Enc 1.0) | `http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p` | ⚠️ 可用 | 固定使用 SHA-1 MGF1 |
| RSA-1_5 | `http://www.w3.org/2001/04/xmlenc#rsa-1_5` | ❌ 不安全 | 已废弃，不推荐使用 |

### 内容加密算法 (Content Encryption)

| 算法 | URI | 安全性 | 说明 |
|------|-----|--------|------|
| AES-128-GCM | `http://www.w3.org/2009/xmlenc11#aes128-gcm` | ✅ 推荐 | 认证加密模式 |
| AES-192-GCM | `http://www.w3.org/2009/xmlenc11#aes192-gcm` | ✅ 推荐 | 认证加密模式 |
| AES-256-GCM | `http://www.w3.org/2009/xmlenc11#aes256-gcm` | ✅ 推荐 | 认证加密模式 |
| AES-128-CBC | `http://www.w3.org/2001/04/xmlenc#aes128-cbc` | ⚠️ 可用 | 存在填充预言攻击风险 |
| AES-192-CBC | `http://www.w3.org/2001/04/xmlenc#aes192-cbc` | ⚠️ 可用 | 存在填充预言攻击风险 |
| AES-256-CBC | `http://www.w3.org/2001/04/xmlenc#aes256-cbc` | ⚠️ 可用 | 存在填充预言攻击风险 |
| 3DES-CBC | `http://www.w3.org/2001/04/xmlenc#tripledes-cbc` | ❌ 不安全 | 已废弃 |

### 哈希算法 (Hash Algorithms for OAEP)

| 算法 | Digest URI | MGF1 URI | 安全性 |
|------|-----------|---------|--------|
| SHA-1 | `http://www.w3.org/2000/09/xmldsig#sha1` | `http://www.w3.org/2009/xmlenc11#mgf1sha1` | ⚠️ 可用 (默认) |
| SHA-256 | `http://www.w3.org/2001/04/xmlenc#sha256` | `http://www.w3.org/2009/xmlenc11#mgf1sha256` | ✅ 推荐 |
| SHA-384 | `http://www.w3.org/2001/04/xmlenc#sha384` | `http://www.w3.org/2009/xmlenc11#mgf1sha384` | ✅ 推荐 |
| SHA-512 | `http://www.w3.org/2001/04/xmlenc#sha512` | `http://www.w3.org/2009/xmlenc11#mgf1sha512` | ✅ 推荐 |

## 配置选项

### 加密选项

| 选项 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `rsa_pub` | String | ✅ | - | RSA 公钥 (PEM 格式) |
| `pem` | String | ✅ | - | X509 证书 (PEM 格式) |
| `encryptionAlgorithm` | String | ✅ | - | 内容加密算法 URI |
| `keyEncryptionAlgorithm` | String | ✅ | - | 密钥加密算法 URI |
| `keyEncryptionDigest` | String | ❌ | `sha256` | OAEP 哈希算法 (`sha1`/`sha256`/`sha384`/`sha512`) |
| `keyEncryptionMgf1` | String | ❌ | `sha256` | MGF1 哈希算法 (仅 XML Enc 1.1) |
| `input_encoding` | String | ❌ | `utf8` | 输入内容编码 |
| `disallowInsecureEncryption` | Boolean | ❌ | `false` | 禁用不安全的加密算法 (AES-CBC) |
| `disallowInsecureHash` | Boolean | ❌ | `false` | 禁用不安全的哈希算法 (SHA-1) |
| `disallowEncryptionWithInsecureAlgorithm` | Boolean | ❌ | `false` | 禁用所有不安全算法 |
| `warnInsecureAlgorithm` | Boolean | ❌ | `true` | 使用不安全算法时发出警告 |

### 解密选项

| 选项 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `key` | String | ✅ | - | RSA 私钥 (PEM 格式) |
| `disallowInsecureEncryption` | Boolean | ❌ | `false` | 禁用不安全的加密算法 |
| `disallowInsecureHash` | Boolean | ❌ | `false` | 禁用不安全的哈希算法 |
| `disallowDecryptionWithInsecureAlgorithm` | Boolean | ❌ | `false` | 禁用所有不安全算法解密 |
| `warnInsecureAlgorithm` | Boolean | ❌ | `true` | 使用不安全算法时发出警告 |

## 安全最佳实践

### ✅ 推荐的加密配置

```javascript
const secureOptions = {
    rsa_pub: publicKey,
    pem: certificate,
    encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes256-gcm',
    keyEncryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#rsa-oaep',
    keyEncryptionDigest: 'sha256',
    keyEncryptionMgf1: 'sha256',
    disallowInsecureEncryption: true,
    disallowInsecureHash: true
};
```

### ❌ 不安全的配置 (已废弃)

```javascript
// 不推荐：使用 RSA-1_5 和 AES-CBC
const insecureOptions = {
    rsa_pub: publicKey,
    pem: certificate,
    encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc',
    keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5'
    // 应使用上面推荐的配置替代
};
```

## 运行测试

```bash
npm test
```

测试套件包括：
- RSA-1_5 加密算法测试 (XML Enc 1.0)
- RSA-OAEP-MGF1P 加密算法测试 (XML Enc 1.0)
- RSA-OAEP 加密算法测试 (XML Enc 1.1)
- AES 加密算法组合测试
- 错误处理测试
- 安全策略测试
- XML 结构验证测试
- 跨算法兼容性测试

## 规范符合性

本库符合以下 W3C 规范：

- **XML Encryption Core 1.0**: https://www.w3.org/TR/xmlenc-core/
- **XML Encryption Core 1.1**: https://www.w3.org/TR/xmlenc-core1/

### XML Enc 1.0 vs 1.1 区别

| 特性 | XML Enc 1.0 | XML Enc 1.1 |
|------|------------|------------|
| RSA-OAEP 支持 | `rsa-oaep-mgf1p` (固定 SHA-1 MGF1) | `rsa-oaep` (可自定义 MGF1) |
| DigestMethod | 可选 | 推荐明确声明 |
| MGF 元素 | 不支持 | 支持 |
| AES-GCM | 不支持 | 支持 |

## 变更日志

### 4.6.0
- 优化代码结构和可读性
- 修复 XML Enc 1.1 规范符合性问题
- 改进安全检查和错误处理
- 添加全面的测试套件 (65+ 测试用例)
- 默认使用 SHA-256 替代 SHA-1
- 添加 JSDoc 文档注释

## 许可证

MIT

## 致谢

原始项目：[auth0/node-xml-encryption](https://github.com/auth0/node-xml-encryption)
