# xml-encryption-next

基于 Node.js 的 W3C XML 加密实现，支持 XML Encryption Core 1.0 和 1.1 规范。

[![npm version](https://img.shields.io/npm/v/xml-encryption-next.svg)](https://www.npmjs.com/package/xml-encryption-next)
[![License](https://img.shields.io/npm/l/xml-encryption-next.svg)](https://github.com/xml-encryption-next/blob/main/LICENSE)

## 📖 目录

- [特性](#-特性)
- [安装](#-安装)
- [快速开始](#-快速开始)
- [支持的算法](#-支持的算法)
- [API 文档](#-api-文档)
- [配置选项](#-配置选项)
- [安全最佳实践](#-安全最佳实践)
- [XML 结构说明](#-xml-结构说明)
- [常见问题](#-常见问题)
- [测试](#-测试)

## ✨ 特性

- 🔐 **完整的 XML Encryption 支持** - 支持 XML Enc 1.0 和 1.1 规范
- 🚀 **双 API 模式** - 同时支持 Callback 和 Async/Await
- 🛡️ **安全优先** - 可配置禁用不安全算法
- 📦 **零依赖** - 仅依赖 node-forge 和 xmldom
- 📝 **TypeScript 友好** - 完整的 JSDoc 注释
- 🧪 **全面测试** - 148+ 测试用例覆盖所有场景

## 📦 安装

```bash
npm install xml-encryption-next
```

## 🚀 快速开始

### 加密示例

```javascript
import { encrypt } from 'xml-encryption-next';
import fs from 'fs';

// 准备密钥和证书
const options = {
    rsa_pub: fs.readFileSync('./keys/rsa-public.pem'),      // RSA 公钥
    pem: fs.readFileSync('./keys/certificate.pem'),         // X509 证书
    encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes256-gcm',
    keyEncryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#rsa-oaep',
    keyEncryptionDigest: 'sha256',
    keyEncryptionMgf1: 'sha256'
};

// 使用 async/await
try {
    const encryptedXml = await encrypt('要加密的敏感内容', options);
    console.log('加密成功:', encryptedXml);
} catch (err) {
    console.error('加密失败:', err);
}

// 或使用回调
encrypt('要加密的敏感内容', options, (err, encryptedXml) => {
    if (err) {
        console.error('加密失败:', err);
        return;
    }
    console.log('加密成功:', encryptedXml);
});
```

### 解密示例

```javascript
import { decrypt } from 'xml-encryption-next';
import fs from 'fs';

const options = {
    key: fs.readFileSync('./keys/rsa-private.pem'),         // RSA 私钥
    disallowInsecureEncryption: true,                       // 禁用不安全加密算法
    disallowInsecureHash: true                              // 禁用不安全哈希算法
};

// 使用 async/await
try {
    const decryptedBuffer = await decrypt(encryptedXml, options);
    console.log('解密内容:', decryptedBuffer.toString('utf8'));
} catch (err) {
    console.error('解密失败:', err);
}

// 或使用回调
decrypt(encryptedXml, options, (err, decrypted) => {
    if (err) {
        console.error('解密失败:', err);
        return;
    }
    console.log('解密内容:', decrypted.toString('utf8'));
});
```

## 🔐 支持的算法

### 1. 密钥加密算法 (Key Encryption Algorithms)

用于加密对称密钥的非对称加密算法。

| 算法名称 | URI | XML Enc 版本 | 安全性 | 说明 |
|---------|-----|-------------|--------|------|
| **RSA-OAEP** | `http://www.w3.org/2009/xmlenc11#rsa-oaep` | 1.1 | ✅ 推荐 | 支持自定义 OAEP 和 MGF1 哈希，推荐使用 SHA-256 |
| **RSA-OAEP-MGF1P** | `http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p` | 1.0 | ⚠️ 可用 | 固定使用 SHA-1 MGF1，向后兼容 |
| **RSA-1_5** | `http://www.w3.org/2001/04/xmlenc#rsa-1_5` | 1.0 | ❌ 不安全 | 已废弃，仅用于向后兼容 |

#### RSA-OAEP (推荐)

```javascript
const options = {
    keyEncryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#rsa-oaep',
    keyEncryptionDigest: 'sha256',    // OAEP 哈希：sha1/sha256/sha384/sha512
    keyEncryptionMgf1: 'sha256'       // MGF1 哈希：sha1/sha256/sha384/sha512
};
```

#### RSA-OAEP-MGF1P

```javascript
const options = {
    keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
    keyEncryptionDigest: 'sha256'     // 支持 sha1/sha256/sha384/sha512
    // MGF1 固定为 sha1，不可配置
};
```

### 2. 内容加密算法 (Content Encryption Algorithms)

用于加密实际数据的对称加密算法。

| 算法名称 | URI | 密钥长度 | IV 长度 | 模式 | 安全性 |
|---------|-----|---------|--------|------|--------|
| **AES-128-GCM** | `http://www.w3.org/2009/xmlenc11#aes128-gcm` | 16 字节 | 12 字节 | GCM | ✅ 推荐 |
| **AES-192-GCM** | `http://www.w3.org/2009/xmlenc11#aes192-gcm` | 24 字节 | 12 字节 | GCM | ✅ 推荐 |
| **AES-256-GCM** | `http://www.w3.org/2009/xmlenc11#aes256-gcm` | 32 字节 | 12 字节 | GCM | ✅ 推荐 |
| **AES-128-CBC** | `http://www.w3.org/2001/04/xmlenc#aes128-cbc` | 16 字节 | 16 字节 | CBC | ⚠️ 可用 |
| **AES-192-CBC** | `http://www.w3.org/2001/04/xmlenc#aes192-cbc` | 24 字节 | 16 字节 | CBC | ⚠️ 可用 |
| **AES-256-CBC** | `http://www.w3.org/2001/04/xmlenc#aes256-cbc` | 32 字节 | 16 字节 | CBC | ⚠️ 可用 |
| **3DES-CBC** | `http://www.w3.org/2001/04/xmlenc#tripledes-cbc` | 24 字节 | 8 字节 | CBC | ❌ 不安全 |

#### AES-GCM (推荐)

GCM (Galois/Counter Mode) 提供认证加密，同时保证机密性和完整性。

```javascript
const options = {
    encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes256-gcm'
};
```

#### AES-CBC

CBC (Cipher Block Chaining) 模式需要注意填充预言攻击风险。

```javascript
const options = {
    encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes256-cbc'
};
```

### 3. 哈希算法 (Hash Algorithms)

用于 RSA-OAEP 的哈希函数。

| 算法 | URI (DigestMethod) | MGF1 URI | 输出长度 | 安全性 |
|------|-------------------|----------|---------|--------|
| **SHA-1** | `http://www.w3.org/2000/09/xmldsig#sha1` | `http://www.w3.org/2009/xmlenc11#mgf1sha1` | 160 位 | ⚠️ 可用 (默认) |
| **SHA-256** | `http://www.w3.org/2001/04/xmlenc#sha256` | `http://www.w3.org/2009/xmlenc11#mgf1sha256` | 256 位 | ✅ 推荐 |
| **SHA-384** | `http://www.w3.org/2001/04/xmlenc#sha384` | `http://www.w3.org/2009/xmlenc11#mgf1sha384` | 384 位 | ✅ 推荐 |
| **SHA-512** | `http://www.w3.org/2001/04/xmlenc#sha512` | `http://www.w3.org/2009/xmlenc11#mgf1sha512` | 512 位 | ✅ 推荐 |

## 📚 API 文档

### encrypt(content, options, [callback])

加密内容并返回 XML EncryptedData 元素。

**参数:**
- `content` (string|Buffer) - 待加密的内容
- `options` (Object) - 加密选项
- `callback` (Function, 可选) - 回调函数，不提供则返回 Promise

**返回:**
- Promise (无回调时) 或 void (有回调时)

**示例:**
```javascript
// Async/Await
const encrypted = await encrypt('secret', options);

// Callback
encrypt('secret', options, (err, encrypted) => {
    // ...
});
```

### decrypt(xml, options, [callback])

解密 XML EncryptedData 元素。

**参数:**
- `xml` (string|Document) - 加密的 XML
- `options` (Object) - 解密选项
- `callback` (Function, 可选) - 回调函数，不提供则返回 Promise

**返回:**
- Promise<Buffer> (无回调时) 或 void (有回调时)

**示例:**
```javascript
// Async/Await
const decrypted = await decrypt(encryptedXml, options);
console.log(decrypted.toString('utf8'));

// Callback
decrypt(encryptedXml, options, (err, decrypted) => {
    console.log(decrypted.toString('utf8'));
});
```

## ⚙️ 配置选项

### 加密选项

| 选项 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `rsa_pub` | String | ✅ | - | RSA 公钥 (PEM 格式) |
| `pem` | String | ✅ | - | X509 证书 (PEM 格式) |
| `encryptionAlgorithm` | String | ✅ | - | 内容加密算法 URI |
| `keyEncryptionAlgorithm` | String | ✅ | - | 密钥加密算法 URI |
| `keyEncryptionDigest` | String | ❌ | `sha256` | OAEP 哈希算法 |
| `keyEncryptionMgf1` | String | ❌ | `sha256` | MGF1 哈希算法 (仅 XML Enc 1.1) |
| `input_encoding` | String | ❌ | `utf8` | 输入内容编码 |
| `disallowInsecureEncryption` | Boolean | ❌ | `false` | 禁用 AES-CBC 算法 |
| `disallowInsecureHash` | Boolean | ❌ | `false` | 禁用 SHA-1 哈希 |
| `disallowEncryptionWithInsecureAlgorithm` | Boolean | ❌ | `false` | 禁用所有不安全算法 |
| `warnInsecureAlgorithm` | Boolean | ❌ | `true` | 使用不安全算法时警告 |

### 解密选项

| 选项 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `key` | String | ✅ | - | RSA 私钥 (PEM 格式) |
| `disallowInsecureEncryption` | Boolean | ❌ | `false` | 禁用 AES-CBC 解密 |
| `disallowInsecureHash` | Boolean | ❌ | `false` | 禁用 SHA-1 哈希解密 |
| `disallowDecryptionWithInsecureAlgorithm` | Boolean | ❌ | `false` | 禁用所有不安全算法解密 |
| `warnInsecureAlgorithm` | Boolean | ❌ | `true` | 使用不安全算法时警告 |

## 🛡️ 安全最佳实践

### ✅ 推荐配置

```javascript
const secureOptions = {
    // 密钥和证书
    rsa_pub: fs.readFileSync('./rsa-public.pem'),
    pem: fs.readFileSync('./certificate.pem'),
    
    // 使用最强的加密组合
    encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes256-gcm',
    keyEncryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#rsa-oaep',
    keyEncryptionDigest: 'sha256',
    keyEncryptionMgf1: 'sha256',
    
    // 启用安全策略
    disallowInsecureEncryption: true,
    disallowInsecureHash: true,
    warnInsecureAlgorithm: true
};
```

### ❌ 不推荐配置

```javascript
// 以下配置已过时，不推荐在新项目中使用
const deprecatedOptions = {
    rsa_pub: publicKey,
    pem: certificate,
    encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc', // ❌ CBC 模式
    keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5'  // ❌ RSA-1_5
};
```

### 算法选择指南

| 场景 | 推荐算法组合 |
|------|-------------|
| **最高安全性** | RSA-OAEP (SHA-256) + AES-256-GCM |
| **兼容性优先** | RSA-OAEP-MGF1P (SHA-256) + AES-128-CBC |
| **性能敏感** | RSA-OAEP (SHA-256) + AES-128-GCM |
| **遗留系统** | RSA-1_5 + AES-128-CBC (需启用警告) |

## 📄 XML 结构说明

### 加密后的 XML 结构

```xml
<xenc:EncryptedData Type="http://www.w3.org/2001/04/xmlenc#Element" 
                    xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
  <xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm" />
  
  <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
    <e:EncryptedKey xmlns:e="http://www.w3.org/2001/04/xmlenc#">
      <e:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep">
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
        <MGF Algorithm="http://www.w3.org/2009/xmlenc11#mgf1sha256" />
      </e:EncryptionMethod>
      <KeyInfo>
        <X509Data>
          <X509Certificate>MIID...base64 证书内容...==</X509Certificate>
        </X509Data>
      </KeyInfo>
      <e:CipherData>
        <e:CipherValue>MIIB...加密的对称密钥...==</e:CipherValue>
      </e:CipherData>
    </e:EncryptedKey>
  </KeyInfo>
  
  <xenc:CipherData>
    <xenc:CipherValue>U2FsdGVkX1...加密的内容...==</xenc:CipherValue>
  </xenc:CipherData>
</xenc:EncryptedData>
```

### XML Enc 1.0 vs 1.1 区别

| 特性 | XML Enc 1.0 | XML Enc 1.1 |
|------|------------|------------|
| RSA-OAEP 支持 | `rsa-oaep-mgf1p` (固定 SHA-1 MGF1) | `rsa-oaep` (可自定义 MGF1) |
| DigestMethod | 可选 | 推荐明确声明 |
| MGF 元素 | 不支持 | 支持 |
| AES-GCM | 不支持 | 支持 |
| 命名空间 | `xmlenc#` | `xmlenc11#` |

## ❓ 常见问题

### 1. 如何生成 RSA 密钥对？

```bash
# 生成私钥
openssl genrsa -out rsa-private.pem 2048

# 从私钥提取公钥
openssl rsa -in rsa-private.pem -pubout -out rsa-public.pem

# 生成自签名证书
openssl req -new -x509 -key rsa-private.pem -out certificate.pem -days 365
```

### 2. 如何处理大文件？

```javascript
import fs from 'fs';
import { encrypt } from 'xml-encryption-next';

// 读取文件为 Buffer
const fileBuffer = fs.readFileSync('./large-file.pdf');

// 直接传递 Buffer 进行加密
const encrypted = await encrypt(fileBuffer, options);
```

### 3. 如何与 Java/SAML 系统互操作？

```javascript
// 使用 Java 兼容的配置
const javaCompatibleOptions = {
    encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
    keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
    keyEncryptionDigest: 'sha256'
    // Java 默认不支持 MGF 元素
};
```

### 4. 解密后如何获取字符串？

```javascript
const decrypted = await decrypt(encryptedXml, options);
const content = decrypted.toString('utf8'); // 或 'binary', 'latin1' 等
```

### 5. 如何处理中文内容？

```javascript
// 默认使用 utf8 编码，无需特殊处理
const encrypted = await encrypt('中文内容 🚀', options);
const decrypted = await decrypt(encrypted, options);
console.log(decrypted.toString('utf8')); // 正常输出中文
```

## 🧪 测试

```bash
# 运行所有测试
npm test

# 运行特定测试文件
npm test -- test/async-api.test.ts

# 生成覆盖率报告
npm test -- --coverage
```

### 测试覆盖

- ✅ RSA-1_5 加密/解密测试
- ✅ RSA-OAEP-MGF1P 加密/解密测试
- ✅ RSA-OAEP 1.1 加密/解密测试
- ✅ AES-CBC/GCM 算法测试
- ✅ 错误处理测试
- ✅ 安全策略测试
- ✅ XML 结构验证测试
- ✅ 跨算法兼容性测试
- ✅ Async/Await API 测试
- ✅ Callback 兼容性测试

## 📄 许可证

MIT License

## 🔗 相关链接

- [W3C XML Encryption Core 1.0](https://www.w3.org/TR/xmlenc-core/)
- [W3C XML Encryption Core 1.1](https://www.w3.org/TR/xmlenc-core1/)
- [NIST 加密指南](https://csrc.nist.gov/publications/detail/sp/800-38a/final)
- [GitHub 仓库](https://github.com/xml-encryption-next)
