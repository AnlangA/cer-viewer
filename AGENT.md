# cer-viewer 项目分析与重构计划

## 项目概述

cer-viewer 是一个使用 egui/eframe 构建的现代化 X.509 证书查看器，当前支持 PEM 和 DER 编码的 X.509 v3 证书（RFC 5280）。

---

## 一、当前功能分析

### 1.1 已支持的格式

| 格式 | 扩展名 | 支持状态 | 使用的库 |
|------|--------|----------|----------|
| X.509 PEM | `.pem`, `.crt` | ✅ 完全支持 | `x509-parser` 0.18.1 |
| X.509 DER | `.cer`, `.der` | ✅ 完全支持 | `x509-parser` 0.18.1 |

### 1.2 已实现的功能

1. **证书解析**
   - PEM 和 DER 格式自动检测
   - 证书链支持（多证书 PEM 文件）
   - 完整的 X.509 v3 字段解析

2. **证书字段展示**
   - 版本、序列号、签名算法
   - 颁发者和主题详细信息
   - 有效期（Not Before / Not After）
   - 公钥信息（算法、密钥大小、公钥字节）
   - X.509 v3 扩展（SAN、Key Usage、Basic Constraints 等）
   - 签名值
   - SHA-256 和 SHA-1 指纹

3. **UI 功能**
   - 多标签页证书查看
   - 可折叠字段树
   - 深色主题
   - 拖放支持
   - 复制到剪贴板
   - 中文支持（Noto Sans SC 字体）

### 1.3 当前依赖版本

```toml
eframe = "0.33.3"
egui = "0.33.3"
x509-parser = "0.18.1"
pem = "3.0.6"
oid-registry = "0.8.1"
hex = "0.4.3"
chrono = "0.4.44"
tracing = "0.1.44"
tracing-subscriber = "0.3.23"
arboard = "3.4.1"
thiserror = "2.0"
base64 = "0.22"
```

---

## 二、缺失的常用证书格式与功能

### 2.1 重要的证书格式缺失

| 格式 | 扩展名 | 重要性 | 推荐库 |
|------|--------|--------|--------|
| PKCS#12 | `.p12`, `.pfx` | ⭐⭐⭐⭐⭐ | `pkcs12` 0.2.0-pre.0 或 `p12-keystore` 0.3.0-rc3 |
| PKCS#7/CMS | `.p7b`, `.p7c` | ⭐⭐⭐⭐⭐ | `cms` 0.3.0-pre.2 |
| PKCS#8 私钥 | `.key`, `.p8` | ⭐⭐⭐⭐ | `sec1` 0.8.0, `pkcs8` |
| JKS | `.jks` | ⭐⭐⭐ | 需要研究或实现解析器 |
| BKS | `.bks` | ⭐⭐ | 低优先级 |
| JCEKS | `.jceks` | ⭐⭐ | 低优先级 |
| CRL | `.crl` | ⭐⭐⭐⭐ | 可能已在 x509-parser 中 |
| OCSP 响应 | `.der` | ⭐⭐⭐ | `x509-ocsp` 0.2.1 |
| CSR (证书签名请求) | `.csr`, `.p10` | ⭐⭐⭐⭐ | 需要实现 |
| TSA 时间戳 | `.tsr` | ⭐⭐⭐ | `cms` 扩展 |
| S/MIME | `.p7m`, `.smime` | ⭐⭐⭐ | `cms` |
| Authenticode 签名 | 嵌入 PE/MSI | ⭐⭐ | 需要研究 |

### 2.2 缺失的功能特性

1. **私钥支持**
   - PEM/DER 格式的私钥查看（RSA、EC、Ed25519）
   - 推荐库: `sec1` 0.8.0, `spki` 0.8.0-rc.4

2. **证书验证**
   - 证书链验证
   - 吊销状态检查（OCSP、CRL）
   - 推荐库: `webpki` (rustls 生态)

3. **证书导出/转换**
   - 格式转换（PEM ↔ DER ↔ PKCS#12）
   - 证书和私钥导出

4. **ASN.1 结构查看器**
   - 原始 ASN.1 结构可视化
   - DER 字节级解析
   - 推荐库: `der` 0.8.0

5. **密钥对生成**
   - RSA、ECDSA、Ed25519 密钥对生成
   - 自签名证书生成

6. **证书比较**
   - 证书差异对比
   - 证书链可视化

7. **证书透明度 (CT)**
   - CT Log 查询
   - SCT 验证（当前仅显示，需验证签名）

8. **时间戳服务 (TSA)**
   - RFC 3161 时间戳令牌解析

9. **S/MIME 支持**
   - 解析 S/MIME 签名邮件
   - 显示签名者信息

10. **代码签名**
    - Authenticode 签名解析
    - JAR 签名验证

11. **网络功能**
    - OCSP 在线验证（不只是解析）
    - CRL 下载和解析
    - CT Log 查询

---

## 三、重构计划

### 3.1 阶段 0: 依赖升级与架构优化

#### 目标
- 升级所有依赖到最新稳定版本
- 优化项目架构，使用 Rust 最佳实践
- 改进错误处理

#### 任务清单

1. **升级核心依赖**
   ```toml
   # 建议的升级版本
   eframe = "0.31"    # 检查最新版本
   egui = "0.31"      # 检查最新版本
   x509-parser = "0.18"  # 当前已是最新
   pem = "3"           # 当前已是最新
   ```

2. **添加新依赖**
   ```toml
   # PKCS#12 支持
   pkcs12 = "0.2.0-pre.0"

   # CMS/PKCS#7 支持
   cms = "0.3.0-pre.2"

   # 私钥支持
   sec1 = "0.8"
   spki = "0.8"
   pkcs8 = "0.11"          # PKCS#8 私钥格式
   rsa = "0.10"            # RSA 密钥生成和解析
   ecdsa = "0.17"          # ECDSA 支持
   ed25519 = "2"           # Ed25519 支持

   # ASN.1 DER 解析
   der = { version = "0.8", features = ["alloc", "oid"] }

   # OCSP 支持
   x509-ocsp = "0.2"       # OCSP 响应解析

   # 密码学库（用于 PKCS#12 解密）
   aes = "0.8"
   des = "0.8"
   pbkdf2 = "0.12"
   sha2 = "0.10"
   md-5 = "0.10"

   # 安全性 - 敏感数据清零
   zeroize = "1.8"
   secrecy = "0.10"        # 秘密类型保护

   # 网络请求（用于在线验证）
   reqwest = { version = "0.12", features = ["blocking"] }
   # 或者使用更轻量的:
   # ureq = "2.12"

   # 序列化（用于配置和导出）
   serde = { version = "1.0", features = ["derive"] }
   serde_json = "1.0"
   toml = "0.8"

   # 日期时间处理（已有 chrono，补充）
   # chrono = "0.4"

   # 日志和调试
   # tracing = "0.1"
   # tracing-subscriber = "0.3"

   # 证书验证（可选，暂不使用 webpki）
   # webpki = "0.22"
   ```

3. **架构重构**
   - 创建 `formats` 模块，按格式类型组织代码
   - 统一 `Certificate` trait/enum，支持多种证书类型
   - 分离解析逻辑和 UI 渲染逻辑
   - 使用 `thiserror` 改进错误处理

### 3.2 阶段 1: PKCS#12 支持

#### 目标
- 解析 PKCS#12 (.p12, .pfx) 文件
- 显示证书链和私钥信息
- 支持密码保护的文件

#### 实现任务

1. **添加 PKCS#12 解析器模块**
   ```rust
   // src/formats/pkcs12.rs
   pub fn parse_pkcs12(data: &[u8], password: Option<&str>) -> Result<Pkcs12Bundle>
   pub struct Pkcs12Bundle {
       pub certificates: Vec<ParsedCert>,
       pub private_key: Option<PrivateKey>,
       pub friendly_name: Option<String>,
   }
   ```

2. **UI 更新**
   - 添加密码输入对话框
   - 显示 PKCS#12 内容概览
   - 支持展开查看每个证书和私钥

3. **测试用例**
   - 创建测试用的 PKCS#12 文件
   - 测试有密码和无密码的文件

### 3.3 阶段 2: PKCS#7/CMS 支持

#### 目标
- 解析 PKCS#7/CMS (.p7b, .p7c) 文件
- 显示证书链
- 支持 SignedData 和 EnvelopedData

#### 实现任务

1. **添加 CMS 解析器模块**
   ```rust
   // src/formats/cms.rs
   pub fn parse_cms(data: &[u8]) -> Result<CmsContent>
   pub enum CmsContent {
       SignedData(Box<SignedData>),
       EnvelopedData(Box<EnvelopedData>),
       Data(Vec<u8>),
       // ...
   }
   ```

2. **UI 更新**
   - 显示 CMS 内容类型
   - 展示签名者信息
   - 显示封装数据的接收者信息

### 3.4 阶段 3: 私钥支持

#### 目标
- 支持 PEM 和 DER 格式的私钥查看
- 支持 RSA、ECDSA、Ed25519 密钥
- 显示密钥参数和公钥信息

#### 实现任务

1. **添加私钥解析器模块**
   ```rust
   // src/formats/private_key.rs
   pub fn parse_private_key(data: &[u8]) -> Result<PrivateKey>
   pub enum PrivateKey {
       Rsa(RsaPrivateKey),
       Ec(EcPrivateKey),
       Ed25519(Ed25519KeyPair),
   }
   ```

2. **UI 更新**
   - 私钥查看器（带敏感信息警告）
   - 显示密钥参数
   - 公钥导出

### 3.5 阶段 4: CSR 支持

#### 目标
- 支持证书签名请求（PKCS#10）
- 显示 CSR 中的所有字段
- 支持 CSR 验证

#### 实现任务

1. **添加 CSR 解析器模块**
   ```rust
   // src/formats/csr.rs
   pub fn parse_csr(data: &[u8]) -> Result<Csr>
   pub struct Csr {
       pub version: u32,
       pub subject: X509Name,
       pub public_key: SubjectPublicKeyInfo,
       pub attributes: Vec<Attribute>,
       pub signature_algorithm: AlgorithmIdentifier,
       pub signature: BitString,
   }
   ```

### 3.6 阶段 5: CRL 和 OCSP 支持

#### 目标
- 解析证书吊销列表（CRL）
- 解析 OCSP 响应
- 在证书视图中显示吊销状态

### 3.7 阶段 6: 证书验证

#### 目标
- 实现完整的证书链验证
- 检查吊销状态
- 显示验证结果

### 3.8 阶段 7: 高级功能

1. **ASN.1 结构查看器**
   - 显示原始 DER 结构
   - 字节级解析
   - OID 解析

2. **格式转换**
   - PEM ↔ DER
   - PKCS#12 导出
   - 证书导出

3. **证书比较**
   - 并排比较两个证书
   - 高亮显示差异

4. **密钥对生成**
   - 生成新的密钥对
   - 创建自签名证书

---

## 四、安全性考虑

### 4.1 敏感数据保护

1. **内存安全**
   - 使用 `zeroize` crate 在敏感数据使用后清零内存
   - 使用 `secrecy::Secret` 类型保护私钥和密码
   - 避免敏感数据出现在日志中

2. **私钥处理**
   - 私钥不应被复制到剪贴板（警告用户）
   - 导出私钥时需要确认
   - 内存中的私钥使用后立即清零

3. **密码处理**
   - 密码输入框不应显示明文
   - 密码不在日志中记录
   - 密码在内存中尽量短时间存在

4. **文件安全**
   - 不自动保存敏感数据
   - 临时文件安全处理
   - 错误信息不泄露敏感路径

### 4.2 安全实现示例

```rust
use zeroize::Zeroize;
use secrecy::{Secret, ExposeSecret};

// 密码处理
pub struct ProtectedPassword(Secret<String>);

impl ProtectedPassword {
    pub fn new(password: String) -> Self {
        Self(Secret::new(password))
    }

    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }
}

impl Drop for ProtectedPassword {
    fn drop(&mut self) {
        // 确保密码内存被清零
        self.0.expose_secret().zeroize();
    }
}

// 私钥包装
pub struct ProtectedPrivateKey {
    key_data: Secret<Vec<u8>>,
}

impl ProtectedPrivateKey {
    pub fn from_bytes(data: Vec<u8>) -> Self {
        Self {
            key_data: Secret::new(data),
        }
    }
}
```

---

## 五、测试策略

### 5.1 测试文件结构

```
tests/
├── integration/
│   ├── mod.rs
│   ├── format_detection.rs
│   ├── pkcs12_tests.rs
│   ├── cms_tests.rs
│   └── chain_tests.rs
├── fixtures/
│   ├── certificates/
│   │   ├── valid/
│   │   ├── expired/
│   │   └── self_signed/
│   ├── keys/
│   │   ├── rsa/
│   │   ├── ec/
│   │   └── ed25519/
│   ├── pkcs12/
│   │   ├── no_password/
│   │   └── with_password/
│   └── cms/
│       ├── signed_data/
│       └── enveloped_data/
└── fuzz/
    └── certificate_fuzz.rs
```

### 5.2 测试类别

1. **单元测试**
   - 每个解析器模块的单元测试
   - 错误处理测试
   - 边界条件测试

2. **集成测试**
   - 完整文件解析测试
   - 格式转换测试
   - 证书链验证测试

3. **属性测试**
   - 使用 `proptest` 进行属性测试
   - 往返测试（PEM ↔ DER ↔ PEM）
   - 格式检测测试

4. **模糊测试**
   - 使用 `cargo-fuzz` 测试解析器
   - 崩溃和内存安全测试

### 5.3 测试数据生成

```rust
// 生成测试证书
#[cfg(test)]
mod fixtures {
    use openssl::x509::X509;
    use openssl::pkey::{PKey, Private};
    use openssl::bn::BigNum;
    use openssl::rsa::Rsa;

    pub fn generate_test_cert() -> (Vec<u8>, Vec<u8>) {
        // 生成自签名证书
        // ...
    }

    pub fn generate_test_pkcs12(password: &str) -> Vec<u8> {
        // 生成 PKCS#12 测试文件
        // ...
    }
}
```

---

## 六、性能优化

### 6.1 大文件处理

1. **流式解析**
   - 对于大型证书链，使用流式解析
   - 延迟加载证书详情

2. **内存管理**
   - 使用 `Cow<[u8]>` 避免不必要的复制
   - 解析后释放原始数据

3. **缓存策略**
   - 缓存指纹计算结果
   - 缓存 OID 解析结果

### 6.2 UI 性能

1. **虚拟滚动**
   - 对于大量证书，使用虚拟滚动

2. **延迟渲染**
   - 只渲染可见区域的证书详情

3. **后台加载**
   - 在后台线程解析大文件
   - 使用 `std::thread` 或 `rayon`

---

## 七、新增功能规划

### 7.1 CLI 模式

添加命令行界面支持，方便脚本使用：

```bash
# 查看证书信息
cer-viewer cli show cert.pem

# 验证证书链
cer-viewer cli validate --chain chain.pem

# 转换格式
cer-viewer cli convert cert.pem --to pkcs12 --out cert.p12

# 检查吊销状态
cer-viewer cli ocsp --cert cert.pem --issuer issuer.pem
```

使用 `clap` crate 实现 CLI：

```toml
clap = { version = "4.5", features = ["derive"] }
```

### 7.2 批处理

1. **批量验证**
   - 验证目录中的所有证书
   - 生成验证报告

2. **批量转换**
   - 转换目录中的证书格式

3. **证书搜索**
   - 按主题、颁发者、序列号搜索
   - 按有效期范围搜索

### 7.3 网络功能

1. **OCSP 在线验证**
   ```rust
   // 使用 reqwest 发送 OCSP 请求
   async fn verify_ocsp_online(cert: &X509Certificate, issuer: &X509Certificate) -> Result<OCSPStatus>
   ```

2. **CRL 下载**
   ```rust
   async fn fetch_crl(url: &str) -> Result<CertificateList>
   ```

3. **CT Log 查询**
   ```rust
   async fn query_ct_log(leaf_hash: &[u8]) -> Result<Vec<SCT>>
   ```

### 7.4 证书链可视化

1. **树形视图**
   - 显示证书链的层次结构
   - 标记信任锚

2. **验证状态**
   - 显示每个证书的验证状态
   - 高亮显示问题证书

### 7.5 配置和设置

1. **用户设置**
   - 主题选择
   - 默认字体大小
   - 最近文件列表
   - 信任存储配置

2. **配置文件**
   ```toml
   # ~/.config/cer-viewer/config.toml
   [general]
   theme = "dark"
   language = "zh-CN"
   check_updates = true

   [security]
   warn_before_copy_key = true
   remember_passwords = false

   [network]
   enable_ocsp = true
   timeout = 30
   proxy = ""
   ```

### 7.6 多语言支持

1. **支持的语种**
   - 英文（默认）
   - 简体中文（已有字体支持）
   - 繁体中文
   - 日文
   - 韩文

2. **实现方式**
   ```rust
   // 使用 fluent-rs 进行国际化
   fluent = "0.16"
   fluent-langneg = "0.13"
   ```

---

## 八、架构设计

### 8.1 模块结构

```
src/
├── main.rs                 # 应用入口
├── cli/                    # CLI 模式 (可选)
│   ├── mod.rs
│   ├── args.rs            # 命令行参数
│   └── commands.rs        # CLI 命令
├── ui/                     # UI 模块
│   ├── mod.rs
│   ├── app.rs             # 主应用状态
│   ├── views.rs           # 各种视图
│   ├── widgets.rs         # 自定义 UI 组件
│   ├── dialogs.rs         # 对话框（密码输入等）
│   └── theme.rs           # 主题定义
├── cert/                   # 证书处理模块
│   ├── mod.rs
│   ├── error.rs           # 错误类型
│   ├── format.rs          # 格式检测和处理
│   └── fields.rs          # 字段解析和显示
├── formats/                # 格式解析器
│   ├── mod.rs
│   ├── x509.rs            # X.509 证书
│   ├── pkcs12.rs          # PKCS#12
│   ├── pkcs8.rs           # PKCS#8 私钥
│   ├── cms.rs             # CMS/PKCS#7
│   ├── csr.rs             # 证书签名请求
│   ├── crl.rs             # 证书吊销列表
│   ├── ocsp.rs            # OCSP 响应
│   ├── tsa.rs             # TSA 时间戳
│   ├── private_key.rs     # 私钥（RSA/EC/Ed25519）
│   └── asn1.rs            # ASN.1 原始解析
├── validation/             # 证书验证
│   ├── mod.rs
│   ├── chain.rs           # 链验证
│   ├── revocation.rs      # 吊销检查
│   ├── ct.rs              # 证书透明度
│   └── ocsp.rs            # OCSP 在线验证
├── network/                # 网络请求
│   ├── mod.rs
│   ├── ocsp_client.rs     # OCSP 客户端
│   ├── crl_fetcher.rs     # CRL 下载
│   └── ct_client.rs       # CT Log 客户端
├── crypto/                 # 加密工具
│   ├── mod.rs
│   ├── keys.rs            # 密钥生成
│   ├── signatures.rs      # 签名验证
│   └── password.rs        # 密码处理（PKCS#12）
├── export/                 # 导出和转换
│   ├── mod.rs
│   ├── pem.rs             # PEM 导出
│   ├── der.rs             # DER 导出
│   ├── pkcs12.rs          # PKCS#12 导出
│   └── convert.rs         # 格式转换
├── security/               # 安全相关
│   ├── mod.rs
│   ├── zeroize.rs         # 敏感数据清零
│   └── protected.rs       # 受保护类型
├── config/                 # 配置管理
│   ├── mod.rs
│   ├── settings.rs        # 用户设置
│   └── prefs.rs           # 偏好
└── utils/                  # 工具函数
    ├── mod.rs
    ├── oid.rs             # OID 助手
    ├── time.rs            # 时间处理
    └── base64.rs          # Base64 工具
```

### 8.2 核心 Trait 设计

```rust
/// 可解析的证书/密钥格式
pub trait Parseable: Sized {
    type Error;

    fn from_pem(data: &[u8]) -> Result<Self, Self::Error>;
    fn from_der(data: &[u8]) -> Result<Self, Self::Error>;
    fn detect_format(data: &[u8]) -> Format;
}

/// 可显示的证书/密钥
pub trait Displayable {
    fn title(&self) -> String;
    fn summary(&self) -> String;
    fn fields(&self) -> Vec<Field>;
    fn fingerprint(&self) -> String;
}

/// 可导出的证书/密钥
pub trait Exportable {
    fn to_pem(&self) -> String;
    fn to_der(&self) -> Vec<u8>;
}
```

### 4.3 统一的证书类型

```rust
pub enum Certificate {
    X509(x509::X509Certificate),
    Csr(csr::CertificateRequest),
    Crl(crl::CertificateList),
}

pub enum KeyEntry {
    Certificate(Certificate),
    PrivateKey(PrivateKey),
    PublicKey(PublicKey),
    Bundle(Vec<KeyEntry>),
}

pub struct FileContent {
    pub filename: String,
    pub format: FileFormat,
    pub entries: Vec<KeyEntry>,
    pub password_protected: bool,
}
```

---

## 九、实现优先级

### 高优先级（核心功能）
1. ✅ 架构重构和依赖升级
2. ✅ PKCS#12 支持
3. ✅ PKCS#7/CMS 支持
4. ✅ 私钥支持（含 PKCS#8）
5. ✅ 安全性增强（zeroize、secrecy）

### 中优先级（增强功能）
6. ✅ CSR 支持
7. ✅ CRL 和 OCSP 响应解析
8. ✅ ASN.1 结构查看器
9. ✅ 证书链可视化
10. ✅ 格式转换（PEM ↔ DER ↔ PKCS#12）

### 低优先级（高级功能）
11. ⏳ 证书验证（链验证、吊销检查）
12. ⏳ OCSP 在线验证
13. ⏳ CT Log 查询和 SCT 验证
14. ⏳ 证书比较
15. ⏳ 密钥对生成
16. ⏳ CLI 模式
17. ⏳ 批处理功能

---

## 十、技术决策

### 10.1 库选择（更新版）

| 功能 | 库 | 版本 | 理由 |
|------|-----|------|------|
| X.509 解析 | `x509-parser` | 0.18.1 | 成熟、稳定、功能完整 |
| PKCS#12 | `pkcs12` | 0.2.0-pre.0 | 纯 Rust 实现 |
| PKCS#8 | `pkcs8` | 0.11 | 私钥格式标准 |
| CMS/PKCS#7 | `cms` | 0.3.0-pre.2 | 替代已弃用的 pkcs7 |
| OCSP | `x509-ocsp` | 0.2.1 | OCSP 响应解析 |
| EC 私钥 | `sec1` | 0.8.0 | SEC1 EC 私钥 |
| 公钥 | `spki` | 0.8.0-rc.4 | 公钥信息解析 |
| RSA | `rsa` | 0.10 | RSA 密钥支持 |
| DER 解析 | `der` | 0.8.0 | ASN.1 DER 支持 |
| 安全 | `zeroize` | 1.8 | 敏感数据清零 |
| 安全 | `secrecy` | 0.10 | 秘密类型保护 |
| UI | `egui`/`eframe` | 0.33+ | 继续使用 |
| CLI | `clap` | 4.5 | 命令行参数 |
| 网络 | `reqwest` | 0.12 | HTTP 客户端 |
| 国际化 | `fluent` | 0.16 | 多语言支持 |

### 10.2 Rust 最佳实践

1. **错误处理**
   - 使用 `thiserror` 定义错误类型
   - 提供详细的错误上下文
   - 使用 `Result` 类型而非 panic

2. **模块化**
   - 功能模块分离
   - 清晰的依赖关系
   - 可测试的代码

3. **性能**
   - 零拷贝解析（使用 `x509-parser`）
   - 延迟解析大型文件
   - 缓存常用数据

4. **测试**
   - 单元测试覆盖核心功能
   - 集成测试覆盖格式解析
   - 使用真实的证书文件进行测试

---

## 十一、里程碑（更新版）

| 里程碑 | 目标 | 预计时间 | 依赖 |
|--------|------|----------|------|
| M0 | 架构重构、依赖升级、安全性基础 | 1-2 周 | - |
| M1 | PKCS#12 和 PKCS#7 支持 | 2-3 周 | M0 |
| M2 | 私钥支持（含 PKCS#8） | 1-2 周 | M0 |
| M3 | CSR 支持 | 1 周 | M0 |
| M4 | CRL 和 OCSP 响应解析 | 1 周 | M0 |
| M5 | 证书链可视化 | 1 周 | M1, M4 |
| M6 | ASN.1 结构查看器 | 1 周 | M0 |
| M7 | 格式转换和导出 | 1-2 周 | M1, M2 |
| M8 | 证书验证和吊销检查 | 2-3 周 | M4, M5 |
| M9 | 网络功能（OCSP/CRL 在线） | 1-2 周 | M8 |
| M10 | CLI 模式 | 1-2 周 | M7 |
| M11 | 高级功能（比较、生成、批处理） | 2-3 周 | M7, M10 |

---

## 十二、风险评估（更新版）

### 技术风险
1. **预发布版本的依赖** - `pkcs12` 和 `cms` 目前是 pre-release 版本
   - 缓解：密切关注这些库的更新，必要时贡献代码或 fork 维护

2. **JKS 格式支持** - 缺乏成熟的 Rust 库
   - 缓解：通过文档实现，或建议用户转换格式

3. **密码学功能** - PKCS#12 解密需要多种加密算法
   - 缓解：使用成熟的密码学库（`aes-gcm`, `des`, `pbkdf2`）

4. **网络请求** - OCSP/CRL 在线验证需要网络功能
   - 缓解：使用 `reqwest`，支持超时和代理配置

5. **内存安全** - 敏感数据（私钥、密码）需要安全处理
   - 缓解：使用 `zeroize` 和 `secrecy`

6. **跨平台兼容性** - 密码学库在不同平台的支持
   - 缓解：使用纯 Rust 实现，避免平台依赖

### 项目风险
1. **向后兼容性** - 用户提到不需要考虑兼容性
   - 影响：可以大胆重构数据结构

2. **UI 复杂度** - 新增功能会增加 UI 复杂度
   - 缓解：使用标签页、折叠面板、设置对话框等保持界面整洁

3. **性能问题** - 大型证书链和 PKCS#12 文件解析
   - 缓解：后台加载、延迟解析、缓存

4. **测试覆盖** - 各种格式和边缘情况需要充分测试
   - 缓解：建立完整的测试套件，包括模糊测试

### 安全风险
1. **私钥泄露** - 内存、日志、剪贴板
   - 缓解：使用 `secrecy`、禁止日志输出敏感数据、警告用户

2. **密码存储** - 不应记住密码
   - 缓解：明确不实现密码记住功能

3. **网络攻击** - OCSP/CRL 请求可能被劫持
   - 缓解：支持 HTTPS 证书验证、代理配置

---

## 十三、补充任务列表

基于以上分析，新增以下任务：

1. **安全性增强任务**
   - [ ] 使用 `zeroize` 保护敏感数据
   - [ ] 使用 `secrecy` 包装私钥和密码
   - [ ] 审查日志输出，确保无敏感信息
   - [ ] 添加私钥复制警告

2. **测试任务**
   - [ ] 建立测试文件生成脚本
   - [ ] 添加模糊测试配置
   - [ ] 设置 CI 测试流程

3. **UI 增强任务**
   - [ ] 证书链可视化组件
   - [ ] 密码输入对话框
   - [ ] 设置对话框
   - [ ] 进度指示器（大文件加载）

4. **网络功能任务**
   - [ ] OCSP 客户端实现
   - [ ] CRL 下载器实现
   - [ ] CT Log 查询实现
   - [ ] 网络设置配置

5. **CLI 模式任务**
   - [ ] CLI 参数解析
   - [ ] show 命令
   - [ ] validate 命令
   - [ ] convert 命令
   - [ ] ocsp 命令

---

## 十四、后续步骤

1. **立即开始**：创建新的分支进行架构重构
2. **优先级排序**：按里程碑顺序实现功能
3. **持续测试**：每个阶段完成后进行测试
4. **文档更新**：同步更新 README 和用户文档
5. **安全审查**：每个功能模块完成后进行安全审查

---

## 十五、总结

本计划经过详细分析后进行了以下补充：

1. **新增格式支持**：PKCS#8、OCSP 响应、TSA 时间戳、S/MIME、Authenticode
2. **安全性考虑**：完整的敏感数据保护策略
3. **测试策略**：详细的测试计划和结构
4. **性能优化**：大文件处理和 UI 性能
5. **网络功能**：OCSP/CRL 在线验证、CT Log 查询
6. **CLI 模式**：命令行界面支持
7. **配置管理**：用户设置和偏好
8. **国际化**：多语言支持框架
9. **风险评估**：更全面的风险识别和缓解措施
10. **依赖更新**：更完整的依赖清单

---

*此计划由 Claude 于 2025-03-17 生成并补充，基于当前项目状态和 Rust 生态系统的最新调研。*
