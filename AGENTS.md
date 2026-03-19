# cer-viewer

## 项目概述

cer-viewer 是一个使用 Rust 编写的现代化 X.509 证书和 CSR（证书签名请求）查看器，基于 egui/eframe 构建 GUI，同时提供功能完整的 CLI 模式。项目支持 PEM/DER 编码的证书、CSR、PKCS#12、PKCS#7/CMS 格式的解析与查看，具备证书链构建与自动补全（通过 AIA 扩展下载中间 CA）、OCSP/CRL 吊销检查、自签名证书和 CSR 生成等能力。

- **版本**: v1.2.0（`Cargo.toml` 中 crate version 为 `0.1.0`，git tag 为 `v1.2.0`）
- **许可证**: MIT OR Apache-2.0
- **最低 Rust 版本**: 1.80
- **技术栈**: egui 0.33.3 / eframe 0.33.3（GUI）、x509-parser 0.18.1（证书解析）、rcgen 0.14.7（证书生成）、clap 4.5（CLI）、reqwest 0.12（网络）、thiserror 2.0（错误处理）、serde/serde_json（序列化）、zeroize + secrecy（敏感数据保护）

## 架构概览

```
┌──────────────────────────────────────────────────┐
│                   main.rs 入口                     │
│  cli::run() ──有CLI参数──> CLI 模式 (退出)          │
│           ──无CLI参数──> GUI 模式 (eframe)          │
└──────────────────┬───────────────────────────────┘
                   │
      ┌────────────┴────────────┐
      │         GUI 模式          │          │         CLI 模式
      │  CertViewerApp (ui/app)  │          │  cli::run()
      │  ├─ toolbar.rs           │          │  ├─ 显示证书/CSR 信息
      │  ├─ tab_bar.rs           │          │  ├─ chain 子命令
      │  ├─ details_view.rs      │          │  ├─ extract 子命令
      │  ├─ chain_view.rs        │          │  ├─ verify 子命令
      │  ├─ diff_view.rs         │          │  ├─ convert 子命令
      │  ├─ field_tree.rs        │          │  ├─ fingerprint 子命令
      │  ├─ empty_state.rs       │          │  └─ cache 子命令
      │  ├─ generate_dialog.rs   │
      │  └─ password_dialog.rs   │
      └────────────┬────────────┘
                   │
         ┌─────────┴─────────┐
         │   document 模块    │  Document 枚举统一 Certificate/Csr
         └─────────┬─────────┘
                   │
    ┌──────────────┼──────────────┐
    │  cert 模块    │  formats 模块  │
    │  ParsedCert   │  ├─ x509.rs   │  (re-export cert 解析)
    │  CertField    │  ├─ csr.rs    │  ParsedCsr, CSR 解析
    │  CertChain    │  ├─ keys.rs   │  私钥解析 (feature-gated)
    │  extensions   │  ├─ pkcs12.rs │  PKCS#12 (feature-gated)
    │  chain_cache  │  ├─ cms.rs    │  CMS/PKCS#7 (feature-gated)
    └──────────────┘  └─ asn1.rs   │  ASN.1 结构查看
                      └────────────┘
```

**数据流（文件加载 -> 解析 -> 显示）**:
1. 用户通过 `rfd` 文件对话框（GUI）或 CLI 参数指定文件路径
2. 原始字节传入 `document::load_documents()` 自动检测格式（PEM/DER）
3. PEM 数据按块解析：`CERTIFICATE` -> `cert::parse_der_certificate()`，`CERTIFICATE REQUEST` -> `csr::parse_csr_der()`
4. 解析结果封装为 `Document::Certificate(ParsedCert)` 或 `Document::Csr(ParsedCsr)`
5. GUI 将 Document 存入 `CertViewerApp.documents`，通过 tab_bar/details_view/chain_view 渲染

## 模块结构

```
src/
├── main.rs              # 应用入口，初始化 tracing，分发 CLI/GUI 模式
├── lib.rs               # 库入口，公开所有子模块
├── cli.rs               # CLI 定义与实现（clap derive），所有子命令处理
├── config.rs            # 配置持久化（主题、窗口尺寸），JSON 格式
├── theme.rs             # 深色/浅色主题常量、主题切换、egui Visuals 配置
├── cert.rs              # 核心证书解析：ParsedCert, CertField, ValidityStatus, CertId
├── document.rs          # Document 枚举统一 Certificate/Csr，load_documents() 入口
├── export/
│   └── mod.rs           # PEM/DER 导出工具，链导出，pem_to_der 转换
├── formats/
│   ├── mod.rs           # 格式解析器入口（feature-gated 子模块）
│   ├── x509.rs          # re-export cert 模块的公开 API
│   ├── csr.rs           # CSR（PKCS#10）解析：ParsedCsr, CsrId, is_der_csr()
│   ├── keys.rs          # 私钥解析：KeyType, ParsedPrivateKey（private-keys feature）
│   ├── pkcs12.rs        # PKCS#12 (.p12/.pfx) 基本结构解析（pkcs12 feature）
│   ├── cms.rs           # CMS/PKCS#7 (.p7b/.p7c) 证书链提取（pkcs12 feature）
│   └── asn1.rs          # ASN.1 DER 结构查看器，tag 解析，OID 查找
├── cert/
│   ├── chain.rs         # 证书链构建：CertChain, ChainCert, ChainPosition, 签名验证
│   ├── chain_cache.rs   # 链缓存：磁盘缓存下载的中间 CA 证书
│   ├── extensions.rs    # 17 种 X.509 扩展解析（SAN, SKI, AKI, BC, KU, EKU, CRL DP, AIA 等）
│   ├── format.rs        # 文件格式检测：detect_format(), is_pem_certificate()
│   └── error.rs         # CertError 枚举，Result<T> 别名
├── validation/
│   ├── mod.rs           # 验证模块入口
│   ├── chain.rs         # ChainValidator：基于系统信任根的链验证
│   ├── ocsp.rs          # OCSP 响应解析与吊销检查（基础框架，部分 mock）
│   ├── crl.rs           # CRL 解析与吊销检查（基础框架，部分 mock）
│   └── revocation.rs    # RevocationStatus 枚举
├── security/
│   ├── mod.rs           # 安全模块入口
│   ├── protected.rs     # ProtectedString：zeroize 保护的敏感字符串
│   └── sensitive.rs     # 敏感数据检测与分类，复制警告
├── generation/
│   ├── mod.rs           # 生成模块入口
│   ├── self_signed.rs   # 自签名证书生成：SelfSignedParams, GeneratedCert, KeyType
│   └── csr_gen.rs       # CSR 生成：CsrParams, GeneratedCsr
├── utils/
│   ├── mod.rs           # 工具函数入口：bytes_contains(), bytes_contains_any()
│   ├── base64.rs        # 十六进制/Base64 编解码工具
│   ├── oid.rs           # OID 注册表查询：describe_oid(), 全局 OID_REGISTRY
│   └── time.rs          # 时间格式化工具
├── ui/
│   ├── mod.rs           # UI 模块入口，导出 CertViewerApp
│   ├── app.rs           # 主应用状态：CertViewerApp 结构体，eframe::App 实现
│   ├── toolbar.rs       # 工具栏：打开文件、链视图切换、主题切换、生成按钮
│   ├── tab_bar.rs       # 标签栏：多文档标签管理、关闭、CSR 指示器
│   ├── details_view.rs  # 详情视图：证书字段树展示，有效性横幅
│   ├── chain_view.rs    # 链视图：证书链层级展示，签名状态
│   ├── diff_view.rs     # 对比视图：两个文档的字段差异对比
│   ├── field_tree.rs    # 字段树：递归可折叠 CertField 树渲染
│   ├── empty_state.rs   # 空状态：无文档时的引导界面
│   ├── generate_dialog.rs # 生成对话框：自签名证书/CSR 参数表单
│   └── password_dialog.rs # 密码对话框：PKCS#12 密码输入（预留）
└── assets/              # 测试用的证书和 CSR 固件文件
    ├── baidu.com.pem
    ├── github.com.pem
    ├── test.csr
    └── test_with_exts.csr

tests/
├── cli_tests.rs         # CLI 子命令集成测试
├── fixture_tests.rs     # 基于 fixtures 目录的证书加载测试
├── integration_tests.rs # 端到端集成测试
└── fixtures/            # 测试 fixtures（含 valid/ 和 invalid/ 子目录）

benches/
└── parsing.rs           # Criterion 基准测试（PEM/DER/CSR 解析、链构建、指纹）
```

## Feature Flags

| Feature | 作用 | 启用的依赖 |
|---------|------|-----------|
| `network` | 启用网络操作（OCSP 检查、CRL 下载、AIA 链补全） | `reqwest`（blocking）、`tokio`（rt） |
| `pkcs12` | 启用 PKCS#12 (.p12/.pfx) 和 CMS/PKCS#7 (.p7b) 格式解析 | `pkcs12` v0.2.0-pre.0 |
| `private-keys` | 启用私钥格式解析（PKCS#8、SEC1 EC、RSA PKCS#1） | `sec1`、`spki`、`pkcs8` |
| `full-formats` | 启用所有格式支持（`pkcs12` + `private-keys`） | 同上两者 |

**默认 features**: `["pkcs12", "private-keys", "network"]`

**最小化构建**: `cargo build --no-default-features`（仅支持 X.509 PEM/DER 证书和 CSR）

## 核心数据类型

### ParsedCert (`src/cert.rs`)

解析后的 X.509 证书，包含完整的字段树用于 UI 显示。

| 字段 | 类型 | 用途 |
|------|------|------|
| `id` | `CertId` | SHA-256 指纹的唯一标识符 |
| `display_name` | `String` | 显示名称（通常为 CN） |
| `serial_number` | `String` | 冒号分隔的十六进制序列号 |
| `sha256_fingerprint` | `String` | SHA-256 指纹（冒号分隔大写十六进制） |
| `sha1_fingerprint` | `String` | SHA-1 指纹 |
| `validity_status` | `ValidityStatus` | 当前有效性状态 |
| `not_before` | `String` | 生效时间（UTC 格式化） |
| `not_after` | `String` | 过期时间（UTC 格式化） |
| `issuer` | `String` | 颁发者 DN |
| `subject` | `String` | 主体 DN |
| `fields` | `Vec<CertField>` | 根级字段树 |
| `raw_der` | `Vec<u8>` | 原始 DER 字节（用于导出） |

方法: `to_pem() -> String`

### ParsedCsr (`src/formats/csr.rs`)

解析后的 PKCS#10 证书签名请求。

| 字段 | 类型 | 用途 |
|------|------|------|
| `id` | `CsrId` | SHA-256 指纹的唯一标识符 |
| `display_name` | `String` | 显示名称（CN） |
| `subject` | `String` | 主体 DN |
| `sha256_fingerprint` | `String` | SHA-256 指纹 |
| `sha1_fingerprint` | `String` | SHA-1 指纹 |
| `signature_algorithm` | `String` | 签名算法 |
| `fields` | `Vec<CertField>` | 根级字段树 |
| `raw_der` | `Vec<u8>` | 原始 DER 字节 |

方法: `to_pem() -> String`

### CertField (`src/cert.rs`)

证书字段树节点，UI 可递归渲染为可折叠层级。

| 字段 | 类型 | 用途 |
|------|------|------|
| `label` | `String` | 字段标签（如 "Subject", "Serial Number"） |
| `value` | `Option<String>` | 叶节点的值，容器节点为 `None` |
| `children` | `Vec<CertField>` | 子字段 |

构造器: `CertField::leaf(label, value)`, `CertField::container(label, children)`, `CertField::node(label, value, children)`

### Document (`src/document.rs`)

```rust
pub enum Document {
    Certificate(ParsedCert),
    Csr(ParsedCsr),
}
```

方法: `display_name()`, `fields()`, `id_str()`, `is_csr()`, `raw_der()`, `to_pem()`, `subject()`

### CertChain (`src/cert/chain.rs`)

| 字段 | 类型 | 用途 |
|------|------|------|
| `certificates` | `Vec<ChainCert>` | 从叶到根排序的证书链 |
| `validation_status` | `ChainValidationStatus` | 链验证状态 |
| `completion_error` | `Option<String>` | 链补全错误（仅 network feature） |

### ChainCert / ChainPosition / ChainValidationStatus / SignatureStatus

- `ChainPosition`: `Leaf`, `Intermediate { depth }`, `Root`
- `ChainValidationStatus`: `Valid`, `Incomplete { missing_count }`, `BrokenLinks`, `Empty`
- `SignatureStatus`: `Valid`, `Invalid`, `Unknown`

### CertId / CsrId

基于 SHA-256 的唯一标识符，结构体元组包装 `String`。实现了 `Display`, `Hash`, `Eq`。

### ValidityStatus

`Valid`, `NotYetValid`, `Expired`。通过 `ValidityStatus::check(not_before, not_after)` 计算。

### Config (`src/config.rs`)

```rust
pub struct Config {
    pub theme: String,        // "dark" 或 "light"
    pub window_width: f32,    // 默认 1024.0
    pub window_height: f32,   // 默认 768.0
}
```

持久化到 `<平台配置目录>/cer-viewer/config.json`。

### FileFormat (`src/cert/format.rs`)

`Pem`, `Der`, `Pkcs12`, `Cms`, `Unknown`

## 关键 API

### 证书解析

```rust
// 单个 PEM 证书
cert::parse_pem_certificate(pem_data: &[u8]) -> Result<ParsedCert>

// 多个 PEM 证书（链文件）
cert::parse_pem_certificates(pem_data: &[u8]) -> Vec<Result<ParsedCert>>

// 单个 DER 证书
cert::parse_der_certificate(der_data: &[u8]) -> Result<ParsedCert>

// 自动检测格式并解析
cert::parse_certificate(data: &[u8]) -> Result<ParsedCert>
cert::parse_certificates(data: &[u8]) -> Vec<Result<ParsedCert>>
```

### CSR 解析

```rust
formats::csr::parse_csr_pem(pem_data: &[u8]) -> Result<ParsedCsr>
formats::csr::parse_csr_der(der_data: &[u8]) -> Result<ParsedCsr>
formats::csr::parse_csrs(data: &[u8]) -> Vec<Result<ParsedCsr>>
formats::csr::is_pem_csr(data: &[u8]) -> bool
formats::csr::is_der_csr(data: &[u8]) -> bool
```

### 文档加载

```rust
// 统一加载入口，自动区分证书和 CSR
document::load_documents(data: &[u8]) -> Vec<std::result::Result<Document, String>>
```

### 链构建

```rust
// 从多个证书构建链（叶 -> 中间 -> 根）
CertChain::build(certs: Vec<ParsedCert>) -> CertChain

// 通过 AIA 扩展下载缺失的中间 CA（network feature）
CertChain::complete_chain(self) -> Self

// 提取 CA Issuers URL
CertChain::extract_ca_issuers_url(cert: &ParsedCert) -> Option<String>
```

### 链缓存

```rust
cert::chain_cache::ChainCache::new() -> ChainCache
chain_cache.lookup_by_subject(subject: &str) -> Vec<ParsedCert>
chain_cache.lookup_by_fingerprint(fingerprint: &str) -> Option<ParsedCert>
chain_cache.save(cert: &ParsedCert) -> Result<(), String>
chain_cache.cleanup(max_age_days: u64) -> Result<usize, String>
chain_cache.clear() -> Result<usize, String>
chain_cache.info() -> CacheInfo
```

### 导出

```rust
export::to_pem(label: &str, data: &[u8]) -> String
export::to_der(data: &[u8]) -> Vec<u8>
export::pem_to_der(pem_data: &[u8]) -> Result<Vec<u8>>
export::export_chain_as_pem(certs: &[ParsedCert]) -> String
```

### 证书/CSR 生成

```rust
generation::self_signed::generate_self_signed_cert(params: &SelfSignedParams) -> Result<GeneratedCert>
generation::csr_gen::generate_csr(params: &CsrParams) -> Result<GeneratedCsr>
```

### 配置持久化

```rust
config::Config::load() -> Config     // 磁盘加载，失败返回默认值
config::Config::save(&self)          // 保存到磁盘
```

### 格式检测

```rust
cert::format::detect_format(data: &[u8]) -> FileFormat
cert::format::is_pem_certificate(data: &[u8]) -> bool
cert::format::is_pem_private_key(data: &[u8]) -> bool
```

### 链验证

```rust
validation::chain::ChainValidator::with_system_trust() -> ChainValidator
chain_validator.validate(chain: &[Vec<u8>]) -> Result<ValidationResult>
// ValidationResult: Valid, Invalid(String), Unknown(String)
```

## CLI 接口

```
cer-viewer [OPTIONS] [FILES]... [COMMAND]

参数:
  [FILES]...              证书或 CSR 文件（PEM/DER），使用 "-" 从 stdin 读取
  -f, --format <FORMAT>   输出格式 [text|json|table]（默认: text）
  -c, --chain             以链视图显示多个证书
  --fields <FIELDS>       仅显示指定字段（逗号分隔）
  --no-color              禁用彩色输出

子命令:
  chain <FILES>...        显示证书链信息
  extract <FILE> <FIELD>  提取证书/CSR 的特定字段
    可用字段:
      证书: subject, issuer, serial, sha256, sha1, not_before, not_after, name, pem
      CSR: subject, sha256, sha1, signature, pem
  verify <FILES>...       验证证书有效性（时间有效性 + 链完整性）
  convert <INPUT> <OUTPUT> --to <FORMAT>
                          PEM <-> DER 格式转换
    --to pem|der          目标格式（默认: pem）
  fingerprint <FILES>...  显示 SHA-256 和 SHA-1 指纹
  cache <COMMAND>          管理本地证书链缓存
    list                  列出所有缓存条目
    clear                 清空缓存
    info                  显示缓存信息（大小、位置）
    cleanup [DAYS]        清理超过 N 天的缓存（默认: 30）
```

## UI 架构

### ViewMode 枚举 (`src/ui/app.rs`)

```rust
pub(crate) enum ViewMode {
    Details,  // 单证书详情视图
    Chain,    // 证书链视图
}
```

### UI 子模块职责

| 模块 | 文件 | 职责 |
|------|------|------|
| `app` | `app.rs` | `CertViewerApp` 主状态，`eframe::App` 实现，文件加载、标签管理、主题切换 |
| `toolbar` | `toolbar.rs` | 顶部工具栏：打开文件、链视图/详情切换、主题切换、生成证书/CSR、快捷键 |
| `tab_bar` | `tab_bar.rs` | 多文档标签栏：标签切换、关闭按钮、CSR 蓝色指示器、叶证书金色指示器 |
| `details_view` | `details_view.rs` | 证书详情面板：有效性横幅（绿/黄/红）、字段树、复制按钮 |
| `chain_view` | `chain_view.rs` | 证书链面板：层级展示叶/中间/根证书，签名验证状态 |
| `diff_view` | `diff_view.rs` | 两文档对比：字段差异以绿色/红色标注 |
| `field_tree` | `field_tree.rs` | 递归可折叠字段树：展开/折叠、复制值、敏感数据警告 |
| `empty_state` | `empty_state.rs` | 无文档时的欢迎界面：拖拽提示、快捷键说明 |
| `generate_dialog` | `generate_dialog.rs` | 生成对话框：自签名证书或 CSR 的参数表单（CN、SAN、密钥类型/大小、有效期） |
| `password_dialog` | `password_dialog.rs` | 密码输入对话框：PKCS#12 解密（预留功能） |

### CertViewerApp 关键状态字段

- `documents: Vec<Document>` -- 已加载的文档列表
- `doc_index: HashMap<String, usize>` -- ID -> 索引的去重映射
- `selected_tab: usize` -- 当前选中标签索引
- `view_mode: ViewMode` -- 当前视图模式
- `theme_mode: ThemeMode` -- 当前主题
- `clipboard: Option<arboard::Clipboard>` -- 剪贴板实例
- `recent_files: Vec<String>` -- 最近打开的文件列表（最多 10 个）
- `search_filter: String` -- 字段搜索过滤
- `completed_chain: Option<CertChain>` -- 已补全的证书链（network feature）
- `error_msgs: Vec<String>` -- 错误消息列表
- `info_msg: Option<String>` -- 信息提示

### 主题系统 (`src/theme.rs`)

- `ThemeMode`: `Dark`（默认）, `Light`
- 每个主题定义独立的颜色常量：`BG_PRIMARY`, `TEXT_PRIMARY`, `ACCENT`, `BORDER` 等
- 共享状态颜色：`STATUS_VALID`(绿), `STATUS_NOT_YET_VALID`(黄), `STATUS_EXPIRED`(红)
- 特殊指示器颜色：`LEAF_INDICATOR`(金), `CSR_INDICATOR`(蓝)
- 主题感知辅助函数：`bg_primary(mode)`, `text_primary(mode)`, `accent(mode)` 等
- 应用函数：`apply_theme(ctx, mode)`, `apply_dark_theme(ctx)`, `apply_light_theme(ctx)`
- 状态颜色/文本映射：`validity_color(status)`, `validity_text(status)`
- 字体常量：`FONT_TITLE`(18.0), `FONT_HEADING`(14.0), `FONT_BODY`(13.0), `FONT_MONO`(12.0)

## 代码规范

### 命名约定

- 类型名：`PascalCase`（`ParsedCert`, `CertField`, `CertChain`）
- 函数名：`snake_case`（`parse_pem_certificate`, `build_cert_tree`）
- 常量名：`UPPER_SNAKE_CASE`（`BG_PRIMARY`, `STATUS_VALID`, `FONT_BODY`）
- 模块内部不公开的函数/字段使用 `pub(crate)` 或私有
- CLI 子命令枚举：`PascalCase`（`Commands::Chain`, `Commands::Verify`）

### 错误处理模式

- 核心错误类型：`cert::CertError`（thiserror 派生）
- 错误变体：`PemParse(String)`, `DerParse(String)`, `FileRead { path, source }`, `Clipboard(String)`, `Validation(String)`, `UnsupportedFormat(String)`, `NoCertificate`
- 辅助构造器：`CertError::pem(msg)`, `CertError::der(msg)`, `CertError::parse(msg)`
- Result 别名：`cert::Result<T> = std::result::Result<T, CertError>`
- CLI 使用 `Result<bool, String>` 作为顶层错误，通过 `eprintln!` 报告
- 验证模块使用独立错误类型（`OcspError`, `CrlError`）

### 测试约定

- 测试固件位于 `assets/` 目录（`baidu.com.pem`, `github.com.pem`, `test.csr`, `test_with_exts.csr`）
- 集成测试 fixtures 位于 `tests/fixtures/certificates/` 目录（含 `valid/` 和 `invalid/` 子目录）
- 使用 `include_bytes!` 加载测试数据
- 测试命名：`test_<模块>_<场景>`（如 `test_parse_pem_certificate_success`, `test_chain_position_display`）
- 临时文件使用 `std::env::temp_dir()` 并在测试结束前清理
- 240 个测试（207 单元 + 13 集成 + 12 CLI + 8 fixture）
- 基准测试使用 `criterion`，位于 `benches/parsing.rs`

### 提交信息格式

参考最近提交：`Fix Chain View button visibility and enable CSR detection without pkcs12 feature`，`feat: add 'convert' CLI subcommand for PEM <-> DER format conversion`

## 构建与测试

```bash
# 默认构建（启用所有 features）
cargo build

# 最小化构建
cargo build --no-default-features

# 仅启用格式支持，无网络
cargo build --no-default-features --features full-formats

# 运行所有测试
cargo test --all-features

# 仅运行单元测试
cargo test --lib --all-features

# 仅运行集成测试
cargo test --tests --all-features

# 基准测试
cargo bench

# 检查（含 clippy）
cargo clippy --all-features -- -D warnings

# 格式检查
cargo fmt --check
```

### 发布构建配置

- `release` 配置：`opt-level=3`, `lto=true`, `codegen-units=1`, `strip=true`, `panic=abort`
- `release-small` 配置：`opt-level="s"`, `lto="fat"`, `strip=true`

## 已知限制与 TODO

1. **PKCS#12 完整解析依赖上游**：`pkcs12` crate (v0.2.0-pre.0) 为预发布版本，密码保护的 PKCS#12 文件尚不支持解密。当前仅能解析未加密的 PFX 结构。完整支持等待上游 crate 稳定。相关代码在 `src/formats/pkcs12.rs`。

2. **OCSP/CRL 为基础框架**：`src/validation/ocsp.rs` 和 `src/validation/crl.rs` 中的 `check_certificate()` 方法目前返回 mock 数据。实际的 OCSP 请求构造和 CRL 完整解析尚未实现。

3. **ASN.1 内容解析有限**：`src/formats/asn1.rs` 提供基本的 ASN.1 结构查看，但深度内容解码（如嵌套 SEQUENCE 内的 OID 查找）仍有限。

4. **密钥材料不存储**：`src/formats/keys.rs` 中的 `ParsedPrivateKey` 仅解析密钥元信息（类型、大小），不存储实际密钥材料，以防止意外泄漏。

5. **敏感数据保护**：`src/security/` 模块的 `ProtectedString` 实现了 `zeroize`，但当前并非所有敏感数据路径都使用该类型保护。

6. **GUI 线程模型**：证书链补全（`complete_chain()`）和网络请求使用 `std::sync::mpsc` 进行异步通信，但链补全下载发生在 UI 线程的消息检查中，可能阻塞 UI 响应。
