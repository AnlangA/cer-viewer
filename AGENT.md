# cer-viewer 项目文档

## 项目概述

cer-viewer 是一个使用 egui/eframe 构建的现代化 X.509 证书查看器，使用 Rust 编写。项目支持多种证书和密钥格式的解析、查看和验证，具有图形界面和命令行两种使用模式。

**项目状态**: 🟢 核心功能已完成，11/17 主要任务完成

**技术栈**: Rust, egui/eframe, x509-parser, clap, serde

---

## 一、当前功能状态

### 1.1 已支持的格式

| 格式 | 扩展名 | 状态 | 使用的库 |
|------|--------|------|----------|
| X.509 PEM | `.pem`, `.crt` | ✅ 完全支持 | `x509-parser` 0.18.1 |
| X.509 DER | `.cer`, `.der` | ✅ 完全支持 | `x509-parser` 0.18.1 |
| PKCS#12 | `.p12`, `.pfx` | ⚠️ 基础支持 | `pkcs12` 0.2.0-pre.0 |
| PKCS#7/CMS | `.p7b`, `.p7c` | ✅ 完全支持 | 内置解析器 |
| PKCS#8 私钥 | `.key`, `.p8` | ✅ 完全支持 | `pkcs8`, `sec1`, `spki` |
| CSR (PKCS#10) | `.csr` | ✅ 完全支持 | 内置解析器 |
| CRL | `.crl` | ✅ 完全支持 | 内置解析器 |
| OCSP 响应 | `.der` | ✅ 解析支持 | 内置解析器 |
| SEC1 EC 私钥 | `.key` | ✅ 完全支持 | `sec1` 0.8 |

### 1.2 已实现的功能

#### 证书解析与显示
- ✅ PEM 和 DER 格式自动检测
- ✅ 多证书 PEM 文件支持（证书链）
- ✅ 完整的 X.509 v3 字段解析
- ✅ 证书有效性检查（Not Before / Not After）
- ✅ SHA-256 和 SHA-1 指纹计算

#### 私钥支持
- ✅ PKCS#8 格式私钥解析
- ✅ SEC1 EC 私钥解析
- ✅ 密钥类型识别（RSA, EC, DSA）
- ✅ 曲线名称提取（P-256, P-384, P-521, secp256k1）
- ✅ 加密私钥检测

#### CSR 支持
- ✅ PKCS#10 CSR 解析
- ✅ Subject DN 提取
- ✅ 公钥算法检测
- ✅ 签名算法和签名值提取

#### PKCS#7/CMS 支持
- ✅ CMS 格式检测
- ✅ SignedData 解析
- ✅ 从 CMS 提取证书

#### 证书链功能
- ✅ 自动证书链构建
- ✅ 链位置识别（Leaf, Intermediate, Root）
- ✅ 链验证状态显示
- ✅ 树形视图可视化

#### OCSP/CRL 功能
- ✅ OCSP 响应解析
- ✅ CRL 解析（PEM/DER）
- ✅ 证书吊销状态检查
- ✅ CRL URL 提取
- ✅ 网络下载支持（需 `network` feature）

#### ASN.1 查看器
- ✅ DER 字节级解析
- ✅ 标签类别识别
- ✅ 通用标签类型（SEQUENCE, INTEGER, NULL 等）
- ✅ OID 解析和描述
- ✅ 递归嵌套结构解析

#### CLI 模式
- ✅ 证书信息查看
- ✅ 证书链显示
- ✅ JSON 输出格式
- ✅ 字段过滤
- ✅ 子命令支持（chain, extract, verify）

#### 安全功能
- ✅ 敏感数据检测（私钥、密码）
- ✅ 复制敏感数据警告
- ✅ 审计日志输出

#### UI 功能
- ✅ 多标签页证书查看
- ✅ 可折叠字段树
- ✅ 深色主题
- ✅ 拖放支持
- ✅ 复制到剪贴板
- ✅ 中文支持（Noto Sans SC 字体）
- ✅ 视图模式切换（详情/链视图）

### 1.3 当前依赖版本

```toml
# UI 框架
eframe = "0.33.3"
egui = "0.33.3"

# 证书解析
x509-parser = "0.18.1"
pem = "3.0.6"

# ASN.1 和 DER 解析
der = { version = "0.8", features = ["alloc", "oid"] }
pkcs12 = { version = "0.2.0-pre.0" }

# 私钥支持
sec1 = "0.8"
spki = { version = "0.8.0-rc.4" }
pkcs8 = { version = "0.11.0-rc.11" }

# 网络功能（可选）
reqwest = { version = "0.12", features = ["blocking"], optional = true }
tokio = { version = "1.35", features = ["rt"], optional = true }
url = "2.5"

# 工具库
hex = "0.4.3"
chrono = "0.4.44"
oid-registry = { version = "0.8.1", features = ["crypto", "x509", "x962"] }
sha1 = "0.10.6"
sha2 = "0.10.8"
base64 = "0.22"

# CLI 和序列化
clap = { version = "4.5", features = ["derive"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

# 安全
zeroize = "1.8"
secrecy = { version = "0.10", features = ["serde"] }

# 日志
tracing = "0.1.44"
tracing-subscriber = { version = "0.3.23", features = ["fmt", "std"] }
```

---

## 二、项目结构

### 2.1 模块结构

```
src/
├── main.rs                 # 应用入口
├── lib.rs                  # 库入口（测试/模糊测试）
├── cli.rs                  # CLI 模式实现
├── ui.rs                   # UI 主逻辑
├── theme.rs                # 主题定义
│
├── cert/                   # 证书处理模块
│   ├── mod.rs
│   ├── error.rs           # 错误类型
│   ├── format.rs          # 格式检测
│   ├── extensions.rs      # 扩展解析
│   └── chain.rs           # 证书链构建
│
├── formats/                # 格式解析器
│   ├── mod.rs
│   ├── asn1.rs           # ASN.1 原始解析
│   ├── cms.rs            # PKCS#7/CMS 解析
│   ├── csr.rs            # CSR 解析
│   ├── keys.rs           # 私钥解析
│   └── pkcs12.rs         # PKCS#12 解析
│
├── validation/             # 证书验证
│   ├── mod.rs
│   ├── chain.rs          # 链验证
│   ├── revocation.rs     # 吊销检查
│   ├── ocsp.rs           # OCSP 处理
│   └── crl.rs            # CRL 处理
│
├── security/               # 安全相关
│   ├── mod.rs
│   ├── protected.rs      # 受保护类型
│   └── sensitive.rs      # 敏感数据检测
│
├── export/                 # 导出功能
│   └── mod.rs
│
└── utils/                  # 工具函数
    ├── mod.rs
    ├── base64.rs         # Base64 工具
    ├── oid.rs            # OID 助手
    └── time.rs           # 时间处理
```

### 2.2 测试结构

```
tests/
├── integration_tests.rs   # 集成测试
└── fixtures/              # 测试数据
    └── README.md          # Fixtures 说明

fuzz/                      # 模糊测试
├── Cargo.toml
├── README.md
└── fuzz_targets/
    ├── certificate_parsing.rs
    ├── asn1_parsing.rs
    └── crl_parsing.rs

.github/workflows/         # CI 配置
└── ci.yml                 # GitHub Actions
```

---

## 三、已完成的任务

### 阶段 0: 架构重构和依赖升级 ✅
- 升级核心依赖到最新版本
- 创建新的模块结构
- 添加新依赖 (zeroize, secrecy, der, sec1, spki, pkcs8)
- 改进错误处理

### 阶段 0.5: 安全性增强 ✅
- 集成 zeroize 和 secrecy
- 保护敏感数据
- 审计日志输出
- 添加私钥复制警告

### 阶段 1: PKCS#12 支持 ⚠️
- 添加 pkcs12 crate
- 实现 PKCS#12 格式检测
- 测试用例
- 完整解析等待底层 crate 成熟

### 阶段 2: PKCS#7/CMS 支持 ✅
- 添加 CMS 解析器
- 实现 CMS 格式检测
- 从 SignedData 提取证书
- 测试用例

### 阶段 3: 私钥支持 ✅
- 实现 PKCS#8 格式支持
- 实现 SEC1 EC 私钥支持
- 检测加密私钥
- 密钥类型和大小识别

### 阶段 4: CSR 支持 ✅
- 实现 CSR 解析器 (PKCS#10)
- 格式检测函数
- Subject DN 提取
- 签名算法检测

### 阶段 5: OCSP/CRL 支持 ✅
- OCSP 响应解析
- CRL 解析（PEM/DER）
- 在线验证支持
- URL 提取功能

### 阶段 6: 证书链可视化 ✅
- 树形视图
- 验证状态显示
- 位置指示器

### 阶段 7: ASN.1 查看器 ✅
- DER 字节级解析
- OID 解析
- 递归嵌套解析

### 阶段 8: 测试基础设施 ✅
- 测试 fixtures 目录
- 模糊测试配置
- CI/CD 设置
- 集成测试

### 阶段 9: CLI 模式 ✅
- clap 集成
- 命令实现（chain, extract, verify）
- JSON 输出

---

## 四、待完成的功能

### 高优先级

1. **PKCS#12 完整支持**
   - 等待 `pkcs12` crate 成熟
   - 密码输入对话框 UI
   - 完整的证书和私钥提取

2. **证书验证**
   - 完整的链验证逻辑
   - 签名验证
   - 信任存储集成

### 中优先级

3. **格式转换**
   - PEM ↔ DER 转换
   - PKCS#12 导出
   - 批量转换

4. **证书比较**
   - 并排比较
   - 差异高亮

5. **密钥对生成**
   - RSA 密钥生成
   - EC 密钥生成
   - 自签名证书生成

### 低优先级

6. **CT Log 支持**
   - SCT 解析和验证
   - CT Log 查询

7. **多语言支持**
   - i18n 框架
   - 翻译文件

8. **配置管理**
   - 用户设置持久化
   - 配置文件

---

## 五、测试状态

### 测试覆盖

```
总测试数: 136
├── 单元测试: 128
└── 集成测试: 8
```

### 测试类别

- ✅ 格式检测测试
- ✅ 证书解析测试
- ✅ 私钥解析测试
- ✅ CSR 解析测试
- ✅ CMS 解析测试
- ✅ PKCS#12 检测测试
- ✅ ASN.1 解析测试
- ✅ 证书链构建测试
- ✅ OCSP/CRL 测试
- ✅ 安全功能测试
- ✅ CLI 测试
- ✅ 集成测试

### 模糊测试

- certificate_parsing - 证书解析
- asn1_parsing - ASN.1 解析
- crl_parsing - CRL 解析

### CI/CD

- 多平台测试 (Ubuntu, Windows, macOS)
- Rust 版本测试 (stable, beta)
- Fmt 和 Clippy 检查
- 安全审计
- Release 构建

---

## 六、构建和运行

### 构建

```bash
# 标准构建
cargo build --release

# 带网络功能
cargo build --release --features network
```

### 运行

```bash
# GUI 模式
cargo run

# CLI 模式
cargo run -- --help
cargo run -- file.pem
cargo run -- --chain file.pem
cargo run -- --format json file.pem
cargo run -- extract file.pem subject
cargo run -- verify file.pem
```

### 测试

```bash
# 所有测试
cargo test

# 集成测试
cargo test --test integration_tests

# 模糊测试
cargo fuzz run certificate_parsing
```

---

## 七、安全性

### 已实现的安全措施

1. **敏感数据保护**
   - `zeroize` 用于敏感数据清零
   - `secrecy` 用于秘密类型保护
   - 私钥复制警告

2. **审计日志**
   - 敏感操作日志记录
   - WARN 级别敏感事件

3. **内存安全**
   - Rust 内存安全保证
   - 避免缓冲区溢出
   - 类型安全

### 安全最佳实践

- ✅ 不记录敏感数据到日志
- ✅ 私钥不自动复制
- ✅ 密码不存储
- ✅ 临时文件安全处理

---

## 八、贡献指南

### 开发环境

1. Rust 1.80+
2. 推荐使用 VS Code + rust-analyzer
3. 运行 `cargo test` 确保测试通过
4. 运行 `cargo fmt` 格式化代码
5. 运行 `cargo clippy` 检查代码质量

### 代码风格

- 使用 `rustfmt` 默认配置
- 遵循 Rust API 指南
- 添加文档注释
- 编写测试用例

### 提交规范

```
类型(范围): 简短描述

详细描述

类型: feat, fix, docs, style, refactor, test, chore
```

---

## 九、许可证

MIT OR Apache-2.0

---

## 十、联系方式

- GitHub: https://github.com/your-org/cer-viewer
- Issues: https://github.com/your-org/cer-viewer/issues

---

*文档更新时间: 2025-03-18*
