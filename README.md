# cer-viewer

一款基于 [egui](https://github.com/emilk/egui)/[eframe](https://github.com/emilk/egui/tree/master/crates/eframe) 构建的现代化 X.509 证书查看器，支持 GUI 图形界面与 CLI 命令行两种使用模式。

中文 | [English](README.en.md)

[![CI](https://github.com/AnlangA/cer-viewer/actions/workflows/ci.yml/badge.svg)](https://github.com/AnlangA/cer-viewer/actions)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Rust 1.80+](https://img.shields.io/badge/rust-1.80%2B-orange.svg)](https://www.rust-lang.org/)

## 功能特性

### 证书与 CSR 查看
- 支持 PEM（`.pem`、`.crt`）和 DER（`.cer`、`.der`）编码的 X.509 证书解析
- 支持 CSR（PKCS#10）文件（`.csr`、`.p10`），含扩展属性解析
- 可折叠的字段树展示所有证书详情：版本、序列号、签名算法、颁发者、主题、有效期、公钥信息、扩展项、签名值、指纹
- 支持 18 种 X.509 v3 扩展：SAN、Key Usage、Basic Constraints、EKU、AIA、CRL Distribution Points、Certificate Policies、SCT/CT、Name Constraints、Policy Mappings、Policy Constraints、Inhibit Any Policy、Subject Info Access、Issuer Alternative Name、NS Cert Type 等
- SHA-256 和 SHA-1 指纹计算与显示

### 证书链
- 自动构建从叶证书到根 CA 的证书链
- 通过 AIA CA Issuers 自动下载缺失的中间证书
- 密码学签名验证（需要 `network` feature）
- Issuer-Subject 链路验证与完整性检查
- 系统信任存储集成

### CLI 工具
- 查看证书和 CSR 的详细信息
- JSON 输出格式，支持脚本集成
- 子命令：`view`、`chain`、`extract`、`verify`、`convert`、`fingerprint`、`cache`
- 管道/Stdin 输入支持
- 彩色输出（可禁用）

### GUI 特性
- 深色/浅色主题切换，现代配色方案
- 多标签页支持，可同时打开多个证书和 CSR
- 可折叠的证书字段树
- 一键复制字段值到剪贴板
- 最近文件列表
- 证书对比视图
- 证书链可视化视图
- 证书生成对话框（自签名证书和 CSR）
- PKCS#12 密码输入对话框
- 敏感数据检测与安全警告

### 安全特性
- 敏感数据自动检测（私钥、密码、密钥材料等）
- 复制敏感数据时的安全警告
- `ProtectedString` 类型使用 `zeroize` 在内存中自动擦除敏感数据
- 支持密码保护的 PKCS#12 文件检测

### 证书生成工具
- 自签名证书生成（RSA 2048/3072/4096、EC P-256/P-384/P-521）
- CSR（证书签名请求）生成
- 支持 Subject Alternative Names（DNS 名称和 IP 地址）
- 支持 CA 证书生成
- 输出 PEM 和 DER 两种格式

## 截图

GUI 模式提供现代化的证书查看界面，包含工具栏、多标签页、可折叠字段树和证书链可视化。支持深色和浅色两种主题。

## 支持的格式

| 格式 | 扩展名 | 说明 | Feature |
|------|--------|------|---------|
| X.509 证书 (PEM) | `.pem`, `.crt` | Base64 编码，带 BEGIN/END 标记 | 默认 |
| X.509 证书 (DER) | `.cer`, `.der` | 二进制 ASN.1 编码 | 默认 |
| CSR / PKCS#10 | `.csr`, `.p10` | 证书签名请求 | 默认 |
| PKCS#12 / PFX | `.p12`, `.pfx` | 证书和私钥打包格式 | `pkcs12` |
| CMS / PKCS#7 | `.p7b`, `.p7c` | 签名数据（证书链） | `pkcs12` |
| 私钥 (PKCS#8) | `.key`, `.pem` | 通用私钥格式 | `private-keys` |
| 私钥 (EC/SEC1) | `.key`, `.pem` | EC 椭圆曲线私钥 | `private-keys` |
| 私钥 (RSA/PKCS#1) | `.key`, `.pem` | RSA 传统私钥格式 | `private-keys` |

## 安装

### 预编译二进制

预编译的二进制文件可在 [Releases 页面](https://github.com/AnlangA/cer-viewer/releases) 下载，支持以下平台：

- Windows (x86_64)
- macOS (Apple Silicon / Intel)
- Linux (x86_64)

### 从源码构建

**前置要求：** [Rust 工具链](https://rustup.rs/)（稳定版，最低 1.80）

```bash
git clone https://github.com/AnlangA/cer-viewer.git
cd cer-viewer
cargo build --release
```

编译产物位于 `target/release/cer-viewer`（Windows 上为 `cer-viewer.exe`）。

#### Feature Flags

```bash
# 默认构建（启用所有功能）
cargo build --release

# 最小化构建（不含网络和私钥解析）
cargo build --release --no-default-features

# 启用所有格式支持
cargo build --release --features full-formats

# 仅启用网络功能（OCSP/CRL）
cargo build --release --features network
```

| Feature | 说明 | 默认 |
|---------|------|------|
| `pkcs12` | PKCS#12 和 CMS/PKCS#7 解析 | 启用 |
| `private-keys` | 私钥解析（PKCS#8、EC、RSA） | 启用 |
| `network` | 网络操作（OCSP/CRL、链补全） | 启用 |
| `full-formats` | 所有格式支持（`pkcs12` + `private-keys`） | -- |

#### Linux 额外依赖

```bash
sudo apt-get install -y libgtk-3-dev libxcb-render0-dev libxcb-shape0-dev \
  libxcb-xfixes0-dev libx11-dev libxi-dev libgl1-mesa-dev
```

### 系统要求

- **Rust:** 1.80 或更高版本
- **平台:** Windows、macOS、Linux（需要 GTK3）

## 使用方法

### GUI 模式

直接运行二进制文件即可启动图形界面（不带参数或文件路径）：

```bash
cer-viewer
```

操作说明：
- 点击 **Open Files...** 按钮或使用快捷键打开文件对话框
- 支持拖放文件到窗口打开
- 支持同时打开多个文件，以标签页形式展示
- 点击字段树中的字段可复制其值到剪贴板
- 在标签页上右键可关闭其他标签或关闭右侧标签
- 点击工具栏中的主题图标可在深色和浅色主题间切换

### CLI 模式

提供文件路径即可进入 CLI 模式查看证书信息：

```bash
# 查看证书
cer-viewer certificate.pem

# 以 JSON 格式输出
cer-viewer --format json certificate.pem

# 以表格格式输出
cer-viewer --format table certificate.pem

# 只显示特定字段
cer-viewer --fields subject,issuer certificate.pem

# 查看多个证书并显示链信息
cer-viewer --chain leaf.crt intermediate.crt root.crt

# 从 stdin 读取
cat certificate.pem | cer-viewer -
```

#### 子命令

**view -- 查看证书/CSR**

```bash
cer-viewer certificate.pem
cer-viewer --format json certificate.pem
cer-viewer --fields subject,issuer,serial certificate.pem
cer-viewer --no-color certificate.pem
```

**chain -- 证书链分析**

```bash
# 分析证书链
cer-viewer chain leaf.crt intermediate.crt root.crt

# 以表格格式显示
cer-viewer chain --format table leaf.crt intermediate.crt root.crt

# 以 JSON 格式输出
cer-viewer chain --format json leaf.crt intermediate.crt root.crt
```

**extract -- 提取特定字段**

```bash
# 提取证书字段
cer-viewer extract certificate.pem subject
cer-viewer extract certificate.pem issuer
cer-viewer extract certificate.pem serial
cer-viewer extract certificate.pem sha256
cer-viewer extract certificate.pem sha1
cer-viewer extract certificate.pem not_before
cer-viewer extract certificate.pem not_after
cer-viewer extract certificate.pem name
cer-viewer extract certificate.pem pem

# 提取 CSR 字段
cer-viewer extract request.csr subject
cer-viewer extract request.csr signature
cer-viewer extract request.csr fingerprint
```

**verify -- 验证证书**

```bash
# 验证单个证书
cer-viewer verify certificate.pem

# 验证证书链
cer-viewer verify leaf.crt intermediate.crt root.crt
```

**convert -- 格式转换**

```bash
# PEM 转 DER
cer-viewer convert input.pem output.der --to der

# DER 转 PEM
cer-viewer convert input.der output.pem --to pem
```

**fingerprint -- 显示指纹**

```bash
# 显示 SHA-256 和 SHA-1 指纹
cer-viewer fingerprint certificate.pem

# 显示多个证书的指纹
cer-viewer fingerprint cert1.pem cert2.pem
```

**cache -- 缓存管理**

```bash
# 查看缓存信息
cer-viewer cache info

# 列出所有缓存条目
cer-viewer cache list

# 清理超过 30 天的缓存
cer-viewer cache cleanup --days 30

# 清空所有缓存
cer-viewer cache clear
```

#### 输出格式

| 格式 | 说明 |
|------|------|
| `text` | 人类可读文本格式（默认） |
| `json` | JSON 格式，适合脚本处理 |
| `table` | 对齐表格格式（使用 comfy-table） |

#### 管道与 Stdin

所有接受文件路径的命令均支持使用 `-` 从 stdin 读取数据：

```bash
cat certificate.pem | cer-viewer -
cat certificate.pem | cer-viewer extract - subject
cat certificate.pem | cer-viewer --format json -
```

`colored` 库会自动检测输出是否被管道重定向并相应地禁用彩色输出。你也可以使用 `--no-color` 全局选项强制禁用彩色。

## 快捷键

| 快捷键 | 功能 |
|--------|------|
| `Cmd/Ctrl + O` | 打开文件对话框 |
| `Cmd/Ctrl + W` | 关闭当前标签页 |

## 配置

配置文件自动保存到系统标准配置目录：

- **Linux:** `~/.config/cer-viewer/config.json`
- **macOS:** `~/Library/Application Support/cer-viewer/config.json`
- **Windows:** `C:\Users\<用户>\AppData\Roaming\cer-viewer\config.json`

支持的配置项：

```json
{
  "theme": "dark",
  "window_width": 1024.0,
  "window_height": 768.0
}
```

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `theme` | string | `"dark"` | 主题模式：`dark` 或 `light` |
| `window_width` | float | `1024.0` | 窗口宽度（像素） |
| `window_height` | float | `768.0` | 窗口高度（像素） |

## 证书链缓存

当 `network` feature 启用时，证书链补全功能会自动将下载的证书缓存到本地磁盘，避免重复的网络请求。

缓存机制：
- 按 Subject DN 和 SHA-256 指纹建立双索引
- 缓存内容包含证书的 DER 编码数据
- 使用系统标准缓存目录存储

缓存位置：
- **Linux:** `~/.cache/cer-viewer/`
- **macOS:** `~/Library/Caches/cer-viewer/`
- **Windows:** `C:\Users\<用户>\AppData\Local\cache\cer-viewer\`

通过 CLI 管理缓存：

```bash
cer-viewer cache info     # 查看缓存信息
cer-viewer cache list     # 列出缓存条目
cer-viewer cache cleanup  # 清理过期缓存
cer-viewer cache clear    # 清空所有缓存
```

## 开发

### 项目结构

```
cer-viewer/
├── src/
│   ├── main.rs            # 应用入口
│   ├── lib.rs             # 库入口（测试和 fuzzing）
│   ├── cli.rs             # CLI 命令行接口
│   ├── config.rs          # 配置持久化
│   ├── theme.rs           # 深色/浅色主题定义
│   ├── cert.rs            # 证书解析与字段树构建
│   ├── cert/
│   │   ├── chain.rs       # 证书链构建与验证
│   │   ├── chain_cache.rs # 证书链本地缓存
│   │   ├── extensions.rs  # X.509 扩展解析
│   │   ├── format.rs      # 格式检测
│   │   └── error.rs       # 错误类型定义
│   ├── document.rs        # 统一文档模型（证书/CSR）
│   ├── formats/
│   │   ├── mod.rs         # 格式模块入口
│   │   ├── x509.rs        # X.509 格式处理
│   │   ├── csr.rs         # CSR/PKCS#10 解析
│   │   ├── pkcs12.rs      # PKCS#12 解析
│   │   ├── cms.rs         # CMS/PKCS#7 解析
│   │   ├── keys.rs        # 私钥解析
│   │   └── asn1.rs        # ASN.1 工具
│   ├── export/
│   │   └── mod.rs         # PEM/DER 导出与转换
│   ├── generation/
│   │   ├── mod.rs         # 证书生成模块入口
│   │   ├── self_signed.rs # 自签名证书生成
│   │   └── csr_gen.rs     # CSR 生成
│   ├── validation/
│   │   ├── mod.rs         # 验证模块入口
│   │   ├── chain.rs       # 链验证
│   │   ├── ocsp.rs        # OCSP 检查
│   │   ├── crl.rs         # CRL 检查
│   │   └── revocation.rs  # 吊销状态检查
│   ├── security/
│   │   ├── mod.rs         # 安全模块入口
│   │   ├── protected.rs   # ProtectedString（自动擦除）
│   │   └── sensitive.rs   # 敏感数据检测
│   ├── ui/
│   │   ├── mod.rs         # UI 模块入口
│   │   ├── app.rs         # 主应用状态与逻辑
│   │   ├── toolbar.rs     # 工具栏与标签页
│   │   ├── tab_bar.rs     # 标签页管理
│   │   ├── details_view.rs # 证书详情视图
│   │   ├── field_tree.rs  # 可折叠字段树
│   │   ├── chain_view.rs  # 证书链视图
│   │   ├── diff_view.rs   # 证书对比视图
│   │   ├── generate_dialog.rs  # 证书生成对话框
│   │   ├── password_dialog.rs  # 密码输入对话框
│   │   └── empty_state.rs # 空状态提示
│   └── utils/
│       └── mod.rs         # 通用工具函数
├── tests/
│   ├── cli_tests.rs       # CLI 集成测试
│   ├── fixture_tests.rs   # 固件测试
│   └── integration_tests.rs # 集成测试
├── benches/
│   └── parsing.rs         # Criterion 基准测试
├── assets/                # 测试用证书和 CSR 文件
└── .github/workflows/
    └── ci.yml             # CI 配置
```

### 构建与测试

```bash
# 构建
cargo build

# 运行测试
cargo test

# 运行所有 feature 的测试
cargo test --all-features

# 运行测试（不含 network feature）
cargo test

# 代码格式检查
cargo fmt --all -- --check

# 代码格式化
cargo fmt --all

# Clippy 静态分析
cargo clippy --all-targets --all-features -- -D warnings

# 基准测试
cargo bench
```

CI 流水线在每次提交时自动运行格式检查、Clippy、测试（含所有 feature 和不含 network feature），并生成代码覆盖率报告。

### 代码规范

详细的贡献指南请参阅 [CONTRIBUTING.md](CONTRIBUTING.md)，版本变更记录请参阅 [CHANGELOG.md](CHANGELOG.md)。

## 许可证

本项目采用双重许可：

- [MIT License](LICENSE)
- [Apache License 2.0](LICENSE-APACHE)
