# cer-viewer

一款基于 Rust 编写的现代化 X.509 证书与 CSR 查看器，基于 [egui](https://github.com/emilk/egui)/[eframe](https://github.com/emilk/egui/tree/master/crates/eframe) 构建 GUI，同时提供功能完整的 CLI 模式。

中文 | [English](README.en.md)

[![CI](https://github.com/AnlangA/cer-viewer/actions/workflows/ci.yml/badge.svg)](https://github.com/AnlangA/cer-viewer/actions)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Rust 1.80+](https://img.shields.io/badge/rust-1.80%2B-orange.svg)](https://www.rust-lang.org/)

## 功能特性

### 证书与 CSR 查看

- 支持 PEM（`.pem`、`.crt`）和 DER（`.cer`、`.der`）编码的 X.509 证书
- 支持 CSR（PKCS#10）文件（`.csr`、`.p10`），含扩展属性解析
- 可折叠字段树展示所有证书详情：版本、序列号、签名算法、颁发者、主题、有效期、公钥信息、扩展项、签名值、指纹
- 支持 18 种 X.509 v3 扩展：SAN、Key Usage、Basic Constraints、EKU、AIA、CRL Distribution Points、Certificate Policies、SCT/CT、Name Constraints、Policy Mappings、Policy Constraints、Inhibit Any Policy、Subject Info Access、Issuer Alternative Name、NS Cert Type 等
- SHA-256 与 SHA-1 指纹计算与显示

### 证书链

- 自动构建从叶证书到根 CA 的证书链
- 通过 AIA CA Issuers 自动下载缺失的中间证书（`network` feature）
- 密码学签名验证
- Issuer-Subject 链路验证与完整性检查
- 系统信任存储集成

### CLI 工具

- 查看证书与 CSR 的详细信息
- 子命令：`chain`、`extract`、`verify`、`convert`、`fingerprint`、`cache`
- 支持 `text`、`json`、`table` 三种输出格式
- 支持管道/stdin 输入
- 彩色输出（可禁用）

### GUI 特性

- 深色/浅色主题切换
- 多标签页同时打开多个证书与 CSR
- 可折叠证书字段树，一键复制字段值
- 证书对比视图与证书链可视化
- 证书生成对话框（自签名证书与 CSR）
- PKCS#12 密码输入对话框
- 敏感数据检测与安全警告

### 安全特性

- 敏感数据自动检测（私钥、密码、密钥材料）
- 复制敏感数据时的安全警告
- `ProtectedString` 类型使用 `zeroize` 自动擦除内存
- 密码保护 PKCS#12 文件检测

### 证书生成

- 自签名证书生成（RSA 2048/3072/4096、EC P-256/P-384/P-521）
- CSR（证书签名请求）生成
- Subject Alternative Names 支持（DNS 名称与 IP 地址）
- CA 证书生成
- PEM 与 DER 输出格式

## 支持的格式

| 格式 | 扩展名 | 说明 | Feature |
|------|--------|------|---------|
| X.509 证书 (PEM) | `.pem`, `.crt` | Base64 编码 | 默认 |
| X.509 证书 (DER) | `.cer`, `.der` | 二进制 ASN.1 编码 | 默认 |
| CSR / PKCS#10 | `.csr`, `.p10` | 证书签名请求 | 默认 |
| PKCS#12 / PFX | `.p12`, `.pfx` | 证书和私钥打包格式 | `pkcs12` |
| CMS / PKCS#7 | `.p7b`, `.p7c` | 签名数据（证书链） | `pkcs12` |
| 私钥 (PKCS#8) | `.key`, `.pem` | 通用私钥格式 | `private-keys` |
| 私钥 (EC/SEC1) | `.key`, `.pem` | EC 椭圆曲线私钥 | `private-keys` |
| 私钥 (RSA/PKCS#1) | `.key`, `.pem` | RSA 传统私钥格式 | `private-keys` |

## 安装

### 预编译二进制

预编译二进制可在 [Releases](https://github.com/AnlangA/cer-viewer/releases) 下载：

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

编译产物位于 `target/release/cer-viewer`。

#### Feature Flags

```bash
cargo build --release                              # 默认构建（启用所有功能）
cargo build --release --no-default-features        # 最小化构建
cargo build --release --features full-formats      # 所有格式支持
cargo build --release --features network           # 仅启用网络功能
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

## 使用方法

### GUI 模式

```bash
cer-viewer
```

- 拖放文件到窗口打开，支持多文件同时打开
- 点击字段树中的字段可复制值到剪贴板
- 右键标签页可关闭其他标签或关闭右侧标签
- 工具栏主题图标切换深色/浅色主题

### CLI 模式

```bash
# 查看证书
cer-viewer certificate.pem

# JSON / 表格格式输出
cer-viewer --format json certificate.pem
cer-viewer --format table certificate.pem

# 仅显示特定字段
cer-viewer --fields subject,issuer certificate.pem

# 证书链查看
cer-viewer --chain leaf.crt intermediate.crt root.crt

# 从 stdin 读取
cat certificate.pem | cer-viewer -
```

#### 子命令

**chain** -- 证书链分析

```bash
cer-viewer chain leaf.crt intermediate.crt root.crt
cer-viewer chain --format json leaf.crt intermediate.crt root.crt
```

**extract** -- 提取特定字段

```bash
cer-viewer extract certificate.pem subject      # 证书字段
cer-viewer extract certificate.pem serial
cer-viewer extract certificate.pem sha256
cer-viewer extract certificate.pem pem
cer-viewer extract request.csr subject          # CSR 字段
cer-viewer extract request.csr signature
```

**verify** -- 验证证书

```bash
cer-viewer verify certificate.pem
cer-viewer verify --trust-store ca-bundle.crt certificate.pem
cer-viewer verify --hostname example.com certificate.pem
```

**convert** -- 格式转换

```bash
cer-viewer convert input.pem output.der --to der
cer-viewer convert input.der output.pem --to pem
```

**fingerprint** -- 显示指纹

```bash
cer-viewer fingerprint certificate.pem
cer-viewer fingerprint cert1.pem cert2.pem
```

**cache** -- 缓存管理

```bash
cer-viewer cache info                            # 查看缓存信息
cer-viewer cache list                            # 列出缓存条目
cer-viewer cache cleanup --days 30               # 清理过期缓存
cer-viewer cache clear                           # 清空所有缓存
```

## 快捷键

| 快捷键 | 功能 |
|--------|------|
| `Cmd/Ctrl + O` | 打开文件对话框 |
| `Cmd/Ctrl + W` | 关闭当前标签页 |

## 配置

配置文件自动保存到系统标准配置目录：

- **Linux:** `~/.config/cer-viewer/config.json`
- **macOS:** `~/Library/Application Support/cer-viewer/config.json`
- **Windows:** `C:\Users\<user>\AppData\Roaming\cer-viewer\config.json`

```json
{
  "theme": "dark",
  "window_width": 1024.0,
  "window_height": 768.0
}
```

## 开发

详细的开发者指南请参阅 [AGENTS.md](AGENTS.md)。

```bash
cargo build                                      # 构建
cargo test --all-features                        # 运行测试
cargo fmt --all -- --check                       # 格式检查
cargo clippy --all-targets --all-features -- -D warnings  # Clippy 检查
cargo bench                                      # 基准测试
```

## 许可证

- [MIT License](LICENSE)
- [Apache License 2.0](LICENSE-APACHE)
