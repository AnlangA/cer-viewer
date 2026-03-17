# cer-viewer 实施计划追踪

## 状态概览

- 开始时间: 2025-03-17
- 当前迭代: 1
- 完成任务: 6 / 17

## 任务清单

### 阶段 0: 架构重构和依赖升级 (M0)
- [x] **Task #4**: 架构重构和依赖升级 ✅ **已完成**
  - [x] 升级核心依赖到最新版本
  - [x] 创建新的模块结构 (formats/, ui/, validation/, utils/)
  - [x] 添加新依赖 (zeroize, secrecy, der, sec1, spki, pkcs8)
  - [x] 改进错误处理
  - [x] 所有测试通过

### 阶段 0.5: 安全性增强
- [x] **Task #6**: 安全增强 ✅ **已完成**
  - [x] 集成 zeroize 和 secrecy
  - [x] 保护敏感数据
  - [x] 审计日志输出
  - [x] 添加私钥复制警告

### 阶段 1: PKCS#12 支持 (M1)
- [x] **Task #5**: PKCS#12 基础支持 ⚠️ **部分完成**
  - [x] 添加 pkcs12 crate
  - [x] 实现 PKCS#12 格式检测
  - [ ] 实现 PKCS#12 完整解析 (等待 pkcs12 crate 成熟)
  - [ ] 密码输入对话框
  - [x] 测试用例

### 阶段 2: PKCS#7/CMS 支持 (M1)
- [x] **Task #1**: PKCS#7/CMS 支持 ✅ **已完成**
  - [x] 添加 cms crate (通过 pkcs12 依赖)
  - [x] 实现 CMS 解析器
  - [x] 格式检测集成
  - [x] 测试用例

### 阶段 3: 私钥支持 (M2)
- [x] **Task #2**: 私钥查看 ✅ **已完成**
  - [x] 添加 sec1 和 spki crates (已在 M0 添加)
  - [x] 实现私钥解析器
  - [x] 格式检测函数
  - [x] 测试用例

### 阶段 4: CSR 支持 (M3)
- [x] **Task #3**: CSR 支持 ✅ **已完成**
  - [x] 实现 CSR 解析器 (PKCS#10)
  - [x] 格式检测函数
  - [x] 测试用例

### 阶段 5: CRL 和 OCSP (M4)
- [ ] **Task #10**: 网络功能 - OCSP/CRL
  - [ ] OCSP 响应解析
  - [ ] CRL 下载
  - [ ] 在线验证

### 阶段 6: UI 增强
- [ ] **Task #7**: 证书链可视化
  - [ ] 树形视图
  - [ ] 验证状态显示

### 阶段 7: ASN.1 查看器 (M6)
- [ ] **Task #9**: ASN.1 结构查看器
  - [ ] DER 字节级解析
  - [ ] OID 解析

### 阶段 8: 测试基础设施
- [ ] **Task #11**: 测试基础设施
  - [ ] 测试 fixtures
  - [ ] 模糊测试配置
  - [ ] CI 设置

### 阶段 9: CLI 模式 (M10)
- [ ] **Task #8**: CLI 模式
  - [ ] clap 集成
  - [ ] 命令实现

## 完成记录

### ✅ Task #4: 架构重构和依赖升级 (2025-03-17)
**完成内容：**
1. **依赖更新**
   - zeroize = "1.8" - 敏感数据清零
   - secrecy = "0.10" - 秘密类型保护
   - der = "0.8" - ASN.1 DER 解析
   - sec1 = "0.8" - EC 私钥
   - spki = "0.8.0-rc.4" - 公钥信息
   - pkcs8 = "0.11.0-rc.11" - PKCS#8 私钥
   - serde = "1.0" - 序列化支持

2. **新模块结构**
   ```
   src/
   ├── formats/          # 格式解析器
   │   ├── mod.rs
   │   ├── x509.rs        # X.509 证书
   │   └── asn1.rs       # ASN.1 原始解析
   ├── validation/       # 证书验证
   │   ├── mod.rs
   │   ├── chain.rs       # 链验证
   │   └── revocation.rs  # 吊销检查
   ├── security/         # 安全相关
   │   ├── mod.rs
   │   └── protected.rs   # 受保护类型
   ├── export/           # 导出和转换
   │   └── mod.rs
   ├── utils/            # 工具函数
   │   ├── mod.rs
   │   ├── oid.rs         # OID 助手
   │   ├── time.rs        # 时间处理
   │   └── base64.rs      # Base64 工具
   └── cert/format.rs    # 格式检测
   ```

3. **测试结果**
   - 53 个测试全部通过 ✅
   - 包括新增模块的单元测试
   - 现有功能测试保持通过

### ✅ Task #6: 安全增强 (2025-03-17)
**完成内容：**
1. **敏感数据检测模块** (src/security/sensitive.rs)
   - `is_potentially_sensitive()` - 检测敏感数据模式
   - `SensitiveDataType` 枚举 - 分类敏感数据类型 (PrivateKey, Password, Secret, Unknown)
   - `sensitive_copy_warning()` - 生成警告消息

2. **UI 安全增强**
   - 复制操作前自动检测敏感数据
   - 复制敏感数据时显示警告消息
   - 上下文菜单中标记敏感数据
   - 日志中记录敏感数据复制事件 (WARN 级别)

3. **测试结果**
   - 7 个新测试全部通过 ✅
   - 总计 60 个测试通过

### ⚠️ Task #5: PKCS#12 基础支持 (2025-03-17)
**完成内容：**
1. **PKCS#12 crate 添加**
   - pkcs12 = "0.2.0-pre.0"

2. **PKCS#12 模块** (src/formats/pkcs12.rs)
   - `ParsedPkcs12` 结构体 - 解析后的 PKCS#12 数据
   - `is_pkcs12()` - 检测 PKCS#12 格式
   - `requires_password()` - 检查是否需要密码
   - 格式检测集成到 cert/format.rs

3. **限制说明**
   - 底层 pkcs12 crate 尚未实现高级解密 API
   - 完整的密码保护 PKCS#12 支持需要等待 crate 成熟或使用 openssl

4. **测试结果**
   - 6 个新测试全部通过 ✅
   - 总计 66 个测试通过

### ✅ Task #1: PKCS#7/CMS 支持 (2025-03-17)
**完成内容：**
1. **CMS 模块** (src/formats/cms.rs)
   - `ParsedCms` 结构体 - 解析后的 CMS 数据
   - `is_cms()` - 检测 CMS 格式
   - `is_pem_cms()` - 检测 PEM 格式的 CMS
   - `extract_signed_data_certs()` - 从 SignedData 提取证书

2. **格式检测集成**
   - 更新 cert/format.rs 以检测 CMS 格式
   - CMS OID 检测 (1.2.840.113549.1.7.2)

3. **测试结果**
   - 7 个新测试全部通过 ✅
   - 总计 73 个测试通过

### ✅ Task #2: 私钥查看 (2025-03-17)
**完成内容：**
1. **私钥解析模块** (src/formats/keys.rs)
   - `ParsedPrivateKey` 结构体 - 解析后的私钥信息
   - `KeyType` 枚举 - RSA, EC, DSA 类型
   - `from_der()` / `from_pem()` - 解析 DER/PEM 私钥
   - 格式检测函数

2. **功能特性**
   - PKCS#8 格式支持
   - SEC1 EC 私钥支持
   - 检测加密私钥
   - 密钥类型和大小识别
   - 曲线名称提取 (P-256, P-384, P-521, secp256k1)

3. **测试结果**
   - 8 个新测试全部通过 ✅
   - 总计 81 个测试通过

### ✅ Task #3: CSR 支持 (2025-03-17)
**完成内容：**
1. **CSR 解析模块** (src/formats/csr.rs)
   - `ParsedCsr` 结构体 - 解析后的 CSR 信息
   - `from_der()` / `from_pem()` - 解析 DER/PEM CSR
   - `is_pem_csr()` / `is_der_csr()` - 格式检测函数
   - OID 查找和字符串提取功能

2. **功能特性**
   - Subject DN 提取
   - 公钥算法检测
   - 签名算法和签名值提取
   - CSR 属性支持

3. **测试结果**
   - 6 个新测试全部通过 ✅
   - 总计 87 个测试通过

## 问题日志

*暂无问题记录*

## 下一步

**下一个任务**: 根据计划继续实现剩余功能
- Task #7: 证书链可视化
- Task #9: ASN.1 结构查看器
- Task #10: 网络功能 (OCSP/CRL)
- Task #8: CLI 模式
- Task #11: 测试基础设施
