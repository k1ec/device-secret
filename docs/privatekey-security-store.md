# 私钥安全管理方案

> 日期: 2026-08-12
> 状态: 设计中
> 关联: SysRS-device-secret.md, 2026-08-11-device-secret-design.md

## 1. 问题陈述

### 当前状态

`license-gen` 当前通过 `-key` 参数直接从文件系统读取**明文 PEM 私钥**进行 Ed25519 签名：

```bash
license-gen -request req.json -key private.pem -expires +365d
```

其中 `private.pem` 是 `cmd/keygen` 生成的明文 PEM 文件：

```
-----BEGIN ED25519 PRIVATE KEY-----
<base64 64 字节私钥>
-----END ED25519 PRIVATE KEY-----
```

### 安全隐患

| 威胁 | 当前状态 |
|---|---|
| 私钥文件泄露（U 盘拷贝、备份泄露） | 无任何静态加密保护 |
| 签发机文件系统被非授权访问 | 文件权限 `0600`，仅 OS 级别保护 |
| 恶意管理员事后抵赖 | 无审计日志 |
| 私钥使用无追溯 | 不知道谁在何时签发了什么 license |
| 密码共享/弱口令 | 无私钥加密，无口令概念 |

### 设计目标

1. **私钥静态加密**：落盘即密文，泄露文件无法使用
2. **管理员权限控制**：只有知道口令的人才能签发，口令强度可强制执行
3. **全链路审计**：每次签发记录操作者、时间、目标设备、license 指纹，支持防篡改
4. **接口可扩展**：预留 KMS/Vault 等外部密钥管理后端的接入接口
5. **零第三方依赖**：所有加密使用 Go 标准库 + `golang.org/x/crypto`（Argon2id）
6. **向后兼容**：仍可读取明文 PEM，但打印迁移警告

---

## 2. 架构概览

### 核心思路

`license-gen` 引入 **Signer 接口**，私钥操作抽象为后端插件，当前实现两个后端，未来可扩展。

```
license-gen CLI
│
├── -signer file  (默认)        ──▶ FileSigner
│   ├── 私钥文件: AES-256-GCM 加密（双层 DEK/KEK）
│   ├── KEK 派生: Argon2id(passphrase, salt)
│   ├── 密码: stdin 交互输入 或 $DEVICE_SECRET_PASSPHRASE 环境变量
│   └── 实现: internal/signer/file.go
│
├── -signer kms   (预留)        ──▶ KMSSigner
│   ├── 私钥加密 PEM 的 DEK 由云 KMS 解密
│   ├── Ed25519 签名仍由本地完成（KMS 仅解密 DEK，不签名）
│   ├── 认证: 云厂商默认凭证链（环境变量/实例角色）
│   └── 实现: internal/signer/kms.go（未来）
│
└── Signer 接口 (internal/signer/signer.go)
    type Signer interface {
        Sign(payload []byte) (signature []byte, error)
        PublicKey() ed25519.PublicKey
    }
```

**关键约束**：
- Signer 接口零第三方依赖——Ed25519 类型直接用 `crypto/ed25519`
- 私钥永远不会以明文落盘（FileSigner）
- cmd/keygen 生成的私钥默认加密存储，`-raw` 标志显式请求明文（仅测试用途）
- 新增 `internal/signer` 包，现有 `internal/crypto` 保持不变（仅做基础 Ed25519 操作）

---

## 3. 方案 A：加密 PEM + Argon2id（推荐首选）

### 3.1 OWASP 对标分析

以下逐一对照 OWASP Password Storage Cheat Sheet、OWASP Cryptographic Storage Cheat Sheet、OWASP Key Management Cheat Sheet 的最新建议，并确保每一项**高于** OWASP 最低要求。

| 参数 | OWASP 最低 | 本方案 | 超出幅度 |
|---|---|---|---|
| **对称加密算法** | AES-128-GCM | **AES-256-GCM** | OWASP 将 256-bit 标记为「理想」；FIPS 140-3 兼容 |
| **KDF 算法** | Argon2id | **Argon2id** | OWASP 首选，NIST SP 800-132 修订版即将纳入 |
| **KDF 内存 (m)** | 19 MiB (19456 KiB) | **128 MiB** (131072 KiB) | **~7x** |
| **KDF 迭代 (t)** | 2 | **5** | **2.5x** |
| **KDF 并行度 (p)** | 1 | **4** | 利用多核抵抗 GPU/ASIC |
| **Salt 长度** | 16 bytes | **32 bytes** (256-bit) | **2x** |
| **派生密钥长度** | 128 bits | **256 bits** | **2x** |
| **GCM Nonce** | 12 bytes | **12 bytes** | 标准 96-bit，唯一性由 CSPRNG 保证 |
| **GCM Tag** | 未显式规定 | **16 bytes** (128-bit) | GCM 最大认证强度 |

### 3.2 Argon2id 参数论证

OWASP Password Storage Cheat Sheet 推荐的五个等效配置中，最强的为 m=46 MiB, t=1, p=1。本方案选择 **m=128 MiB, t=5, p=4**：

- **为什么 128 MiB？** 签发机为云服务器，至少有 2-4 GB 内存。128 MiB × 4 线程 = 512 MiB 峰值，完全可承受。远超 OWASP 最大推荐 46 MiB
- **为什么 t=5？** OWASP 各配置迭代范围 1-5 次。选最高端 5 次，等效于 ~640 MiB·iterations 的 GPU 暴力破解成本
- **为什么 p=4？** 利用多核 CPU，增加并行内存访问压力，进一步抵抗 FPGA/ASIC
- **单次解密耗时**：约 1-2 秒（现代云 VM），对于低频（月均几次）的签发操作完全合理

### 3.3 双层密钥架构（Envelope Encryption）

OWASP Key Management Cheat Sheet 明确要求 **DEK + KEK** 分离——密钥加密密钥（KEK）保护数据加密密钥（DEK），DEK 保护实际数据。本方案完整实现该模式：

```
┌── encrypted_private.pem ──────────────────────┐
│                                                │
│  PEM Header:                                   │
│    Proc-Type: 4,ENCRYPTED                      │
│    DEK-Info: ARGON2ID,<salt_b64>,<nonce_b64>   │
│    KEK-Params: m=131072,t=5,p=4                │
│                                                │
│  Body:                                         │
│    base64(                                     │
│      Encrypted DEK (32 bytes + 16-byte GCM tag)│
│      +                                         │
│      Encrypted Private Key (64 bytes           │
│        + 16-byte GCM tag)                      │
│    )                                           │
│                                                │
│  密钥层级:                                      │
│                                                │
│    passphrase ──▶ Argon2id ──▶ KEK (256-bit)   │
│                                    │            │
│                         AES-256-GCM Decrypt     │
│                                    │            │
│                                    ▼            │
│                            DEK (256-bit,        │
│                              CSPRNG 生成)       │
│                                    │            │
│                         AES-256-GCM Decrypt     │
│                                    │            │
│                                    ▼            │
│                          Ed25519 Private Key    │
│                              (64 bytes)         │
│                                                │
└────────────────────────────────────────────────┘
```

**为什么双层架构超出 OWASP 要求：**

| 收益 | 说明 |
|---|---|
| **密码修改零成本** | 修改口令只重新加密外层 DEK，无需重新加密私钥 |
| **多人共享私钥** | 同一个 DEK 可有多个 KEK（不同管理员的独立口令），每个口令独立加密 DEK |
| **密钥分离** | OWASP Key Management 要求的「密钥与加密数据分离存储」原则——DEK 和 KEK 位于不同加密层 |
| **防篡改** | 两层 GCM 认证标签：篡改 DEK 或私钥均被检测 |

### 3.4 加密 PEM 文件格式

```
-----BEGIN ED25519 PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: ARGON2ID,<base64-salt>,<base64-nonce1>
KEK-Params: m=131072,t=5,p=4

<base64(encrypted_DEK || GCM_tag1 || encrypted_privkey || GCM_tag2)>
-----END ED25519 PRIVATE KEY-----
```

- 头部 `Proc-Type: 4,ENCRYPTED` 与 OpenSSL 兼容风格一致
- `DEK-Info` 携带 KDF 类型、salt、GCM nonce
- `KEK-Params` 显式记录 Argon2id 参数，确保未来参数升级时可自动识别
- 实际 32 字节 KEK 由 Argon2id 从口令+salt 派生，不写入文件
- 每个 GCM tag 追加在对应 ciphertext 后，一并 base64 编码

### 3.5 `internal/crypto` 新增 API

```go
// EncryptPrivateKey 用双层架构加密私钥，返回加密 PEM。
// DEK 由 crypto/rand 生成，KEK 由 Argon2id 从 passphrase + salt 派生。
func EncryptPrivateKey(key ed25519.PrivateKey, passphrase []byte) ([]byte, error)

// ParseEncryptedPrivateKey 解析加密 PEM，验证两层 GCM tag 后返回私钥。
// 若口令错误或文件损坏，返回 ErrIncorrectPassphrase。
func ParseEncryptedPrivateKey(pemBytes []byte, passphrase []byte) (ed25519.PrivateKey, error)

// IsEncryptedPEM 快速判断 PEM 是否加密（检查 Proc-Type 头）。
func IsEncryptedPEM(pemBytes []byte) bool

// ChangePassphrase 修改口令，只重新加密 DEK 层，不触碰私钥层。
func ChangePassphrase(pemBytes []byte, oldPass, newPass []byte) ([]byte, error)
```

### 3.6 密码强度策略

**生成阶段（keygen）**——强制校验，不依赖管理员自觉：

```
$ keygen
Enter new passphrase (min 16 chars): ********
Confirm passphrase: ********

✗ Too weak: min 16 characters (got 8)
✗ Too weak: detected in common password list
✗ Too weak: entropy < 80 bits

✓ Passphrase accepted. Key saved to private.enc.pem
```

| 策略 | 阈值 | 依据 |
|---|---|---|
| 最小长度 | **16 字符** | OWASP 多因素认证建议 ≥8；密钥加密加倍 |
| 最小熵 | **80 bits**（Shannon entropy） | NIST SP 800-63B 建议 ≥80 bits for secrets |
| 常见密码拒绝 | 内置 10k 弱口令黑名单 + zxcvbn 评分 | OWASP Password Storage Cheat Sheet：拒绝已知弱口令 |
| 无复杂度规则 | 不强制大小写/数字/符号 | NIST SP 800-63B：取消组合规则，提倡长口令 |

### 3.7 反暴力破解设计

| 层 | 措施 |
|---|---|
| Argon2id | 128 MiB / 5 iter / 4 threads，每次尝试 ~1.5 秒，单核每秒 < 1 次 |
| 无在线提示 | 密码错误只返回通用错误 `signer: incorrect passphrase or corrupted key file`，不区分「文件损坏」和「密码错误」 |
| 建议的运维加固 | 签发机仅允许密钥管理员 SSH 登录（sshd `AllowUsers`），`private.enc.pem` 权限 `0600`，`/home/admin` 权限 `0700` |

### 3.8 FileSigner 签名流程与密码交互

```
管理员 SSH 到签发机
         │
         ▼
$ license-gen -request req.json -key private.enc.pem -expires +365d
         │
         │  FileSigner 初始化
         │  ┌─ 读取 PEM 文件
         │  ├─ 检查 Proc-Type: 4,ENCRYPTED
         │  ├─ 解析 DEK-Info（salt, nonce1）
         │  └─ 准备 Argon2id 参数
         │
         ▼
Enter passphrase for private key: ********  ← stdin（不回显）
         │
         │  KEK = Argon2id(passphrase, salt, m=128MiB, t=5, p=4)
         │  ~1-2 秒
         │  DEK = AES-256-GCM-Decrypt(KEK, nonce1, encrypted_DEK)
         │  验证 GCM tag1 ✓
         │  privKey = AES-256-GCM-Decrypt(DEK, nonce2, encrypted_privkey)
         │  验证 GCM tag2 ✓
         │
         ▼
签名: ed25519.Sign(privKey, payload)  ← 私钥仅在内存，~微秒级
         │
         ├─ 成功: 输出 license → stdout / -o 文件
         │        进程退出，OS 回收所有内存
         │
         └─ 密码错误: GCM tag 验证失败
                     返回 "signer: incorrect passphrase or corrupted key file"
                     不做重试提示
```

**密码来源优先级：**

```
1. stdin 交互输入（默认，未设置环境变量时）
2. $DEVICE_SECRET_PASSPHRASE 环境变量（非交互场景，如 CI）
3. 空密码直接拒绝（拒绝无口令加密的私钥）
```

**安全细节：**

- 私钥内存使用 `[]byte` 分配在 Go 堆上。不引入 memguard/mlock 等第三方依赖（违反项目零依赖约束）。进程退出时 OS 回收所有内存
- `crypto/ed25519.PrivateKey` 实际是 64 字节 seed，Go 标准库内部通过 `NewKeyFromSeed()` 派生完整密钥
- 签发完成后进程立即退出

### 3.9 `internal/signer` 接口定义

```go
// internal/signer/signer.go

// Signer 抽象签名操作。所有实现不得将私钥写入文件系统。
type Signer interface {
    // Sign 对 payload 进行 Ed25519 签名。
    Sign(payload []byte) (signature []byte, err error)

    // PublicKey 返回对应的 Ed25519 公钥。
    PublicKey() ed25519.PublicKey
}

// ErrIncorrectPassphrase 密码错误的统一错误（不区分损坏/错误）
var ErrIncorrectPassphrase = errors.New("signer: incorrect passphrase or corrupted key file")
```

```go
// internal/signer/file.go

type FileSigner struct {
    privKey ed25519.PrivateKey // 仅在内存，Init 后立即可用
}

// NewFileSigner 读取加密 PEM，交互获取口令，解密私钥。
// passphrase 为 nil 时从 stdin 交互读取。
func NewFileSigner(pemPath string, passphrase []byte) (*FileSigner, error)

func (fs *FileSigner) Sign(payload []byte) ([]byte, error)
func (fs *FileSigner) PublicKey() ed25519.PublicKey
```

---

## 4. 方案 B：KMS Signer（预留设计）

### 4.1 为什么需要预设计

当前选择 FileSigner 作为首发方案，但 Signer 接口一经验证，后续新增 KMS 后端只需实现 `Sign(payload) -> signature` + `PublicKey()`，不改 CLI、不改审计、不改 SDK。预留设计确保不重写。

### 4.2 云 KMS Ed25519 支持现状

| 云平台 | Ed25519 支持 | 支持的非对称算法 |
|---|---|---|
| 阿里云 KMS | ❌ 不支持 | RSA_PSS_SHA_256, RSA_PKCS1_SHA_256, ECDSA_SHA_256, SM2DSA |
| 腾讯云 KMS | ❌ 不支持 | RSA_2048, SM2, ECDSA |
| AWS KMS | ❌ 不支持 | RSA, ECC (P-256/P-384/P-521) |
| GCP Cloud KMS | ❌ 不支持 | RSA, EC (P-256/P-384) |

**结论**：截至 2026 年 8 月，主流云 KMS 均不支持 Ed25519 非对称密钥。因此直接将签名操作迁移到 KMS 需要对签名算法进行不兼容改造（ECDSA 或 RSA），破坏现有 license 格式。

### 4.3 KMS 选项对比

| 选项 | SDK 侧影响 | 签发侧影响 | 安全收益 |
|---|---|---|---|
| **选项 A**：签名算法迁移到 ECDSA | 需更新公钥+验签算法，多 kid 并存过渡期 | KMS 直接签名，私钥不出 KMS | ★★★★ |
| **选项 B（推荐保留）**：KMS 仅解密 DEK | 无变化（仍 Ed25519 验签） | 同 FileSigner 格式，KEK 来自 KMS 而非口令 | ★★★☆ |

### 4.4 推荐保留路径：KMS 选项 B

```
┌── 加密 PEM 文件（格式与方案 A 完全相同）──────┐
│                                                │
│  DEK 层: AES-256-GCM(DEK, 私钥明文)             │
│  KEK 层:                                       │
│    方案 A → KEK = Argon2id(passphrase, salt)    │
│    方案 B → KEK = KMS.Decrypt(encrypted_DEK)    │
│                                                │
│  共享: 加密 PEM 格式、审计日志、Signer 接口      │
│  差异: 仅 KEK 解密方式                           │
└────────────────────────────────────────────────┘
```

```go
// internal/signer/kms.go（未来实现）

type KMSSigner struct {
    privKey ed25519.PrivateKey
}

// NewKMSSigner 用 KMS 解密 DEK，然后解密 Ed25519 私钥。
// 工作流：
//   1. 读取加密 PEM（双层格式与 FileSigner 相同）
//   2. 调用 KMS.Decrypt(encrypted_DEK) → DEK  ← 核心差异
//   3. AES-GCM-Decrypt(DEK, nonce2, encrypted_privkey) → Ed25519 私钥
//   4. Sign() 仍用本地 Ed25519
func NewKMSSigner(pemPath string, keyAlias string) (*KMSSigner, error)
```

**权限模型（阿里云 RAM Policy 示例）：**

```json
{
  "Effect": "Allow",
  "Action": "kms:Decrypt",
  "Resource": "acs:kms:*:*:key/device-secret-dek-key",
  "Condition": {
    "IpAddress": {
      "acs:SourceIp": ["10.0.0.0/8"]
    }
  }
}
```

### 4.5 与 HashiCorp Vault 的比对

| 维度 | 本方案（加密 PEM + Argon2id） | 本方案（KMS 选项 B） | HashiCorp Vault Transit |
|---|---|---|---|
| **安全级别** | ★★★☆ 中高——静态加密，口令保护 | ★★★★ 高——云 KMS 保护 KEK | ★★★★★ 极高——完整密钥生命周期+ACL+审计 |
| **运维复杂度** | ★☆☆☆ 极低——零新服务 | ★★☆☆ 低——云服务托管 | ★★★★☆ 高——需部署、维护、备份、升级 |
| **管理员控制** | 知道口令的人才能签发 | 有 RAM 授权的人才能签发 | Vault Policy 精确到路径和操作 |
| **审计追踪** | 本地 HMAC 链 | 云 ActionTrail + 本地审计 | Vault Audit Device |
| **Ed25519 兼容** | ✅ 原生 | ✅ 原生 | ❌ Transit 仅支持 RSA/ECDSA/Ed25519(???需要验证) |
| **适用场景** | 低频手动签发，团队 < 5 人 | 已有云账号体系，需集中权限管理 | 多应用、多密钥、需自动化签发 |
| **成本** | 零 | 按 KMS API 调用计费 | 自建服务器成本 + 运维人力 |
| **第三方依赖** | 仅 `golang.org/x/crypto` | 云 SDK（阿里云/腾讯云） | Vault API 客户端 |

**Vault Transit Engine 的 Ed25519 支持**：HashiCorp Vault 1.4+ Transit Engine 支持 `ed25519` 密钥类型，签名操作为 `POST /transit/sign/:name`。但引入 Vault 意味着：
- 需要维护 Vault 集群（或至少单节点 + 备份）
- Unseal 操作需人工介入（或依赖云 KMS Auto-Unseal）
- 运维复杂度远高于本方案，适合多应用、多密钥场景

---

## 5. 审计日志设计

### 5.1 OWASP 审计要求对标

OWASP Key Management Cheat Sheet 要求：
- 所有密钥操作必须可审计
- 审计日志需防篡改
- 至少记录：操作者、时间、密钥标识、操作类型、结果

### 5.2 审计事件结构

```go
type AuditEvent struct {
    Timestamp   time.Time `json:"timestamp"`    // RFC3339
    Operator    string    `json:"operator"`     // $USER 或 -operator 标志
    Operation   string    `json:"operation"`    // "sign_license"
    SignerType  string    `json:"signer_type"`  // "file" / "kms"
    KeyID       string    `json:"key_id"`       // SHA-256(pubKey)[:8]，不记录完整公钥
    LicenseFP   string    `json:"license_fp"`   // SHA-256(licData)[:12]，追踪但不泄露内容
    DeviceHash  string    `json:"device_hash"`  // 被签发设备的指纹
    ExpiresAt   string    `json:"expires_at"`   // license 到期时间
    Result      string    `json:"result"`       // "success" / "error:<type>"
}
```

**字段设计原则**：记录足够追溯、但不过度暴露敏感信息。

### 5.3 审计日志存储

```
/var/log/device-secret/audit.log
```

| 属性 | 策略 |
|---|---|
| 格式 | JSONL（每行一条 JSON），便于 `jq` 和 log-agent 采集 |
| 权限 | `0640`，owner `root`，group `device-secret-admin` |
| 轮转 | 依赖外部 logrotate（不自行实现），建议保留 90 天 |
| 完整性 | 每行带 HMAC-SHA256 尾随字段 `mac:<hex>`，密钥来自环境变量 `$AUDIT_HMAC_KEY`（可选，未设则跳过） |
| 同步写入 | `O_APPEND \| O_SYNC`，每次签发立即 fsync |

### 5.4 HMAC 防篡改链

```
audit.log:
{"timestamp":"2026-08-12T10:30:00Z","operator":"admin",...,"mac":"abc123..."}
{"timestamp":"2026-08-12T11:15:00Z","operator":"admin",...,"mac":"def456..."}

每行 MAC = HMAC-SHA256($AUDIT_HMAC_KEY, 去除mac字段的完整JSON行)
→ 若任意一行被篡改，mac 不匹配 → 告警
→ 无法阻止删除整行，但可通过行号间隙检测
```

### 5.5 审计日志写入流程

```
license-gen 启动
  │
  ├─ 解析标志
  ├─ 打开审计日志（追加模式）
  ├─ 构建 AuditEvent{
  │     Operator:  $USER 或 -operator 值,
  │     Operation: "sign_license",
  │     SignerType: "file",
  │     KeyID:     SHA256(pubKey)[:8],
  │     ... 其余字段在签名后填充 ...
  │   }
  │
  ├─ 签名
  │   ├─ 成功 → event.Result = "success"
  │   │        event.LicenseFP = SHA256(licData)[:12]
  │   │        event.DeviceHash = payload.DeviceHash
  │   │        event.ExpiresAt = payload.ExpiresAt
  │   │
  │   └─ 失败 → event.Result = "error:<msg>"
  │
  ├─ 计算 MAC（若 $AUDIT_HMAC_KEY 已设）
  ├─ 追加写入一行 JSON + \n
  ├─ fsync
  └─ 输出 license / 报错退出
```

---

## 6. CLI 改造

### 6.1 `cmd/license-gen` 新增标志

```bash
license-gen [flags]
  -request string    请求文件路径（必填）
  -key string        私钥 PEM 路径（必填，支持明文和加密 PEM）
  -signer string     签名后端: file（默认）/ kms（预留）
  -expires string    到期时间，ISO8601 或 +Nd（必填）
  -features string   功能模块，逗号分隔（可选）
  -metadata string   备注信息（可选）
  -kid string        密钥 ID（可选）
  -operator string   操作者标识（默认 $USER，用于审计日志）
  -audit string      审计日志路径（默认 /var/log/device-secret/audit.log）
  -o string          输出路径（默认 stdout）
```

### 6.2 明文 PEM 向后兼容

```
检测逻辑:
  if IsEncryptedPEM(keyPEM) → 走加密流程（新行为）
  else → 走明文流程 + stderr 打印迁移警告

stderr:
  ⚠ Reading plaintext private key. Migrate to encrypted PEM:
    1. keygen -out new_encrypted.pem  (set a strong passphrase)
    2. Keep the passphrase in your password manager.
    3. Shred the old plaintext key:  shred -u old_private.pem
    4. Use the new encrypted key with license-gen.
```

### 6.3 `cmd/keygen` 改造

```bash
keygen [flags]
  -out string      私钥输出路径（默认 private.pem）
  -pub string      公钥输出路径（默认 public.pem）
  -raw             输出明文私钥（默认 false，即加密输出，仅测试用途）
```

- 默认模式（无 `-raw`）：`keygen` 提示输入口令（stdin），输出加密 PEM
- `-raw` 模式：行为与当前一致，输出明文 PEM，stderr 打印警告

---

## 7. 威胁模型分析

| 威胁 | 方案 A 防御 | 方案 B 防御 |
|---|---|---|
| 私钥文件泄露（U 盘拷贝、备份泄露） | AES-256-GCM + Argon2id 128 MiB/5 iter 加密，暴力破解不可行 | AES-256-GCM + KMS 解密权限，无云凭证无法解密 |
| 管理员弱口令被暴力破解 | Argon2id 单次 ~1.5 秒，每秒 < 1 次尝试；zxcvbn 拒绝弱口令 | 无口令，凭 RAM 角色/STS Token |
| 签发机被 root 提权 | 内存 dump 可读密钥（Go 无 mlock），审计日志 HMAC 链可追溯异常签发 | 私钥永不出 KMS，攻击者最多调用 KMS API（受 RAM IP 白名单限制） |
| 恶意管理员事后抵赖 | 审计日志 HMAC 链 + 不可否认性 | 云 ActionTrail + 本地审计日志 |
| KMS API 被滥用 | N/A | RAM IP 白名单 + 操作频率告警 |
| 审计日志被篡改 | HMAC-SHA256 逐行 MAC | HMAC-SHA256 + 云审计双记录 |

---

## 8. 实施路径

```
阶段 1（本次）: 方案 A 完整实现
  ├── internal/crypto: EncryptPrivateKey, ParseEncryptedPrivateKey, IsEncryptedPEM, ChangePassphrase
  ├── internal/signer: Signer 接口 + FileSigner 实现
  ├── cmd/keygen: 加密输出（默认）+ 口令强度校验
  ├── cmd/license-gen: -signer file + 密码交互 + 审计日志 + 明文 PEM 兼容
  └── 测试: 加密往返、错误口令、审计格式、HMAC 完整性

阶段 2（未来）: 方案 B KMS 集成
  ├── internal/signer/kms.go: KMS Signer 实现
  ├── cmd/license-gen: -signer kms 分支
  └── 文档: KMS 部署指南（阿里云/腾讯云）

阶段 3（远期）: 运维增强
  ├── 审计日志自动轮转配置
  ├── Prometheus 指标暴露
  └── 签发审批流程（如需要）
```

---

## 9. 参考标准

- OWASP Password Storage Cheat Sheet — Argon2id 参数推荐
- OWASP Cryptographic Storage Cheat Sheet — AES-256-GCM 算法推荐
- OWASP Key Management Cheat Sheet — DEK/KEK 双层架构
- NIST SP 800-132 Rev. (draft) — 基于密码的密钥派生（即将纳入 Argon2id）
- NIST SP 800-63B — 数字身份指南（口令长度与熵要求）
- RFC 9106 — Argon2 内存硬 KDF 规范
