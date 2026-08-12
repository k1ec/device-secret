# SDK 多公钥支持（kid-based Key Selection）— 设计文档

> 日期: 2026-08-12
> 状态: 已确认
> 关联: SysRS-device-secret.md §4.2 密钥轮换, §6.5 SDK API

## 目标

SDK 支持通过 License 中的 `kid` 字段选择对应公钥验签，实现平滑密钥轮换：更换签发密钥后，已发出的旧 License 持续有效，新 License 用新密钥签发和验证。

## 设计总览

**核心变化**：`SDK` 从「单公钥」变为「`kid` → 公钥映射」，映射表通过 Go `embed` 在编译时嵌入二进制，避免运行时加载文件被篡改的风险。

```
源码仓库                             编译后二进制
───────                             ──────────
keys/                               SDK 内部
├── default.pem ──┐                 map[string]ed25519.PublicKey{
├── 2026-v1.pem ──┤── go:embed ──▶    "":          pub_default,
├── 2027-v2.pem ──┘                   "2026-v1":  pub_2026,
                                       "2027-v2":  pub_2027,
                                     }

license.kid ───────────────────────────┘ 选择对应公钥验签
```

## kid 命名规范

| 维度 | 规则 |
|---|---|
| 允许字符 | `[a-zA-Z0-9_-]+`（字母、数字、连字符、下划线） |
| 长度 | 1-64 字符 |
| 大小写 | 区分大小写，建议全小写 |
| 保留名 | `default` 保留给无 `kid` 的旧 License |

**合规示例**：`2026-primary`、`2027-rotation-v2`、`rk3568-batch-03`、`key_2026Q4`

## 公钥文件命名规范

源码仓库中按 `<kid>.pem` 命名，放在统一目录（如 `keys/`），通过 `//go:embed keys/*.pem` 嵌入：

```
keys/
├── default.pem          ← 匹配 kid="" 的旧 License（当前活跃签发密钥）
├── 2026-primary.pem     ← 匹配 kid="2026-primary"
├── 2027-rotation-v2.pem ← 匹配 kid="2027-rotation-v2"
```

**规则**：
- 文件扩展名固定 `.pem`
- 文件名（去掉 `.pem`）即 `kid` 值；`default` → `kid=""`
- 文件必须在 `keys/` 目录下，不可嵌套子目录
- PEM 类型必须为 `ED25519 PUBLIC KEY`

## API 设计

### Config 变更

```go
type Config struct {
    // PublicKey 是单公钥模式（向后兼容）。设置此项时 KeyFS 被忽略。
    PublicKey []byte

    // KeyFS 是多公钥模式，通过 go:embed 注入 keys/*.pem。
    KeyFS fs.FS

    LicensePath   string
    MarkerPath    string
    GraceDuration time.Duration
}
```

优先级：`PublicKey != nil` → 单公钥模式（行为不变）；否则 `KeyFS != nil` → 多公钥模式；两者都 nil → Init 返回 error。

### LicenseInfo 增加 KID

```go
type LicenseInfo struct {
    KID        string    // 新增
    DeviceHash string
    ExpiresAt  time.Time
    Features   []string
}
```

### 调用方使用方式

```go
//go:embed keys/*.pem
var keyFS embed.FS

func main() {
    lic, err := sdk.Init(sdk.Config{
        LicensePath: "/license/license",
        KeyFS:       keyFS,
    })
    // ...
}
```

## Init() 流程（多公钥模式）

```
Init(cfg)
  │
  ├─ 1. cfg.PublicKey != nil → 走单公钥路径（与当前一致）
  ├─ 2. cfg.KeyFS == nil → return error("no public key configured")
  │
  ├─ 3. 扫描 KeyFS，加载所有 *.pem
  │   ├─ 校验文件名（kid）匹配 ^[a-zA-Z0-9_-]{1,64}$
  │   │   └─ 不匹配 → return error
  │   ├─ "default" → kid = ""
  │   ├─ 校验 kid 不重复
  │   └─ 解析 PEM → 校验 ED25519 PUBLIC KEY
  │       └─ 无效 → return error
  │   └─ 至少 1 个 key，否则 return error
  │
  ├─ 4. 读 license 文件
  ├─ 5. PeekKID(licenseData) → 提取 kid（不解签）
  ├─ 6. kid → 查映射表取公钥
  │   ├─ 找到 → 用它验签
  │   ├─ 找不到 → return error("unknown kid 'xxx'")
  │   └─ 无 kid 且无 "default" → return error
  │
  ├─ 7. VerifyLicense(licenseData, selectedPubKey) → 验签
  │   └─ 失败 → initPassed=false（与当前一致）
  │
  └─ 8. 返回 SDK
```

## internal/license 新增辅助函数

```go
// PeekKID 不解码签名，仅从 license 数据中提取 kid 字段。
// 用于 Init 阶段——先拿到 kid 选定公钥，再完整验签。
func PeekKID(licenseData []byte) (string, error)
```

## 错误场景汇总

| 场景 | Init 行为 |
|---|---|
| `PublicKey` 和 `KeyFS` 都设置 | 以 `PublicKey` 为准（向后兼容） |
| `PublicKey` 和 `KeyFS` 都为空 | `return error: "sdk: no public key configured"` |
| KeyFS 中无 `.pem` 文件 | `return error: "sdk: no key files found in KeyFS"` |
| KeyFS 中文件名不符合 kid 规范 | `return error: "sdk: invalid kid '...' in key file '...'"` |
| 文件名重复映射到同一 kid | `return error: "sdk: duplicate kid '...'"` |
| PEM 内容无效 | `return error: "sdk: invalid PEM in key file '...'"` |
| License 无 `kid` 且无 `default.pem` | `return error: "sdk: license has no kid, and no default key configured"` |
| License 的 `kid` 在映射表中找不到 | `return error: "sdk: unknown kid '...' — no matching public key"` |
| License 签名无效 | `initPassed=false`，`Verify()` → `StatusInvalid`（与当前一致） |

> 前 8 个场景是配置错误，`Init()` 直接返回 error。只有签名无效走「Init 成功但 Verify 失败」的软着陆路径。

## 密钥轮换生命周期

```
阶段 1: 初始部署          阶段 2: 轮换过渡              阶段 3: 旧密钥退役
                                                    (所有旧 License 已到期)

keys/                    keys/                      keys/
├── default.pem (pub₁)   ├── default.pem (pub₂)     ├── default.pem (pub₂)
                          ├── 2024-v1.pem (pub₁)

签发: kid="" → priv₁     签发: kid="2025-v2"→priv₂   签发: kid="2025-v2"→priv₂
设备: pub₁ 验签           设备: pub₁+pub₂ 双验签       设备: 仅 pub₂

旧 Lic ✅                旧 Lic ✅                    旧 Lic ❌ (过期)
                         新 Lic ✅                    新 Lic ✅
```

**规则**：
- `default.pem` 始终是当前活跃签发密钥
- 旧密钥保留在 `keys/` 直至其签发的所有 License 自然过期
- 更换 `default.pem` 不影响已有 License（旧 License 要么有 kid 指向旧密钥，要么无 kid 用旧的 default——但旧 default 作为 `<old-kid>.pem` 保留）

## 测试策略

### internal/license — PeekKID

- `TestPeekKID_WithKID` — 正确提取 kid
- `TestPeekKID_NoKID` — 无 kid 返回空字符串
- `TestPeekKID_InvalidBase64` — 非法 base64 返回 error

### pkg/sdk — Key 加载

- `TestLoadKeys_SingleDefault` — 仅 `default.pem`
- `TestLoadKeys_MultipleKids` — 多 kid + default
- `TestLoadKeys_InvalidKidName` — 非法文件名
- `TestLoadKeys_InvalidPEM` — PEM 内容损坏
- `TestLoadKeys_EmptyDir` — 无 .pem 文件

### pkg/sdk — Init 多公钥

- `TestInit_KeyFSSelectsByKid` — 按 kid 选择公钥验签成功
- `TestInit_KeyFSDefaultFallback` — 无 kid License 用 default.pem
- `TestInit_KeyFSUnknownKid` — 未知 kid → Init error
- `TestInit_KeyFSNoDefaultForOldLicense` — 无 kid 无 default → error
- `TestInit_KeyFSWrongKeyForKid` — kid 匹配但密钥不对 → initPassed=false
- `TestInit_PublicKeyBackwardCompat` — PublicKey + KeyFS 同时设 → 单公钥路径
- `TestInit_NoPublicKeyNoKeyFS` — 都不设 → error

### pkg/sdk — LicenseInfo

- `TestLicenseInfo_IncludesKID` — 验签后 KID 正确
- `TestLicenseInfo_KIDEmpty` — 无 kid License，KID 为空

### cmd/license-gen — kid 校验

- 非法 kid → 拒绝并报错

## 不纳入范围

- TPM/安全硬件的密钥存储
- 在线 CRL/OCSP 吊销检查
- 跨设备密钥同步
