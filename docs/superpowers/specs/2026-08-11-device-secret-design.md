# Device Secret — 设计文档

## 1. 概述

`device-secret` 是一套软件 License 方案，通过设备指纹绑定防止程序被非法拷贝到未授权设备运行。由三个制品组成：

- **fingerprint CLI**：在目标宿主机采集硬件指纹，生成请求文件
- **license-gen CLI**：在签发机读取请求文件，Ed25519 签名生成 license 文件
- **SDK (`pkg/sdk`)**：嵌入应用程序，运行时校验 license 合法性

## 2. 架构

```
┌──────────────────────────────┐     ┌──────────────────────────────┐
│         目标宿主机              │     │        签发机（安全环境）         │
│                              │     │                              │
│  fingerprint CLI             │     │  license-gen CLI              │
│  ┌────────────────────────┐  │     │  ┌────────────────────────┐  │
│  │ internal/fingerprint   │  │     │  │ internal/license       │  │
│  │  - collector.go        │  │     │  │  - format.go           │  │
│  │  - sources.go          │  │ req │  │  - sign.go             │  │
│  │  - hash.go             │──┼────▶│  │ internal/crypto        │  │
│  └────────────────────────┘  │     │  │  - keys.go (ed25519)   │  │
│                              │     │  └────────────────────────┘  │
│  SDK (应用容器内)              │     │          │                   │
│  ┌────────────────────────┐  │     │          ▼                   │
│  │ pkg/sdk                │  │ lic │    license.bin               │
│  │  - sdk.go              │◀─┼─────┘                              │
│  │ internal/grace         │  │                                    │
│  │ internal/fingerprint   │  │                                    │
│  │ internal/license       │  │                                    │
│  └────────────────────────┘  │                                    │
└──────────────────────────────┘                                    │
```

## 3. 模块设计

### 3.1 `internal/crypto` — 密钥管理

**职责**：Ed25519 密钥对生成、PEM 编码/解码、签名、验签。

```go
// 生成密钥对
func GenerateKeyPair() (ed25519.PrivateKey, ed25519.PublicKey, error)

// PEM 编码
func MarshalPrivateKey(key ed25519.PrivateKey) ([]byte, error)
func MarshalPublicKey(key ed25519.PublicKey) ([]byte, error)

// PEM 解码
func ParsePrivateKey(pemBytes []byte) (ed25519.PrivateKey, error)
func ParsePublicKey(pemBytes []byte) (ed25519.PublicKey, error)

// 签名与验签
func Sign(key ed25519.PrivateKey, message []byte) []byte
func Verify(key ed25519.PublicKey, message, sig []byte) bool
```

**实现要点**：
- 直接使用 Go 标准库 `crypto/ed25519`，零外部依赖
- PEM 使用 `"ED25519 PRIVATE KEY"` / `"ED25519 PUBLIC KEY"` 类型标签
- `Sign` 和 `Verify` 是薄封装，参数直传标准库，不做非标准变形

### 3.2 `internal/fingerprint` — 指纹采集

**职责**：跨平台采集硬件唯一标识，生成稳定的设备指纹哈希。

**数据结构**：

```go
type DeviceMeta struct {
    Hostname string `json:"hostname"`
    OS       string `json:"os"`
    Arch     string `json:"arch"`
}

type Sources map[string]string  // 硬件采集原始键值对

type Fingerprint struct {
    Sources Sources `json:"sources"`
    Hash    string  `json:"hash"`  // "sha256:<hex>"
}

type RequestFile struct {
    Version     int         `json:"version"`
    Device      DeviceMeta  `json:"device"`
    Fingerprint Fingerprint `json:"fingerprint"`
    RequestedAt time.Time   `json:"requested_at"`
}
```

**采集函数**：

```go
func Collect() (*Fingerprint, error)
```

**采集实现**（`sources.go`）：

| Key | 实现方式 | ARM | x86 |
|---|---|---|---|
| `machine_id` | 读取 `/etc/machine-id` | ✅ | ✅ |
| `cpu_serial` | 解析 `/proc/cpuinfo`，按行匹配 `Serial` 字段 | ✅ | ❌ |
| `product_serial` | 读取 `/sys/class/dmi/id/product_serial`，为空则跳过 | ❌(为空) | ✅ |
| `product_uuid` | 读取 `/sys/class/dmi/id/product_uuid`，为空则跳过 | ❌(为空) | ✅ |
| `macs` | 解析 `/sys/class/net/`，排除 `lo`/`docker*`/`veth*`/`br-*`，读取 `address` | ✅ | ✅ |

- 每个采集函数返回空字符串不报错——部分缺失是预期行为
- 所有采集完成后 filter 掉空值，若有效项数 < 2 则返回 error

**哈希生成**（`hash.go`）：

```go
func ComputeHash(sources Sources) string
```

算法：
1. 提取所有非空 key-value
2. 按 key 排序
3. 序列化为 `key1=value1\nkey2=value2\n...`
4. `SHA-256(序列化结果)` → `"sha256:<hex>"`

**确定性要求**：相同 sources 必须产生相同 hash，用于签发和验签两侧比对。

### 3.3 `internal/license` — License 格式与签名

**职责**：定义请求文件和 license 文件的数据结构，实现签名和验签逻辑。

**数据结构**：

```go
type LicensePayload struct {
    Version    int       `json:"version"`
    KID        string    `json:"kid,omitempty"`
    DeviceHash string    `json:"device_hash"`
    IssuedAt   time.Time `json:"issued_at"`
    ExpiresAt  time.Time `json:"expires_at"`
    Features   []string  `json:"features,omitempty"`  // nil = 全功能
    Metadata   string    `json:"metadata,omitempty"`
}
```

**签名（签发端）**：

```go
func SignLicense(payload LicensePayload, priv ed25519.PrivateKey) ([]byte, error)
```

1. `json.Marshal(payload)` 得到紧凑 JSON（无空格换行）
2. `ed25519.Sign(priv, compactJSON)` 得到 64 字节签名
3. 拼接输出：`base64(compactJSON) + "." + base64(signature)`

**验签（设备端）**：

```go
func VerifyLicense(licenseData []byte, pub ed25519.PublicKey) (*LicensePayload, error)
```

1. 按 `"."` 分割 `licenseData`
2. Base64 解码得到 JSON 和签名
3. `ed25519.Verify(pub, jsonBytes, sig)` 验签
4. JSON 反序列化为 `LicensePayload`
5. 返回 `*LicensePayload`

**错误类型**：

```go
var (
    ErrInvalidFormat  = errors.New("license: invalid format")
    ErrInvalidSignature = errors.New("license: signature verification failed")
)
```

### 3.4 `internal/grace` — 宽限期状态机

**职责**：管理宽限期状态转换和持久化，防止重启重置宽限期。

**状态定义**：

```go
type Status int

const (
    StatusValid       Status = iota  // 正常
    StatusGracePeriod                // 宽限期
    StatusExpired                    // 已过期（硬拒绝）
    StatusInvalid                    // 非法
)
```

**状态转换**：

```
┌─────────┐  首次过期    ┌──────────────┐  宽限期耗尽   ┌─────────┐
│  Valid  │────────────▶│ GracePeriod  │────────────▶│ Expired │
└─────────┘             └──────┬───────┘             └─────────┘
     ▲                         │
     │   新 license 通过后       │
     └─────────────────────────┘
```

**API**：

```go
type Tracker struct {
    GraceDuration time.Duration  // 默认 7 天
    MarkerPath    string         // 持久化标记文件路径
}

// Evaluate 根据当前校验是否通过，返回当前状态
// pass: true 表示验签+指纹+有效期全部通过
// now: 当前时间（测试友好，生产传 time.Now()）
func (t *Tracker) Evaluate(pass bool, now time.Time) Status
```

**持久化逻辑**：

- 首次进入 GracePeriod 时，将当前时间戳写入 `MarkerPath`（如 `/var/lib/device-secret/.grace_start`）
- 每次 `Evaluate` 读取 marker 文件计算已消耗时间
- 若 `now - graceStart > GraceDuration` → `StatusExpired`
- 若 `pass == true` → 返回 `StatusValid`，删除 marker 文件

**Corner cases**：

- marker 文件不存在且 `pass == false` → 写入当前时间，返回 GracePeriod
- marker 文件损坏/无法解析 → 保守策略，视为宽限期首日
- 写入 marker 失败 → 返回 GracePeriod 但无监控持续计数（不阻塞应用）

### 3.5 `pkg/sdk` — 应用集成 SDK

**职责**：面向应用方的唯一公共 API，组合 internal 包完成完整校验流程。

**API**：

```go
type Config struct {
    LicensePath string  // license 文件路径，如 "/license/license.bin"
    PublicKey   []byte  // Ed25519 公钥 PEM，为空则用内置公钥
}

type SDK struct {
    // 未导出字段
}

func Init(cfg Config) (*SDK, error)

func (s *SDK) Verify() *VerifyResult

func (s *SDK) LicenseInfo() *LicenseInfo

type VerifyResult struct {
    Status  Status        // Valid / GracePeriod / Expired / Invalid
    Message string        // 人类可读描述
    Remain  time.Duration // 剩余有效时间
}

type LicenseInfo struct {
    DeviceHash string
    ExpiresAt  time.Time
    Features   []string
}
```

**`Init` 流程**：

1. 读取 `LicensePath` 文件
2. 解析公钥（优先 `cfg.PublicKey`，为空则使用编译时内置公钥）
3. 调用 `license.VerifyLicense()` 验签
4. 若验签失败 → SDK 仍创建成功，`Verify()` 返回 `StatusInvalid`
5. 若验签通过 → 解析 LicensePayload，存储供 `Verify()` 使用

**`Verify` 流程**：

1. 若 Init 阶段验签失败 → 返回 `StatusInvalid`
2. 调用 `fingerprint.Collect()` 重新采集当前设备指纹
3. 比对 `fingerprint.Hash` == `LicensePayload.DeviceHash`
4. 比对 `time.Now()` vs `ExpiresAt`
5. 调用 `grace.Tracker.Evaluate(pass, now)` 得出最终状态
6. 返回 `VerifyResult`

**内置公钥**：SDK 编译时通过 `go:embed` 嵌入 `pkg/sdk/public.pem`（在 `build/` 构建阶段复制到对应位置）。

## 4. CLI 设计

### 4.1 `fingerprint`

```bash
fingerprint [flags]
  -o string     输出路径（默认 stdout，或指定文件如 request.json）
  -format string 输出格式: json / yaml（默认 json）
  -pretty       格式化输出（不紧凑）
```

**退出码**：
- `0`：采集成功
- `1`：采集失败（有效因子不足、I/O 错误）

### 4.2 `license-gen`

```bash
license-gen [flags]
  -request string   请求文件路径（必填）
  -key string       Ed25519 私钥 PEM 路径（必填）
  -expires string   到期时间，格式 ISO8601 或相对（如 "+365d"）（必填）
  -features string  功能模块列表，逗号分隔（可选）
  -metadata string  备注信息（可选）
  -kid string       密钥 ID（可选）
  -o string         输出路径（默认 stdout，或指定文件如 license.bin）
  -pretty           输出格式化 JSON（调试用，正式发布不用）
```

## 5. 错误处理

### 错误分类

| 类别 | 场景 | 处理策略 |
|---|---|---|
| **可恢复** | 单个硬件信息源读取失败 | 跳过，继续采集其他源 |
| **硬错误** | 有效因子 < 2 | `fingerprint` 退出码 1，提示采集不足 |
| **配置错误** | 公钥/私钥文件不存在或格式错误 | `Init` 返回 error，应用自行决定是否启动 |
| **校验失败** | 签名不匹配/指纹不匹配/已过期 | SDK 不崩溃，返回对应 Status |
| **I/O 错误** | marker 文件写入失败 | 降级运行，grace period 不计时（不阻塞业务） |

### SDK 零崩溃保证

```
SDK 所有公开函数不 panic
└─ 内部采集失败 → 返回 Invalid（不是 crash）
└─ marker 文件 I/O 错误 → GracePeriod 不做精确计时（保守策略，不阻止业务）
└─ license 文件被删除 → 返回 Invalid
```

## 6. 测试策略

### 单元测试

| 包 | 覆盖重点 | Mock 策略 |
|---|---|---|
| `internal/crypto` | 密钥生成往返、PEM 编解码往返、签名验签往返、错误密钥验签失败 | 无外部依赖 |
| `internal/fingerprint` | 各源采集函数（用 `testdata/` mock /proc、/sys）、哈希确定性、容错（部分缺失）、有效因子 < 2 报错 | mock 文件系统 |
| `internal/license` | 请求文件/License 序列化往返、签名格式正确、篡改检测、kid 缺失兼容、features null/[] 兼容 | fixed test keys |
| `internal/grace` | 正常流程、宽限期转换、宽限期耗尽、重启恢复（marker 文件）、marker 损坏处理 | `now` 参数注入 |
| `pkg/sdk` | 完整通过、指纹不匹配、过期、license 文件缺失、公钥不匹配 | 组合 mock |

### 集成测试

- **平台测试**：在真实 RK3568 ARM 和 x86 服务器上运行 fingerprint CLI，验证采集非空、两次采集哈希一致
- **闭环测试**：fingerprint → request → license-gen → SDK Verify()，全链路通过
- **负面测试**：
  - 篡改 license 文件中任意 1 字节 → Invalid
  - A 设备 license 拷贝到 B 设备 → Invalid
  - 过期 license → GracePeriod → Expired

### 测试基础设施

- `testdata/` 目录：测试密钥对、mock /proc /sys 文件
- 测试密钥对固定，存放于 `internal/crypto/testdata/`，供所有测试引用
- GracePeriod 时间控制通过 `now` 参数注入，不依赖 `time.Now()`

## 7. 构建与分发

### Makefile 目标

```makefile
.PHONY: build test lint

build: build-fingerprint build-license-gen

build-fingerprint:
	CGO_ENABLED=0 go build -o bin/fingerprint ./cmd/fingerprint

build-license-gen:
	CGO_ENABLED=0 go build -o bin/license-gen ./cmd/license-gen

test:
	go test ./...

lint:
	golangci-lint run ./...
```

### 分发方式

- `fingerprint` 和 `license-gen` 作为静态链接二进制分发（`CGO_ENABLED=0`）
- SDK 通过 `go get` 或 vendor 方式集成到应用中
- 不提供 Docker 镜像（由应用方自行将 SDK 集成到其容器镜像中）
