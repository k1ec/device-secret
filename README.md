# device-secret

基于硬件指纹和 Ed25519 签名的软件许可系统，将应用绑定到特定 Linux 设备，防止未经授权的复制和分发。适用于离线嵌入式及服务器环境。

## 原理

系统分为**密钥准备**、**安装阶段**和**运行时阶段**三个环节。

### 密钥准备（一次性）

在安全签发机上生成 Ed25519 密钥对，私钥永不离签发机，公钥嵌入应用：

```
keygen → private.pem（签发机保管） + public.pem（嵌入应用/SDK）
```

### 安装阶段 — License 签发数据流

```
目标宿主机                                    签发机（安全环境）
  │                                              │
  ├─ fingerprint CLI                             │
  │   采集 /proc、/sys 等硬件信息                  │
  │   → request.json ────(U盘/Ansible)──────────▶├─ license-gen CLI
  │                                              │   读取 request.json
  │                                              │   + 签发参数（有效期等）
  │                                              │   + Ed25519 私钥签名
  │                                              │   → license
  │                                              │
  ├─ ◀──── license ────(U盘/Ansible)─────────────┘
  │   放入 /host/license/
  │   （通过 bind mount 供容器读取）
```

1. 目标宿主机运行 `fingerprint`，采集 `machine-id`、CPU 序列号、MAC 地址、eMMC CID 等硬件唯一标识，输出标准化的 `request.json`
2. 通过 U 盘或 Ansible 将请求文件传递到签发机
3. 签发机运行 `license-gen`，读取请求文件中的设备指纹哈希，加上有效期等参数，用 Ed25519 私钥签名，生成 `license` 文件
4. license 文件回传到目标设备，放在宿主机目录，通过 bind mount 供容器读取

### 运行时阶段 — SDK 校验流程

应用容器内 SDK 的校验过程：

```
SDK.Init()
  │
  ├─ 1. 读取 /license/license
  ├─ 2. Ed25519 公钥验签 ──── 确认 license 未被篡改
  ├─ 3. 采集宿主机硬件指纹 ── 通过容器挂载的 /proc、/sys（宿主机路径）
  ├─ 4. 比对指纹哈希 ──────── 确认「当前设备」=「授权设备」
  ├─ 5. 检查有效期 ────────── 确认未到期
  └─ 6. 管理宽限期状态 ────── 持久化到挂载卷（防重启重置）
          │
SDK.Verify() → Valid / GracePeriod / Expired / Invalid
```

**核心安全逻辑**：SDK 每次 `Verify()` 都**重新采集硬件指纹**并计算哈希，与 license 中的 `device_hash` 实时比对。即使 license 文件被完整拷贝到未授权设备，因硬件指纹不匹配，校验必然失败。这是防拷贝的根本保障。

## 环境要求

- **Go 1.25+**（`crypto/ed25519` 需要）
- 目标平台：Linux x86_64 或 ARM64（如 RK3568）
- 编译要求 `CGO_ENABLED=0`（静态二进制）

## 构建

```bash
# 本机构建（开发机通常是 macOS）
make build

# 交叉编译 Linux 目标
make build-linux-arm64    # → bin/linux-arm64/
make build-linux-amd64    # → bin/linux-amd64/

# 全平台构建
make build-all

# 清理构建产物
make clean
```

## 快速开始

### 1. 生成密钥

```bash
./bin/keygen -out private.pem -pub public.pem
# 私钥: private.pem
# 公钥: public.pem
```

**私钥**妥善保管在签发机上，**公钥**嵌入目标应用。

### 2. 采集设备指纹

在目标 Linux 设备上运行：

```bash
./fingerprint -o request.json -pretty
```

生成 `request.json`：
```json
{
  "version": 1,
  "device": {
    "hostname": "edge-node-01",
    "os": "linux",
    "arch": "arm64"
  },
  "fingerprint": {
    "sources": {
      "machine_id": "abc123...",
      "cpu_serial": "000000004f6e8a3d",
      "macs": "00:1a:2b:3c:4d:5e",
      "emmc_cid": "1501004a4e4234324200..."
    },
    "hash": "sha256:e3b0c44298fc1c149afbf4c8996fb924..."
  },
  "requested_at": "2026-08-12T12:00:00Z"
}
```

### 3. 签发 License

在签发机上运行：

```bash
./license-gen \
  -request request.json \
  -key private.pem \
  -expires +365d \
  -features "module-a,module-b" \
  -metadata "客户: Acme Corp" \
  -kid key-2026-v1 \
  -o license
```

`-expires` 支持相对时间（`+365d`、`+30d`）和 ISO8601 格式（`2027-08-12T00:00:00Z`、`2027-08-12`）。

### 4. 应用内集成 SDK

```go
package main

import (
    "os"
    "device-secret/pkg/sdk"
)

func main() {
    pubKey, _ := os.ReadFile("public.pem")

    lic, err := sdk.Init(sdk.Config{
        LicensePath: "/etc/myapp/license",
        PublicKey:   pubKey,
    })
    if err != nil {
        panic(err)
    }

    result := lic.Verify()
    switch result.Status {
    case sdk.StatusValid:
        // 许可有效，正常运行
    case sdk.StatusGracePeriod:
        // 宽限期内，放行但告警
    case sdk.StatusExpired:
        // 宽限期已耗尽，阻断
    case sdk.StatusInvalid:
        // 签名无效，阻断
    }
}
```

### 5. 部署与运维建议

#### 周期性校验

**不要仅在应用启动时调用一次 `Verify()`。** 如果启动时 License 有效，应用可能持续运行数周直到 License 过期而不自知。建议：

```go
// 启动时强制校验
result := lic.Verify()
if result.Status != sdk.StatusValid {
    log.Fatalf("license check failed: %s", result.Message)
}

// 运行时每天至少校验一次
go func() {
    ticker := time.NewTicker(24 * time.Hour)
    defer ticker.Stop()
    for range ticker.C {
        result := lic.Verify()
        switch result.Status {
        case sdk.StatusValid:
            // 一切正常
        case sdk.StatusGracePeriod:
            log.Printf("WARNING: 进入宽限期——%s", result.Message)
        default:
            log.Printf("CRITICAL: 许可失效——%s", result.Message)
            // 根据业务需要决定是否退出
            os.Exit(1)
        }
    }
}()
```

周期性校验确保应用在运行期间能及时发现 License 过期，而不是等到下次重启才暴露问题。

#### 容器权限加固

宽限期状态依赖 marker 文件 `/var/lib/device-secret/.grace_start` 持久化。有 root 权限的用户可以通过删除该文件无限重置宽限期。虽然软件层面无法根本防御有 root 权限的攻击者，但可以通过以下措施提高门槛：

- **以非 root 用户运行容器**，限制对 marker 文件所在目录的写权限
- 应用只需对 `/var/lib/device-secret/` 目录有读写权限即可，无需 root
- marker 文件所在目录通过 bind mount 挂载到宿主机持久卷，确保重启不丢失

```yaml
# docker-compose.yml 示例
services:
  myapp:
    user: "1000:1000"                        # 非 root 运行
    read_only: true                          # 容器文件系统只读
    volumes:
      - /host/license:/license:ro            # license 只读挂载
      - /host/data/grace:/var/lib/device-secret  # marker 目录可写
```

## 项目结构

```
cmd/
├── fingerprint/     采集硬件指纹的 CLI 工具
├── keygen/          生成 Ed25519 密钥对的 CLI 工具
└── license-gen/     签发 License 的 CLI 工具
pkg/
└── sdk/             公开的嵌入式 SDK，供应用集成
internal/
├── crypto/          Ed25519 密钥生成、PEM 编解码、签名/验签
├── fingerprint/     硬件信息采集与指纹哈希计算
├── grace/           宽限期状态机（基于 marker 文件）
└── license/         License 数据模型、签名与校验
```

| 包 | 可见性 | 用途 |
|---|---|---|
| `pkg/sdk` | 公开 | 嵌入式许可校验 API |
| `internal/crypto` | 内部 | Ed25519 密钥操作（标准库） |
| `internal/fingerprint` | 内部 | 硬件指纹采集与哈希 |
| `internal/license` | 内部 | License 数据模型、签发与校验 |
| `internal/grace` | 内部 | 宽限期状态机 |

## 指纹采集源

指纹采集器从目标 Linux 设备的以下路径读取硬件信息。至少需要 **2 个非空来源** 才能生成有效指纹。

| 来源 | 路径 | 说明 |
|---|---|---|
| `machine_id` | `/etc/machine-id` | 所有 systemd 系统都存在 |
| `cpu_serial` | `/proc/cpuinfo` | `Serial` 字段（ARM SoC） |
| `product_serial` | `/sys/class/dmi/id/product_serial` | x86 DMI；过滤 "To be filled by O.E.M." 等无效值 |
| `product_uuid` | `/sys/class/dmi/id/product_uuid` | x86 DMI |
| `macs` | `/sys/class/net/*/address` | 仅物理网卡（过滤 `lo`、`docker*`、`veth*` 等虚拟接口） |
| `emmc_cid` | `/sys/block/mmcblk*/device/cid` | eMMC 闪存 CID（ARM 嵌入式板卡） |

## License 格式

```
base64url(JSON载荷).base64url(Ed25519签名)
```

- 编码：URL 安全 Base64，无填充（`base64.URLEncoding.WithPadding(base64.NoPadding)`）
- 签名：对 JSON 载荷字节做 Ed25519 签名

载荷字段：

| 字段 | 类型 | 说明 |
|---|---|---|
| `version` | int | 协议版本（当前为 `1`） |
| `kid` | string | 密钥 ID，支持密钥轮换 |
| `device_hash` | string | 设备指纹的 `sha256:...` 哈希值 |
| `issued_at` | RFC3339 | 签发时间 |
| `expires_at` | RFC3339 | 过期时间 |
| `features` | []string | 可选的特性模块列表 |
| `metadata` | string | 自由格式的备注信息 |

## 宽限期

当 `Verify()` 校验失败（硬件指纹不匹配、License 过期或两者同时）时，SDK 不会立即拒绝，而是进入**宽限期**：

- 在 `/var/lib/device-secret/.grace_start` 写入一个时间戳 marker 文件
- 后续 `Verify()` 调用在配置的宽限期内继续放行
- 宽限期耗尽后，`Verify()` 返回 `StatusExpired`
- 一旦某次 `Verify()` 成功，marker 文件被清除，退出宽限期

默认宽限期：**30 天**。通过 `Config.GraceDuration` 可自定义。

## 设计约束

- **零第三方依赖**——仅使用 Go 标准库
- **静态编译**——所有构建均设 `CGO_ENABLED=0`
- **SDK 永不 panic**——所有公开函数通过 error 返回错误
- **离线运行**——校验过程不发起任何网络请求
- **密钥轮换**——`kid` 字段支持更换签发密钥而不影响已签发的 License

## 安全性

- 私钥永不离开签发机；SDK 和 fingerprint CLI 仅嵌入公钥
- SDK 每次 `Verify()` 都重新采集设备指纹，与 License 中的 `device_hash` 实时比对
- 将 License 文件拷贝到另一台机器会因硬件哈希不匹配而失败
- 所有签名使用 Ed25519（Go 标准库 `crypto/ed25519`）
- Base64 使用 URL 安全编码，无填充

### 已知局限

宽限期 marker 文件 `/var/lib/device-secret/.grace_start` 是宽限期状态的唯一持久化存储。拥有 root 权限的用户删除该文件可重置宽限期计时，理论上实现无限期宽限。

**缓解措施：**
- 容器以非 root 用户运行（见上文部署建议）
- 应用周期性调用 `Verify()` 而非仅启动时校验
- License 有效期 + 设备指纹绑定是主要防线，宽限期是辅助容错机制

在不引入 TPM/安全硬件的纯软件方案中，root 用户总能找到绕过手段。部署时应将资源投入在最小化攻击面（最小权限、只读文件系统）上，而非追求软件层面的绝对防御。

## 测试

```bash
# 单元测试
make test

# 代码检查
make lint

# 集成测试（需要在真实 Linux 硬件上运行）
go test -tags=integration ./...
```

## License

[在此处填写你的协议]
