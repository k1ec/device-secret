# 设备安全认证方案 — 系统需求规格 (SysRS)

## 1. 业务背景

公司产品以程序形式部署在客户的工控机/服务器上，存在被第三方非法拷贝到未授权机器运行的风险。需要一套软件 License 方案，将程序绑定到指定设备，防止未授权运行，保护公司核心资产。

## 2. 运行环境

| 维度 | 说明 |
|---|---|
| **编程语言** | Go |
| **目标平台** | Linux x86_64 / ARM (RK3568 为主) |
| **设备类型** | 工控机、服务器（核心板+底板架构） |
| **部署方式** | Docker 容器化，docker-compose 编排，Ansible 批量安装 |
| **网络环境** | 常规离线运行（如变电站内网），无公网访问 |
| **安全硬件** | 初期不考虑 TPM/加密芯片，基于软件指纹方案 |

## 3. 功能需求

### 3.1 设备指纹采集

- 指纹采集工具运行在**宿主机**上（非容器内）
- 采集信息分为两类：
  - **设备元信息（记录存档）**：主机名（`hostname`）— 仅供签发时识别设备，不参与指纹哈希计算
  - **硬件指纹因子（参与哈希绑定）**，按平台自动适配：

| 来源 | ARM (RK3568) | x86 (浪潮服务器等) | 说明 |
|---|---|---|---|
| `/etc/machine-id` | ✅ 总是可用 | ✅ 总是可用 | systemd 安装时生成，全局唯一 |
| CPU Serial (`/proc/cpuinfo`) | ✅ `Serial` 字段 | ❌ x86 不暴露 Serial | ARM 平台核心唯一 ID |
| DMI 产品序列号 | ❌ 通常为空 | ✅ `/sys/class/dmi/id/product_serial` | x86 主板唯一 ID |
| DMI 系统 UUID | ❌ 通常为空 | ✅ `/sys/class/dmi/id/product_uuid` | x86 系统唯一标识 |
| 物理网卡 MAC | ✅ | ✅ | 排除虚拟接口（docker/veth/lo/br），适配 `eth*`/`ens*`/`enp*` |
| eMMC CID | ✅ `/sys/block/mmcblk*/device/cid` | ❌ 通常无 eMMC | 存储芯片唯一 ID |
- **唯一性保障**：`processor`/`model name` 等非唯一信息**不纳入指纹**，确保每台设备至少命中 2-3 个独立唯一因子
- 支持部分因子缺失，采集到足够项数即可生成有效指纹
- 输出标准化的**请求文件**（JSON 格式），供 License 签发使用

### 3.2 License 签发

- 在独立的安全签发机上运行
- 输入：设备请求文件 + 签发参数（有效期等）
- 使用 **Ed25519** 私钥对 License 内容进行签名
- 输出 License 文件，通过 U 盘/Ansible 等方式分发到目标设备

### 3.3 License 校验 (SDK)

- 以 Go SDK 库形式嵌入各应用程序
- 读取 License 文件，使用**公钥**验签
- 比对设备指纹，确认运行环境与授权设备一致
- 校验有效期，确认未过期
- 校验失败后进入**宽限期**（默认 7 天），持续告警，超期后拒绝启动/停止服务

### 3.4 License 内容

- **基础模式**：设备指纹哈希 + 有效期（到期时间戳）
- **可扩展**：预留功能模块授权字段，支持未来按模块控制功能可用性

## 4. 安全需求

### 4.1 密码学方案

符合 **OWASP 2026** 对新项目的推荐要求：

| 环节 | 算法 | 安全强度 |
|---|---|---|
| 签名密钥对 | **Ed25519** | ~128-bit |
| 哈希 | **SHA-256** | 128-bit 抗碰撞 |
| 编码 | **Base64 URL-safe** | — |

**选型理由**：Ed25519 确定性签名，无 ECDSA nonce 重用风险；Go `crypto/ed25519` 标准库原生支持，零外部依赖；签名固定 64 字节，紧凑高效。

### 4.2 安全约束

| 需求 | 说明 |
|---|---|
| **完整性保护** | License 内容经 Ed25519 私钥签名，设备端公钥验签，防篡改 |
| **防重放/克隆** | License 绑定唯一设备指纹哈希，拷贝到其他设备指纹不匹配则拒绝 |
| **私钥安全** | Ed25519 私钥仅存在于签发机，不分发到设备端 |
| **公钥保护** | 公钥编译进 SDK 或随应用镜像分发，泄露不影响签名伪造 |
| **密钥轮换** | License 预留 `kid`（Key ID）字段。公钥文件按 `<kid>.pem` 命名放在源码 `keys/` 目录，通过 `//go:embed` 编译嵌入。更换签发密钥时，新 License 带新 `kid` 用新私钥签名，旧 License 的 `kid` 指向旧公钥持续有效。`default.pem` 为无 `kid` 的旧 License 提供向后兼容。`kid` 格式：`^[a-zA-Z0-9_-]{1,64}$` |

## 5. 非功能需求

| 维度 | 说明 |
|---|---|
| **离线运行** | License 校验过程完全离线，无任何网络请求 |
| **性能** | SDK 校验为启动时一次性操作，对运行时性能零影响 |
| **可靠性** | 宽限期机制确保因硬件微小变化导致的指纹偏差不会立即中断业务 |
| **易集成** | SDK API 简洁，最小化对应用代码的侵入 |
| **可扩展** | License 文件格式预留字段，支持未来增加功能模块授权等能力 |

## 6. 架构方案

采用 **CLI 工具组 + SDK 库** 架构。

### 6.1 数据流

**安装阶段：**

```
目标宿主机                                  签发机（安全环境）
  │                                          │
  ├─ fingerprint CLI                         │
  │  采集硬件指纹                             │
  │  → request.json ────(U盘/Ansible)───────▶├─ license-gen CLI
  │                                          │  读取 request.json
  │                                          │  + 签发参数（有效期等）
  │                                          │  + Ed25519 私钥签名
  │                                          │  → license.bin
  │                                          │
  ├─ ←─── license.bin ────(U盘/Ansible)──────┘
  │  放入 /host/license/（bind mount 供容器读取）
```

**运行时阶段（应用容器内 SDK）：**

```
SDK.Init()
  │
  ├─ 1. 读取 /license/license.bin
  ├─ 2. Ed25519 公钥验签 ──── 确认 license 未被篡改
  ├─ 3. 采集宿主机硬件指纹 ── 通过容器挂载的 /proc、/sys 等宿主机路径
  ├─ 4. 比对指纹哈希 ──────── 确认「当前设备」=「授权设备」
  ├─ 5. 检查有效期 ────────── 确认未到期
  └─ 6. 管理宽限期状态 ────── 持久化到挂载卷（防重启重置）
          │
SDK.Verify() → Valid / GracePeriod / Expired / Invalid
```

**核心安全逻辑**：SDK 每次校验时**重新采集指纹**并计算哈希，与 license 中的 `device_hash` 比对。即使 license 文件被拷贝到未授权设备，指纹不匹配则校验失败。这是防拷贝的根本保障。

### 6.2 三个制品

| 制品 | 运行位置 | 角色 |
|---|---|---|
| `fingerprint` CLI | 目标宿主机 | 采集硬件指纹，输出标准化请求文件 |
| `license-gen` CLI | 签发机（安全环境） | 读取请求文件 + 签发参数 → Ed25519 私钥签名 → license 文件 |
| `device-secret` SDK | 应用容器内 | 公钥验签 + 指纹匹配 + 宽限期管理 |

### 6.3 核心安全边界

- 私钥永不离签发机
- SDK 和 fingerprint 仅携带公钥
- 请求文件与 license 文件通过人工/Ansible 传输，工具不关心传输方式
- SDK 只做校验决策，不修改 license、不联网

### 6.4 项目结构

遵循 Go 社区标准布局（`golang-standards/project-layout`）：

```
device-secret/
├── keys/                        # 公钥文件（编译时嵌入）
│   ├── default.pem              #   当前活跃签发公钥（匹配无 kid 旧 License）
│   └── <kid>.pem                #   历史/轮换公钥（kid 匹配）
├── cmd/
│   ├── fingerprint/
│   │   └── main.go              # 指纹采集 CLI 入口
│   └── license-gen/
│       └── main.go              # License 签发 CLI 入口
├── internal/                    # 私有实现（编译器强制不可外部 import）
│   ├── crypto/                  # Ed25519 密钥管理
│   │   ├── keys.go              #   密钥对生成、PEM 读写
│   │   └── keys_test.go
│   ├── fingerprint/             # 指纹采集逻辑
│   │   ├── collector.go         #   硬件信息采集入口
│   │   ├── sources.go           #   按平台适配的采集实现
│   │   ├── hash.go              #   指纹哈希生成
│   │   ├── testdata/            #   mock /proc /sys 文件
│   │   └── collector_test.go
│   ├── license/                 # License 数据结构与签名
│   │   ├── format.go            #   请求文件 / License 格式定义
│   │   ├── sign.go              #   Ed25519 签名
│   │   └── verify.go            #   Ed25519 验签
│   └── grace/                   # 宽限期状态机
│       ├── grace.go             #   状态转换 + 持久化标记
│       └── grace_test.go
├── pkg/
│   └── sdk/                     # 公共 API（应用集成唯一入口）
│       ├── sdk.go               #   Init / Verify / LicenseInfo
│       └── sdk_test.go
├── build/                       # CI / Dockerfile
├── docs/
│   └── SysRS-device-secret.md
├── go.mod
├── go.sum
└── Makefile
```

**模块依赖关系：**

```
cmd/fingerprint ──▶ internal/fingerprint
cmd/license-gen  ──▶ internal/license ──▶ internal/crypto
pkg/sdk          ──▶ internal/fingerprint + internal/license + internal/grace
```

- `internal/*`：CLI 和 SDK 的共享实现，编译器强制外部不可引用
- `pkg/sdk`：唯一的公共 API，应用方只需 `import "device-secret/pkg/sdk"`

### 6.5 SDK API 概览

```go
//go:embed keys/*.pem
var keyFS embed.FS

// 初始化
sdk, err := devicesecret.Init(Config{
    LicensePath: "/license/license",
    KeyFS:       keyFS,
})

// 校验
result := sdk.Verify()
// result.Status: Valid | GracePeriod | Expired | Invalid

// 查询
info := sdk.LicenseInfo()  // 有效期、功能模块等
```

**宽限期状态机：**

```
          首次校验失败
    Valid ─────────────▶ GracePeriod
      ▲                      │
      │  License 更新         │ 宽限期耗尽
      │                      ▼
      │                  Expired (硬拒绝)
```

### 6.6 文件格式

**请求文件 (`request.json`)：**

```json
{
  "version": 1,
  "device": {
    "hostname": "substation-gateway-03",
    "os": "linux",
    "arch": "arm64"
  },
  "fingerprint": {
    "sources": {
      "machine_id": "a1b2c3d4...",
      "cpu_serial": "RK3568-xxx",
      "macs": ["aa:bb:cc:dd:ee:ff"],
      "product_serial": "",
      "product_uuid": "",
      "emmc_cid": ""
    },
    "hash": "sha256:a1b2c3d4e5f6..."
  },
  "requested_at": "2026-08-11T10:00:00Z"
}
```

- `device.hostname`：纯记录存档，不参与指纹哈希
- `fingerprint.sources`：原始采集值（缺失为空），签发者可审核
- `fingerprint.hash`：SHA-256(按 key 排序的 sources 序列化结果)

**License 文件：**

```json
{
  "version": 1,
  "kid": "2026-primary",
  "device_hash": "sha256:a1b2c3d4e5f6...",
  "issued_at": "2026-08-11T00:00:00Z",
  "expires_at": "2027-08-11T00:00:00Z",
  "features": null,
  "metadata": "可选备注"
}
```

- `kid`：密钥 ID，SDK 据此选择对应公钥验签。格式 `^[a-zA-Z0-9_-]{1,64}$`，文件命名 `<kid>.pem`
- `features`：`null` 表示全功能，未来扩展为 `["module_a"]`
- 最终文件：`base64(紧凑JSON).base64(Ed25519签名)`

## 7. 术语

| 术语 | 说明 |
|---|---|
| **设备指纹** | 由多项硬件唯一标识组合而成的设备唯一标识 |
| **请求文件** | fingerprint 工具输出的标准化 JSON，包含设备指纹和元信息 |
| **License 文件** | 签发机生成的已签名授权文件 |
| **宽限期** | 校验失败后允许继续运行的缓冲期，超期后拒绝服务 |
| **签发机** | 保管 Ed25519 私钥、执行 License 签发的安全环境 |
