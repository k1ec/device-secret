# 待办事项

## 平台验证

以下验证需要在真实 Linux 设备上执行（macOS 缺少 `/proc`、`/sys` 等 Linux 特定路径，指纹采集无法运行）。

### RK3568 ARM 平台

- [ ] 编译 ARM64 二进制：`GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o bin/fingerprint-arm64 ./cmd/fingerprint`
- [ ] 在 RK3568 设备上运行 `fingerprint` 采集指纹，确认下列因子非空：
  - `machine_id`
  - `cpu_serial`（RK3568 `/proc/cpuinfo` 的 `Serial` 字段）
  - `macs`（物理网卡 MAC，排除虚拟接口）
  - `emmc_cid`
- [ ] 连续采集两次，确认 `fingerprint.hash` 完全一致（确定性验证）
- [ ] 全链路闭环：fingerprint → license-gen → SDK Verify() → `Status: Valid`

### x86 浪潮服务器

- [ ] 编译 x86_64 二进制：`GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bin/fingerprint-amd64 ./cmd/fingerprint`
- [ ] 在浪潮服务器上运行 `fingerprint` 采集指纹，确认下列因子非空：
  - `machine_id`
  - `product_serial`（`/sys/class/dmi/id/product_serial`）
  - `product_uuid`（`/sys/class/dmi/id/product_uuid`）
  - `macs`（物理网卡 MAC，如 `ens1f1`、`ens3f0`）
- [ ] 连续采集两次，确认 `fingerprint.hash` 完全一致
- [ ] 全链路闭环：fingerprint → license-gen → SDK Verify() → `Status: Valid`

## 负面测试

- [ ] 篡改 license 文件中任意 1 字节 → SDK Verify() 返回 `StatusInvalid`
- [ ] A 设备 license 文件拷贝到 B 设备 → SDK Verify() 返回 `StatusInvalid`（指纹不匹配）
- [ ] 过期 license → SDK Verify() 进入 `StatusGracePeriod`，超期后返回 `StatusExpired`
- [ ] 宽限期持久化：GracePeriod 期间重启应用 → 宽限期计时不重置
- [ ] 有效因子不足测试：在缺少 `/etc/machine-id` 等关键文件的环境下运行 fingerprint → 退出码 1

## 集成测试

- [ ] 运行 `go test -tags=integration ./internal/fingerprint/ -v`（在 Linux 真机上，已用 build tag 排除 macOS）
- [ ] Ansible 部署流程集成：指纹采集 → 请求文件 → 签发 → license 文件分发 → docker-compose 挂载

## 后续优化

- [ ] 生产环境 Ed25519 密钥对生成并安全保管（当前 `keygen` 仅用于测试）
- [ ] 评估是否需要增加 K8s flannel 等虚拟网卡的过滤规则（当前正则 `flannel\w+` 可能遗漏 `flannel.1` 等变体）
- [ ] `+Nd` 相对过期时间携带签发机本地时区偏移，生产签发建议使用 ISO8601 绝对时间
