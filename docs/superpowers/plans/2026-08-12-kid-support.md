# SDK 多公钥支持（kid-based Key Selection）— 实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** SDK 支持通过 License 的 `kid` 字段选择对应公钥验签，实现平滑密钥轮换。

**Architecture:** 公钥通过 Go `embed` 在编译时嵌入二进制（非运行时加载文件）。`internal/license` 新增 `PeekKID` 预读 kid，`pkg/sdk` 新增 `loadKeys` 从 `fs.FS` 构建 kid→公钥映射表，`Init()` 根据 kid 选公钥验签。向后兼容单公钥模式。

**Tech Stack:** Go 1.26+, stdlib only (`crypto/ed25519`, `embed`, `io/fs`, `testing/fstest`)

**Design Spec:** `docs/superpowers/specs/2026-08-12-kid-support-design.md`

## Global Constraints

- 零第三方依赖 — 仅 Go 标准库
- `CGO_ENABLED=0` 静态编译
- SDK 所有公开函数返回 error，永不 panic
- 向后兼容：现有 `Config.PublicKey` 单公钥模式行为不变
- kid 格式：`^[a-zA-Z0-9_-]{1,64}$`
- PEM 类型：`ED25519 PUBLIC KEY`

---

### Task 1: `internal/license` — PeekKID 函数

**Files:**
- Modify: `internal/license/verify.go` — 新增 `PeekKID`
- Modify: `internal/license/license_test.go` — 新增 3 个测试

**Interfaces:**
- Produces: `func PeekKID(licenseData []byte) (string, error)` — 不解签，仅提取 kid
- Consumes: 无（纯 stdlib base64 + json）

- [ ] **Step 1: 在 license_test.go 中编写 PeekKID 的三个测试**

在 `internal/license/license_test.go` 末尾追加：

```go
func TestPeekKID_WithKID(t *testing.T) {
	priv, _ := testKeyPair(t)
	payload := LicensePayload{
		Version:    1,
		KID:        "2026-primary",
		DeviceHash: "sha256:abcdef123456",
		ExpiresAt:  time.Now().Add(365 * 24 * time.Hour),
	}
	data, err := SignLicense(payload, priv)
	if err != nil {
		t.Fatalf("SignLicense() error = %v", err)
	}

	kid, err := PeekKID(data)
	if err != nil {
		t.Fatalf("PeekKID() error = %v", err)
	}
	if kid != "2026-primary" {
		t.Errorf("PeekKID() = %q, want %q", kid, "2026-primary")
	}
}

func TestPeekKID_NoKID(t *testing.T) {
	priv, _ := testKeyPair(t)
	payload := LicensePayload{
		Version:    1,
		DeviceHash: "sha256:abcdef123456",
		ExpiresAt:  time.Now().Add(365 * 24 * time.Hour),
		// KID 未设置
	}
	data, err := SignLicense(payload, priv)
	if err != nil {
		t.Fatalf("SignLicense() error = %v", err)
	}

	kid, err := PeekKID(data)
	if err != nil {
		t.Fatalf("PeekKID() error = %v", err)
	}
	if kid != "" {
		t.Errorf("PeekKID() = %q, want empty string", kid)
	}
}

func TestPeekKID_InvalidBase64(t *testing.T) {
	_, err := PeekKID([]byte("!!!!not-valid-base64!!!!"))
	if err == nil {
		t.Error("PeekKID() expected error for invalid base64 input")
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

```bash
go test ./internal/license/ -run TestPeekKID -v
```

预期：`undefined: PeekKID` 编译错误。

- [ ] **Step 3: 在 verify.go 中实现 PeekKID**

在 `internal/license/verify.go` 文件末尾追加：

```go
// PeekKID extracts the kid field from a license without verifying the
// signature. This allows Init to select the correct public key before
// performing full verification.
func PeekKID(licenseData []byte) (string, error) {
	parts := strings.SplitN(string(licenseData), ".", 2)
	if len(parts) != 2 {
		return "", ErrInvalidFormat
	}

	encoded := base64.URLEncoding.WithPadding(base64.NoPadding)
	jsonBytes, err := encoded.DecodeString(parts[0])
	if err != nil {
		return "", ErrInvalidFormat
	}

	var payload LicensePayload
	if err := json.Unmarshal(jsonBytes, &payload); err != nil {
		return "", ErrInvalidFormat
	}
	return payload.KID, nil
}
```

- [ ] **Step 4: 运行测试确认通过**

```bash
go test ./internal/license/ -run TestPeekKID -v
```

预期：3 个测试全部 PASS。

- [ ] **Step 5: 确认已有测试未破坏**

```bash
go test ./internal/license/ -v
```

预期：全部 PASS。

- [ ] **Step 6: Commit**

```bash
git add internal/license/verify.go internal/license/license_test.go
git commit -m "feat: add PeekKID to extract kid from license without verifying signature

PeekKID decodes the base64 payload and returns the kid field,
enabling the SDK to select the correct public key before full
signature verification.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 2: `pkg/sdk` — loadKeys 函数

**Files:**
- Create: `pkg/sdk/keys.go` — `loadKeys` 实现 + `validKidRE` 正则
- Create: `pkg/sdk/keys_test.go` — 5 个测试

**Interfaces:**
- Produces: `func loadKeys(keyFS fs.FS) (map[string]ed25519.PublicKey, error)`
- Consumes: `device-secret/internal/crypto.ParsePublicKey`（已有）

- [ ] **Step 1: 创建 keys_test.go，编写 5 个 loadKeys 测试**

创建 `pkg/sdk/keys_test.go`：

```go
package sdk

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
)

func testPEMBytes(t *testing.T) []byte {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "ED25519 PUBLIC KEY", Bytes: pub})
}

func TestLoadKeys_SingleDefault(t *testing.T) {
	pemBytes := testPEMBytes(t)
	mapFS := fstest.MapFS{
		"default.pem": &fstest.MapFile{Data: pemBytes},
	}
	keys, err := loadKeys(mapFS)
	if err != nil {
		t.Fatalf("loadKeys() error = %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if _, ok := keys[""]; !ok {
		t.Error(`expected key with kid="" from default.pem`)
	}
}

func TestLoadKeys_MultipleKids(t *testing.T) {
	pem1 := testPEMBytes(t)
	pem2 := testPEMBytes(t)
	pem3 := testPEMBytes(t)
	mapFS := fstest.MapFS{
		"default.pem":       &fstest.MapFile{Data: pem1},
		"2026-primary.pem":  &fstest.MapFile{Data: pem2},
		"2027-rotation.pem": &fstest.MapFile{Data: pem3},
	}
	keys, err := loadKeys(mapFS)
	if err != nil {
		t.Fatalf("loadKeys() error = %v", err)
	}
	if len(keys) != 3 {
		t.Fatalf("expected 3 keys, got %d", len(keys))
	}
	for _, kid := range []string{"", "2026-primary", "2027-rotation"} {
		if _, ok := keys[kid]; !ok {
			t.Errorf("missing key for kid %q", kid)
		}
	}
}

func TestLoadKeys_InvalidKidName(t *testing.T) {
	pemBytes := testPEMBytes(t)
	badNames := []string{
		"../evil.pem",
		"has space.pem",
		".pem",
		"kid=bad.pem",
	}
	for _, name := range badNames {
		mapFS := fstest.MapFS{
			name: &fstest.MapFile{Data: pemBytes},
		}
		_, err := loadKeys(mapFS)
		if err == nil {
			t.Errorf("loadKeys(%q) expected error for invalid kid name", name)
		}
	}
}

func TestLoadKeys_InvalidPEM(t *testing.T) {
	mapFS := fstest.MapFS{
		"default.pem": &fstest.MapFile{Data: []byte("not valid pem")},
	}
	_, err := loadKeys(mapFS)
	if err == nil {
		t.Error("loadKeys() expected error for invalid PEM content")
	}
}

func TestLoadKeys_EmptyDir(t *testing.T) {
	mapFS := fstest.MapFS{}
	_, err := loadKeys(mapFS)
	if err == nil {
		t.Error("loadKeys() expected error for empty directory")
	}
}

func TestLoadKeys_DuplicateKid(t *testing.T) {
	pem1 := testPEMBytes(t)
	pem2 := testPEMBytes(t)
	mapFS := fstest.MapFS{
		"2026.pem":          &fstest.MapFile{Data: pem1},
		"2026-primary.pem":  &fstest.MapFile{Data: pem2},
	}
	keys, err := loadKeys(mapFS)
	if err != nil {
		t.Fatalf("loadKeys() error = %v", err)
	}
	if len(keys) != 2 {
		t.Errorf("different filenames produce different kids, expected 2 keys, got %d", len(keys))
	}
}

func TestLoadKeys_NonPEMIgnored(t *testing.T) {
	pemBytes := testPEMBytes(t)
	mapFS := fstest.MapFS{
		"default.pem":  &fstest.MapFile{Data: pemBytes},
		"README.txt":   &fstest.MapFile{Data: []byte("not a key")},
		"notes.md":     &fstest.MapFile{Data: []byte("# notes")},
	}
	keys, err := loadKeys(mapFS)
	if err != nil {
		t.Fatalf("loadKeys() error = %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("non-.pem files should be ignored, got %d keys", len(keys))
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

```bash
go test ./pkg/sdk/ -run TestLoadKeys -v
```

预期：`undefined: loadKeys` 编译错误。

- [ ] **Step 3: 创建 keys.go，实现 loadKeys**

创建 `pkg/sdk/keys.go`：

```go
package sdk

import (
	"crypto/ed25519"
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"

	"device-secret/internal/crypto"
)

// validKidRE defines the allowed characters and length for a kid.
// Must match ^[a-zA-Z0-9_-]{1,64}$
var validKidRE = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

// loadKeys scans an fs.FS for *.pem files, extracts the kid from each
// filename (name without .pem extension; "default" maps to ""), and
// returns a map from kid to parsed Ed25519 public key.
func loadKeys(keyFS fs.FS) (map[string]ed25519.PublicKey, error) {
	entries, err := fs.ReadDir(keyFS, ".")
	if err != nil {
		return nil, fmt.Errorf("cannot read key directory: %w", err)
	}

	keys := make(map[string]ed25519.PublicKey)
	hasPEM := false

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if filepath.Ext(name) != ".pem" {
			continue
		}

		hasPEM = true
		kid := strings.TrimSuffix(name, ".pem")

		// "default" maps to empty-string kid (matches licenses without kid)
		if kid == "default" {
			kid = ""
		} else if !validKidRE.MatchString(kid) {
			return nil, fmt.Errorf("invalid kid %q in key file %q: must match %s", kid, name, validKidRE.String())
		}

		if _, exists := keys[kid]; exists {
			return nil, fmt.Errorf("duplicate kid %q", kid)
		}

		pemBytes, err := fs.ReadFile(keyFS, name)
		if err != nil {
			return nil, fmt.Errorf("cannot read key file %q: %w", name, err)
		}

		pubKey, err := crypto.ParsePublicKey(pemBytes)
		if err != nil {
			return nil, fmt.Errorf("invalid PEM in key file %q: %w", name, err)
		}

		keys[kid] = pubKey
	}

	if !hasPEM {
		return nil, fmt.Errorf("no key files found in KeyFS")
	}

	return keys, nil
}
```

- [ ] **Step 4: 运行测试确认通过**

```bash
go test ./pkg/sdk/ -run TestLoadKeys -v
```

预期：全部 PASS。

- [ ] **Step 5: Commit**

```bash
git add pkg/sdk/keys.go pkg/sdk/keys_test.go
git commit -m "feat: add loadKeys to load kid→public-key map from embed.FS

Scans *.pem files, validates kid naming convention, parses ED25519
public keys. 'default.pem' maps to empty-string kid for backward
compatibility with licenses that have no kid field.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 3: `pkg/sdk` — Init 多公钥模式 + LicenseInfo.KID

**Files:**
- Modify: `pkg/sdk/sdk.go:28-48,58-64,72-112,175-184` — Config, SDK struct, LicenseInfo, Init
- Modify: `pkg/sdk/sdk_test.go` — 新增 8 个测试 + 1 个辅助函数

**Interfaces:**
- Consumes: `loadKeys(fs.FS) (map[string]ed25519.PublicKey, error)` (Task 2), `license.PeekKID([]byte) (string, error)` (Task 1)
- Modifies: `Config` struct (add `KeyFS fs.FS`), `LicenseInfo` struct (add `KID string`), `Init` function, `LicenseInfo` method

- [ ] **Step 1: 在 sdk_test.go 中添加多公钥模式测试**

在 `pkg/sdk/sdk_test.go` 中：

首先在 import 块中添加 `"io/fs"` 和 `"testing/fstest"`。

然后在文件末尾追加以下测试：

```go
// makeLicenseWithKID creates a signed license with an explicit kid.
func makeLicenseWithKID(t *testing.T, priv ed25519.PrivateKey, hash string, expiresAt time.Time, kid string) []byte {
	t.Helper()
	data, err := license.SignLicense(license.LicensePayload{
		Version:    1,
		KID:        kid,
		DeviceHash: hash,
		IssuedAt:   time.Now().Truncate(time.Second),
		ExpiresAt:  expiresAt,
	}, priv)
	if err != nil {
		t.Fatalf("SignLicense error: %v", err)
	}
	return data
}

// keyFSBuilder helps construct an fstest.MapFS from kid→PEM mappings.
func keyFSBuilder(t *testing.T, kidsToKeys map[string][]byte) fs.FS {
	t.Helper()
	m := make(fstest.MapFS)
	for kid, pemBytes := range kidsToKeys {
		filename := kid + ".pem"
		if kid == "" {
			filename = "default.pem"
		}
		m[filename] = &fstest.MapFile{Data: pemBytes}
	}
	return m
}

// genKeyPair returns (priv, pubPEM).
func genKeyPair(t *testing.T) (ed25519.PrivateKey, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "ED25519 PUBLIC KEY", Bytes: pub})
	return priv, pubPEM
}

func TestInit_KeyFSSelectsByKid(t *testing.T) {
	dir := t.TempDir()
	priv, pubPEM := genKeyPair(t)
	licData := makeLicenseWithKID(t, priv, "sha256:test", time.Now().Add(365*24*time.Hour), "2026-v1")
	licPath := writeLicense(t, dir, licData)

	keyFS := keyFSBuilder(t, map[string][]byte{
		"":         {}, // empty placeholder
		"2026-v1":  pubPEM,
	})

	sdkInst, err := Init(Config{
		LicensePath:   licPath,
		KeyFS:         keyFS,
		MarkerPath:    filepath.Join(dir, ".grace_start"),
		GraceDuration: testGraceDuration,
	})
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	if !sdkInst.initPassed {
		t.Error("initPassed should be true when kid matches correct key")
	}
	info := sdkInst.LicenseInfo()
	if info == nil {
		t.Fatal("LicenseInfo() should not be nil")
	}
	if info.KID != "2026-v1" {
		t.Errorf("LicenseInfo.KID = %q, want %q", info.KID, "2026-v1")
	}
}

func TestInit_KeyFSDefaultFallback(t *testing.T) {
	dir := t.TempDir()
	priv, pubPEM := genKeyPair(t)
	// License WITHOUT kid — must match default.pem
	licData := makeLicense(t, priv, "sha256:test", time.Now().Add(365*24*time.Hour))
	licPath := writeLicense(t, dir, licData)

	keyFS := keyFSBuilder(t, map[string][]byte{
		"": pubPEM, // default.pem
	})

	sdkInst, err := Init(Config{
		LicensePath:   licPath,
		KeyFS:         keyFS,
		MarkerPath:    filepath.Join(dir, ".grace_start"),
		GraceDuration: testGraceDuration,
	})
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	if !sdkInst.initPassed {
		t.Error("initPassed should be true when default key matches no-kid license")
	}
}

func TestInit_KeyFSUnknownKid(t *testing.T) {
	dir := t.TempDir()
	priv, pubPEM := genKeyPair(t)
	licData := makeLicenseWithKID(t, priv, "sha256:test", time.Now().Add(365*24*time.Hour), "v9-unknown")
	licPath := writeLicense(t, dir, licData)

	keyFS := keyFSBuilder(t, map[string][]byte{
		"":         pubPEM, // only default, no v9-unknown
		"2026-v1":  pubPEM,
	})

	_, err := Init(Config{
		LicensePath:   licPath,
		KeyFS:         keyFS,
		MarkerPath:    filepath.Join(dir, ".grace_start"),
		GraceDuration: testGraceDuration,
	})
	if err == nil {
		t.Fatal("Init() expected error for unknown kid")
	}
}

func TestInit_KeyFSNoDefaultForOldLicense(t *testing.T) {
	dir := t.TempDir()
	priv, pubPEM := genKeyPair(t)
	// License WITHOUT kid, and no default.pem in KeyFS
	licData := makeLicense(t, priv, "sha256:test", time.Now().Add(365*24*time.Hour))
	licPath := writeLicense(t, dir, licData)

	keyFS := keyFSBuilder(t, map[string][]byte{
		"2026-v1": pubPEM, // only named keys, no default
	})

	_, err := Init(Config{
		LicensePath:   licPath,
		KeyFS:         keyFS,
		MarkerPath:    filepath.Join(dir, ".grace_start"),
		GraceDuration: testGraceDuration,
	})
	if err == nil {
		t.Fatal("Init() expected error when license has no kid and no default key")
	}
}

func TestInit_KeyFSWrongKeyForKid(t *testing.T) {
	dir := t.TempDir()
	priv1, _ := genKeyPair(t)
	_, pubPEM2 := genKeyPair(t) // different key pair!
	licData := makeLicenseWithKID(t, priv1, "sha256:test", time.Now().Add(365*24*time.Hour), "2026-v1")
	licPath := writeLicense(t, dir, licData)

	keyFS := keyFSBuilder(t, map[string][]byte{
		"2026-v1": pubPEM2, // wrong key for this license
	})

	sdkInst, err := Init(Config{
		LicensePath:   licPath,
		KeyFS:         keyFS,
		MarkerPath:    filepath.Join(dir, ".grace_start"),
		GraceDuration: testGraceDuration,
	})
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	if sdkInst.initPassed {
		t.Error("initPassed should be false when kid matches but key is wrong")
	}
}

func TestInit_PublicKeyBackwardCompat(t *testing.T) {
	dir := t.TempDir()
	priv, pubPEM := genKeyPair(t)
	licData := makeLicense(t, priv, "sha256:test", time.Now().Add(365*24*time.Hour))
	licPath := writeLicense(t, dir, licData)

	// Both PublicKey and KeyFS set — PublicKey takes precedence
	_, pubPEM2 := genKeyPair(t)
	keyFS := keyFSBuilder(t, map[string][]byte{
		"": pubPEM2, // different key — should be ignored
	})

	sdkInst, err := Init(Config{
		LicensePath:   licPath,
		PublicKey:     pubPEM, // this one wins
		KeyFS:         keyFS,  // ignored
		MarkerPath:    filepath.Join(dir, ".grace_start"),
		GraceDuration: testGraceDuration,
	})
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	if !sdkInst.initPassed {
		t.Error("initPassed should be true — PublicKey takes precedence over KeyFS")
	}
}

func TestInit_NoPublicKeyNoKeyFS(t *testing.T) {
	dir := t.TempDir()
	licPath := filepath.Join(dir, "license.bin")
	if err := os.WriteFile(licPath, []byte("dummy"), 0o644); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	_, err := Init(Config{
		LicensePath: licPath,
		// Neither PublicKey nor KeyFS set
	})
	if err == nil {
		t.Fatal("Init() expected error when no public key configured")
	}
}

func TestLicenseInfo_IncludesKID(t *testing.T) {
	dir := t.TempDir()
	priv, pubPEM := genKeyPair(t)
	licData := makeLicenseWithKID(t, priv, "sha256:test", time.Now().Add(365*24*time.Hour), "2027-v2")
	licPath := writeLicense(t, dir, licData)

	keyFS := keyFSBuilder(t, map[string][]byte{
		"2027-v2": pubPEM,
	})

	sdkInst, err := Init(Config{
		LicensePath:   licPath,
		KeyFS:         keyFS,
		MarkerPath:    filepath.Join(dir, ".grace_start"),
		GraceDuration: testGraceDuration,
	})
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	info := sdkInst.LicenseInfo()
	if info == nil {
		t.Fatal("LicenseInfo() should not be nil")
	}
	if info.KID != "2027-v2" {
		t.Errorf("LicenseInfo.KID = %q, want %q", info.KID, "2027-v2")
	}
}

func TestLicenseInfo_KIDEmpty(t *testing.T) {
	dir := t.TempDir()
	priv, pubPEM := genKeyPair(t)
	licData := makeLicense(t, priv, "sha256:test", time.Now().Add(365*24*time.Hour))
	licPath := writeLicense(t, dir, licData)

	keyFS := keyFSBuilder(t, map[string][]byte{
		"": pubPEM,
	})

	sdkInst, err := Init(Config{
		LicensePath:   licPath,
		KeyFS:         keyFS,
		MarkerPath:    filepath.Join(dir, ".grace_start"),
		GraceDuration: testGraceDuration,
	})
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	info := sdkInst.LicenseInfo()
	if info == nil {
		t.Fatal("LicenseInfo() should not be nil")
	}
	if info.KID != "" {
		t.Errorf("LicenseInfo.KID = %q, want empty string", info.KID)
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

```bash
go test ./pkg/sdk/ -run "TestInit_KeyFS|TestInit_PublicKeyBackwardCompat|TestInit_NoPublicKey|TestLicenseInfo_IncludesKID|TestLicenseInfo_KIDEmpty" -v
```

预期：编译错误（`Config` 没有 `KeyFS` 字段，`LicenseInfo` 没有 `KID` 字段）。

- [ ] **Step 3: 修改 sdk.go — Config、SDK struct、LicenseInfo、Init**

修改 `pkg/sdk/sdk.go`：

**3a. 在 import 块中添加 `"errors"` 和 `"io/fs"`：**

```go
import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"device-secret/internal/crypto"
	"device-secret/internal/fingerprint"
	"device-secret/internal/grace"
	"device-secret/internal/license"
)
```

**3b. 修改 Config 结构体（在 `PublicKey` 字段后添加 `KeyFS`）：**

```go
type Config struct {
	// LicensePath is the path of the license file to load and verify.
	LicensePath string
	// PublicKey is the PEM-encoded Ed25519 public key used to verify the
	// license signature. When set, single-key mode is used and KeyFS is
	// ignored (backward compatible).
	PublicKey []byte
	// KeyFS is an fs.FS containing *.pem public key files for multi-key
	// mode. File naming: <kid>.pem, with "default.pem" used for licenses
	// that have no kid. Typically populated via //go:embed keys/*.pem.
	KeyFS fs.FS
	// MarkerPath is where the grace period start time is persisted.
	// Defaults to /var/lib/device-secret/.grace_start.
	MarkerPath string
	// GraceDuration is how long a grace period lasts after a verification
	// failure. Defaults to 30 days.
	GraceDuration time.Duration
}
```

**3c. 修改 SDK 结构体（字段 `pubKey` 不变，Init 中会赋值）：**

SDK 结构体无需修改——`pubKey` 字段在 Init 中根据模式赋值。

**3d. 修改 LicenseInfo（添加 `KID` 字段）：**

```go
type LicenseInfo struct {
	KID        string    // Key ID from the license payload
	DeviceHash string
	ExpiresAt  time.Time
	Features   []string
}
```

**3e. 修改 Init 函数（重写密钥选择逻辑）：**

将现有的 Init 函数从：

```go
func Init(cfg Config) (*SDK, error) {
	pubKey, err := crypto.ParsePublicKey(cfg.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("sdk: invalid public key: %w", err)
	}

	applyDefaults(&cfg)

	s := &SDK{
		pubKey: pubKey,
		tracker: &grace.Tracker{
			GraceDuration: cfg.GraceDuration,
			MarkerPath:    cfg.MarkerPath,
		},
	}

	licData, err := os.ReadFile(cfg.LicensePath)
	if err != nil {
		return nil, fmt.Errorf("sdk: cannot read license file: %w", err)
	}

	s.payload, err = license.VerifyLicense(licData, pubKey)
	if err != nil {
		s.initPassed = false
		return s, nil
	}
	s.initPassed = true

	if dir := filepath.Dir(cfg.MarkerPath); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("sdk: cannot create marker directory: %w", err)
		}
	}

	return s, nil
}
```

改为：

```go
func Init(cfg Config) (*SDK, error) {
	applyDefaults(&cfg)

	// Resolve public key(s)
	var pubKey ed25519.PublicKey
	var pubKeys map[string]ed25519.PublicKey

	if cfg.PublicKey != nil {
		// Single-key mode (backward compatible) — KeyFS is ignored.
		var err error
		pubKey, err = crypto.ParsePublicKey(cfg.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("sdk: invalid public key: %w", err)
		}
	} else if cfg.KeyFS != nil {
		// Multi-key mode — load all *.pem files from the embedded FS.
		var err error
		pubKeys, err = loadKeys(cfg.KeyFS)
		if err != nil {
			return nil, fmt.Errorf("sdk: %w", err)
		}
	} else {
		return nil, errors.New("sdk: no public key configured — set PublicKey or KeyFS")
	}

	s := &SDK{
		tracker: &grace.Tracker{
			GraceDuration: cfg.GraceDuration,
			MarkerPath:    cfg.MarkerPath,
		},
	}

	licData, err := os.ReadFile(cfg.LicensePath)
	if err != nil {
		return nil, fmt.Errorf("sdk: cannot read license file: %w", err)
	}

	// In multi-key mode, peek at the kid to select the correct public key.
	if pubKeys != nil {
		kid, err := license.PeekKID(licData)
		if err != nil {
			return nil, fmt.Errorf("sdk: cannot read license kid: %w", err)
		}
		var ok bool
		pubKey, ok = pubKeys[kid]
		if !ok {
			if kid == "" {
				return nil, errors.New("sdk: license has no kid, and no default key configured")
			}
			return nil, fmt.Errorf("sdk: unknown kid %q — no matching public key", kid)
		}
	}

	s.pubKey = pubKey

	s.payload, err = license.VerifyLicense(licData, pubKey)
	if err != nil {
		// Signature/format problems are reported by Verify(); Init still
		// succeeds so the application can surface the failure gracefully.
		s.initPassed = false
		return s, nil
	}
	s.initPassed = true

	// Ensure the marker file's parent directory exists so grace period
	// state can be persisted on fresh deployments.
	if dir := filepath.Dir(cfg.MarkerPath); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("sdk: cannot create marker directory: %w", err)
		}
	}

	return s, nil
}
```

**3f. 修改 LicenseInfo 方法（添加 KID）：**

```go
func (s *SDK) LicenseInfo() *LicenseInfo {
	if s == nil || s.payload == nil {
		return nil
	}
	return &LicenseInfo{
		KID:        s.payload.KID,
		DeviceHash: s.payload.DeviceHash,
		ExpiresAt:  s.payload.ExpiresAt,
		Features:   s.payload.Features,
	}
}
```

- [ ] **Step 4: 运行全部 SDK 测试确认通过**

```bash
go test ./pkg/sdk/ -v
```

预期：全部测试 PASS（包括新测试和已有测试）。

- [ ] **Step 5: Commit**

```bash
git add pkg/sdk/sdk.go pkg/sdk/sdk_test.go
git commit -m "feat: add multi-key support to SDK via kid-based key selection

Config.KeyFS enables multi-key mode with keys embedded via go:embed.
Init() selects the correct public key using license.PeekKID, with
'default.pem' as fallback for licenses without kid. LicenseInfo now
exposes the KID field. Single-key mode (Config.PublicKey) remains
fully backward compatible.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 4: `cmd/license-gen` — kid 格式校验

**Files:**
- Modify: `cmd/license-gen/main.go` — flag 解析后校验 kid 格式

**Interfaces:**
- Consumes: 无新依赖
- Produces: 无新导出

- [ ] **Step 1: 在 main.go 中添加 kid 校验逻辑**

在 `cmd/license-gen/main.go` 中 flag 解析之后、读取 request file 之前，添加校验：

修改文件，在 `flag.Parse()` 后（当前第 25 行之后），`if *requestPath == "" ...` 校验块之前，加入 kid 校验：

```go
	// Validate kid format if provided
	if *kid != "" {
		if !validKidRE.MatchString(*kid) {
			fmt.Fprintf(os.Stderr, "license-gen: invalid kid %q: must match %s (1-64 chars: letters, digits, hyphens, underscores)\n", *kid, validKidRE.String())
			os.Exit(1)
		}
	}
```

在 import 块中添加 `"regexp"`，并在文件顶部（`func main()` 之前）添加：

```go
var validKidRE = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)
```

- [ ] **Step 2: 手动验证**（license-gen 是 CLI 工具，不适合做 Go 单测）

```bash
# 构建
go build -o /tmp/test-license-gen ./cmd/license-gen

# 合法 kid 应该正常解析参数（后续会因缺少 request 文件报错，但不会因 kid 报错）
/tmp/test-license-gen -request /nonexistent -key /nonexistent -expires +365d -kid "2026-primary" 2>&1 | head -1
# 预期: "license-gen: cannot read request file: ..."（不是 kid 相关错误）

# 非法 kid 应该被拒绝
/tmp/test-license-gen -request /nonexistent -key /nonexistent -expires +365d -kid "../evil" 2>&1
# 预期: "license-gen: invalid kid ..."

/tmp/test-license-gen -request /nonexistent -key /nonexistent -expires +365d -kid "has space" 2>&1
# 预期: "license-gen: invalid kid ..."

# 清理
rm /tmp/test-license-gen
```

- [ ] **Step 3: 确认已有测试未破坏**

```bash
go test ./... -short
```

- [ ] **Step 4: Commit**

```bash
git add cmd/license-gen/main.go
git commit -m "feat: validate kid format in license-gen CLI

Reject kid values that don't match ^[a-zA-Z0-9_-]{1,64}$ at the
signing stage, preventing malformed kids from entering licenses.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 5: 文档更新 — SysRS + README

**Files:**
- Modify: `docs/SysRS-device-secret.md` — 更新 §4.2, §6.4, §6.5
- Modify: `README.md` — 更新快速开始、License 格式、安全性章节

- [ ] **Step 1: 更新 SysRS §4.2 安全约束 — 扩展 kid 描述**

在 `docs/SysRS-device-secret.md` 的 §4.2 表格中，将 `密钥轮换` 行更新为：

```
| **密钥轮换** | License 预留 `kid`（Key ID）字段。公钥文件按 `<kid>.pem` 命名放在源码 `keys/` 目录，通过 `//go:embed` 编译嵌入。更换签发密钥时，新 License 带新 `kid` 用新私钥签名，旧 License 的 `kid` 指向旧公钥持续有效。`default.pem` 为无 `kid` 的旧 License 提供向后兼容。`kid` 格式：`^[a-zA-Z0-9_-]{1,64}$` |
```

- [ ] **Step 2: 更新 SysRS §6.4 项目结构 — 添加 keys/ 目录**

在项目结构树中 `cmd/` 之前，添加 `keys/` 目录：

```
	device-secret/
+	├── keys/                        # 公钥文件（编译时嵌入）
+	│   ├── default.pem              #   当前活跃签发公钥（匹配无 kid 旧 License）
+	│   └── <kid>.pem                #   历史/轮换公钥（kid 匹配）
	├── cmd/
	│   ├── fingerprint/
```

- [ ] **Step 3: 更新 SysRS §6.5 SDK API 概览 — 更新代码示例**

将 §6.5 中的示例代码更新为多公钥模式：

```go
	//go:embed keys/*.pem
	var keyFS embed.FS
	
	// 初始化
	sdk, err := devicesecret.Init(Config{
	    LicensePath: "/license/license",
	    KeyFS:       keyFS,
	})
```

- [ ] **Step 4: 更新 SysRS §6.6 文件格式 — License 载荷中 kid 描述**

在 License 载荷的字段说明中，将 `kid` 的描述更新为：

```
	- `kid`：密钥 ID，SDK 据此选择对应公钥验签。格式 `^[a-zA-Z0-9_-]{1,64}$`，文件命名 `<kid>.pem`
```

- [ ] **Step 5: 更新 README — 快速开始 Step 1 和 Step 3**

Step 1（生成密钥）后添加关于 kid 的说明：

```
	**私钥**妥善保管在签发机上，**公钥**以 `<kid>.pem` 命名放入源码 `keys/` 目录，编译时嵌入应用。

	公钥文件命名规范：
	- `default.pem` — 当前活跃签发密钥，匹配无 `kid` 的旧 License
	- `<kid>.pem` — 特定 kid 的公钥（如 `2026-primary.pem`）
	- 文件名去掉 `.pem` 即为 `kid` 值；`kid` 格式：`^[a-zA-Z0-9_-]{1,64}$`
```

Step 3（签发 License）的示例命令保持不变（已经有 `-kid` 参数）。

- [ ] **Step 6: 更新 README — 快速开始 Step 4 代码示例**

将 SDK 集成示例更新为使用 `embed` 的多公钥模式：

```go
	package main

	import (
	    "embed"
	    "log"
	    "os"
	    "time"

	    "device-secret/pkg/sdk"
	)

	//go:embed keys/*.pem
	var keyFS embed.FS

	func main() {
	    lic, err := sdk.Init(sdk.Config{
	        LicensePath: "/etc/myapp/license",
	        KeyFS:       keyFS,
	    })
	    if err != nil {
	        log.Fatalf("sdk init failed: %v", err)
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

	    // 运行时周期性校验
	    go func() {
	        ticker := time.NewTicker(24 * time.Hour)
	        defer ticker.Stop()
	        for range ticker.C {
	            if result := lic.Verify(); result.Status != sdk.StatusValid {
	                log.Printf("license check: %s", result.Message)
	            }
	        }
	    }()
	}
```

同时将 import 中的 `"os"` 替换为 `"embed"` 和 `"log"`，移除不再需要的 `pubKey, _ := os.ReadFile(...)` 行。

- [ ] **Step 7: 更新 README — License 格式章节**

在 License 格式的 `kid` 字段说明中更新为：

```
	| `kid` | string | 密钥 ID，格式 `^[a-zA-Z0-9_-]{1,64}$`，SDK 据此选择验签公钥 |
```

- [ ] **Step 8: 更新 README — 安全性章节**

在安全性章节的密钥轮换条目中更新为：

```
	- **密钥轮换**——`kid` 字段 + 多公钥 embed 机制，更换签发密钥后旧 License 持续有效
```

- [ ] **Step 9: Commit**

```bash
git add docs/SysRS-device-secret.md README.md
git commit -m "docs: update SysRS and README for kid-based multi-key support

Document kid naming convention, public key file standard, embed-based
key loading, and key rotation lifecycle in both the system spec and
project README.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Execution Check

任务依赖链：

```
Task 1 (PeekKID) ──┐
                    ├──▶ Task 3 (Init + LicenseInfo)
Task 2 (loadKeys) ──┘
Task 4 (license-gen) ── 独立，可并行
Task 5 (docs) ────────── 独立，可最后执行
```

推荐执行顺序：1 → 2 → 3 → 4 → 5（Task 4 可与 1-3 并行）。
