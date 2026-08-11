# Device Secret Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a software license system (device-secret) with fingerprint CLI, license-gen CLI, and embeddable SDK for device binding via Ed25519 signatures.

**Architecture:** Three artifacts — `fingerprint` CLI (host-side hardware collection), `license-gen` CLI (signing machine), and `pkg/sdk` (in-app verification). All shared logic in `internal/`. Ed25519 for signing, SHA-256 for fingerprint hashing, Base64 URL-safe encoding.

**Tech Stack:** Go 1.21+, `crypto/ed25519`, `crypto/sha256`, `encoding/json`, `encoding/base64`, `encoding/pem`. Zero external dependencies.

## Global Constraints

- Go 1.21+ (for `crypto/ed25519` standard library)
- Zero third-party dependencies beyond Go standard library
- `CGO_ENABLED=0` for all builds (static binaries)
- Linux-only targets (x86_64 and ARM64)
- All public functions in `pkg/sdk` must never panic
- Base64 encoding MUST use URL-safe variant (no padding)
- Fingerprint hash format: `"sha256:<hex>"`
- License file format: `base64(compactJSON).base64(signature)`
- Grace period default: 7 days (168 hours)
- Minimum valid fingerprint factors: 2

---

### Task 1: Project Scaffolding

**Files:**
- Create: `go.mod`
- Create: `Makefile`
- Create: `cmd/fingerprint/main.go` (stub)
- Create: `cmd/license-gen/main.go` (stub)
- Create: `internal/crypto/keys.go` (stub)
- Create: `internal/fingerprint/collector.go` (stub)
- Create: `internal/fingerprint/sources.go` (stub)
- Create: `internal/fingerprint/hash.go` (stub)
- Create: `internal/license/format.go` (stub)
- Create: `internal/license/sign.go` (stub)
- Create: `internal/license/verify.go` (stub)
- Create: `internal/grace/grace.go` (stub)
- Create: `pkg/sdk/sdk.go` (stub)
- Create: `.gitignore`

**Interfaces:**
- Produces: directory structure and `go.mod` with module path `device-secret`

- [ ] **Step 1: Initialize Go module**

```bash
cd /Users/bingxu/code/kelin-go/device-secret
go mod init device-secret
```

- [ ] **Step 2: Create Makefile**

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

- [ ] **Step 3: Create .gitignore**

```
/bin/
*.pem
*.bin
```

- [ ] **Step 4: Create stub files**

Create each stub with `package <name>` and an empty file so the directory tree exists:

```bash
mkdir -p cmd/fingerprint cmd/license-gen
mkdir -p internal/crypto internal/fingerprint internal/license internal/grace
mkdir -p pkg/sdk build

echo 'package main' > cmd/fingerprint/main.go
echo 'package main' > cmd/license-gen/main.go
echo 'package crypto' > internal/crypto/keys.go
echo 'package fingerprint' > internal/fingerprint/collector.go
echo 'package fingerprint' > internal/fingerprint/sources.go
echo 'package fingerprint' > internal/fingerprint/hash.go
echo 'package license' > internal/license/format.go
echo 'package license' > internal/license/sign.go
echo 'package license' > internal/license/verify.go
echo 'package grace' > internal/grace/grace.go
echo 'package sdk' > pkg/sdk/sdk.go
```

- [ ] **Step 5: Verify build compiles (stubs are valid)**

Run: `go build ./...`
Expected: success, no output

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "chore: scaffold project structure and go.mod"
```

---

### Task 2: internal/crypto — Ed25519 Key Management

**Files:**
- Create: `internal/crypto/keys.go`
- Create: `internal/crypto/keys_test.go`

**Interfaces:**
- Produces:
  - `func GenerateKeyPair() (ed25519.PrivateKey, ed25519.PublicKey, error)`
  - `func MarshalPrivateKey(key ed25519.PrivateKey) ([]byte, error)`
  - `func MarshalPublicKey(key ed25519.PublicKey) ([]byte, error)`
  - `func ParsePrivateKey(pemBytes []byte) (ed25519.PrivateKey, error)`
  - `func ParsePublicKey(pemBytes []byte) (ed25519.PublicKey, error)`
  - `func Sign(key ed25519.PrivateKey, message []byte) []byte`
  - `func Verify(key ed25519.PublicKey, message, sig []byte) bool`
  - `var ErrInvalidPEM = errors.New("crypto: invalid PEM data")`

- [ ] **Step 1: Write failing tests for key generation and PEM round-trip**

File: `internal/crypto/keys_test.go`

```go
package crypto

import (
    "crypto/ed25519"
    "testing"
)

func TestGenerateKeyPair(t *testing.T) {
    priv, pub, err := GenerateKeyPair()
    if err != nil {
        t.Fatalf("GenerateKeyPair() error = %v", err)
    }
    if len(priv) != ed25519.PrivateKeySize {
        t.Errorf("private key size = %d, want %d", len(priv), ed25519.PrivateKeySize)
    }
    if len(pub) != ed25519.PublicKeySize {
        t.Errorf("public key size = %d, want %d", len(pub), ed25519.PublicKeySize)
    }
}

func TestPEMRoundTripPrivateKey(t *testing.T) {
    priv, _, err := GenerateKeyPair()
    if err != nil {
        t.Fatalf("GenerateKeyPair() error = %v", err)
    }
    pemBytes, err := MarshalPrivateKey(priv)
    if err != nil {
        t.Fatalf("MarshalPrivateKey() error = %v", err)
    }
    parsed, err := ParsePrivateKey(pemBytes)
    if err != nil {
        t.Fatalf("ParsePrivateKey() error = %v", err)
    }
    if !ed25519.PrivateKey(parsed).Equal(priv) {
        t.Error("round-tripped private key not equal to original")
    }
}

func TestPEMRoundTripPublicKey(t *testing.T) {
    _, pub, err := GenerateKeyPair()
    if err != nil {
        t.Fatalf("GenerateKeyPair() error = %v", err)
    }
    pemBytes, err := MarshalPublicKey(pub)
    if err != nil {
        t.Fatalf("MarshalPublicKey() error = %v", err)
    }
    parsed, err := ParsePublicKey(pemBytes)
    if err != nil {
        t.Fatalf("ParsePublicKey() error = %v", err)
    }
    if !ed25519.PublicKey(parsed).Equal(pub) {
        t.Error("round-tripped public key not equal to original")
    }
}

func TestParsePrivateKey_WrongType(t *testing.T) {
    pemData := "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhDHEQ==\n-----END RSA PRIVATE KEY-----"
    _, err := ParsePrivateKey([]byte(pemData))
    if err == nil {
        t.Error("expected error for wrong PEM type, got nil")
    }
}

func TestParsePublicKey_WrongType(t *testing.T) {
    pemData := "-----BEGIN RSA PUBLIC KEY-----\nMIGJAoGBAMkaPw==\n-----END RSA PUBLIC KEY-----"
    _, err := ParsePublicKey([]byte(pemData))
    if err == nil {
        t.Error("expected error for wrong PEM type, got nil")
    }
}

func TestSignAndVerify(t *testing.T) {
    priv, pub, err := GenerateKeyPair()
    if err != nil {
        t.Fatalf("GenerateKeyPair() error = %v", err)
    }
    message := []byte("hello world")
    sig := Sign(priv, message)
    if !Verify(pub, message, sig) {
        t.Error("Verify() returned false for valid signature")
    }
}

func TestVerify_WrongKey(t *testing.T) {
    priv, _, err := GenerateKeyPair()
    if err != nil {
        t.Fatalf("GenerateKeyPair() error = %v", err)
    }
    _, wrongPub, err := GenerateKeyPair()
    if err != nil {
        t.Fatalf("GenerateKeyPair() error = %v", err)
    }
    message := []byte("hello world")
    sig := Sign(priv, message)
    if Verify(wrongPub, message, sig) {
        t.Error("Verify() returned true for signature made with different key")
    }
}

func TestVerify_TamperedMessage(t *testing.T) {
    priv, pub, err := GenerateKeyPair()
    if err != nil {
        t.Fatalf("GenerateKeyPair() error = %v", err)
    }
    message := []byte("hello world")
    sig := Sign(priv, message)
    if Verify(pub, []byte("goodbye world"), sig) {
        t.Error("Verify() returned true for tampered message")
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/crypto/ -v`
Expected: FAIL — "undefined: GenerateKeyPair" and similar errors

- [ ] **Step 3: Implement internal/crypto/keys.go**

```go
package crypto

import (
    "crypto/ed25519"
    "crypto/rand"
    "encoding/pem"
    "errors"
    "fmt"
)

var ErrInvalidPEM = errors.New("crypto: invalid PEM data")

func GenerateKeyPair() (ed25519.PrivateKey, ed25519.PublicKey, error) {
    pub, priv, err := ed25519.GenerateKey(rand.Reader)
    if err != nil {
        return nil, nil, err
    }
    return priv, pub, nil
}

func MarshalPrivateKey(key ed25519.PrivateKey) ([]byte, error) {
    block := &pem.Block{
        Type:  "ED25519 PRIVATE KEY",
        Bytes: key,
    }
    return pem.EncodeToMemory(block), nil
}

func MarshalPublicKey(key ed25519.PublicKey) ([]byte, error) {
    block := &pem.Block{
        Type:  "ED25519 PUBLIC KEY",
        Bytes: key,
    }
    return pem.EncodeToMemory(block), nil
}

func ParsePrivateKey(pemBytes []byte) (ed25519.PrivateKey, error) {
    block, _ := pem.Decode(pemBytes)
    if block == nil || block.Type != "ED25519 PRIVATE KEY" {
        return nil, fmt.Errorf("%w: not a valid ED25519 private key", ErrInvalidPEM)
    }
    if len(block.Bytes) != ed25519.PrivateKeySize {
        return nil, fmt.Errorf("%w: invalid private key size", ErrInvalidPEM)
    }
    return ed25519.PrivateKey(block.Bytes), nil
}

func ParsePublicKey(pemBytes []byte) (ed25519.PublicKey, error) {
    block, _ := pem.Decode(pemBytes)
    if block == nil || block.Type != "ED25519 PUBLIC KEY" {
        return nil, fmt.Errorf("%w: not a valid ED25519 public key", ErrInvalidPEM)
    }
    if len(block.Bytes) != ed25519.PublicKeySize {
        return nil, fmt.Errorf("%w: invalid public key size", ErrInvalidPEM)
    }
    return ed25519.PublicKey(block.Bytes), nil
}

func Sign(key ed25519.PrivateKey, message []byte) []byte {
    return ed25519.Sign(key, message)
}

func Verify(key ed25519.PublicKey, message, sig []byte) bool {
    return ed25519.Verify(key, message, sig)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/crypto/ -v`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add internal/crypto/keys.go internal/crypto/keys_test.go
git commit -m "feat: add Ed25519 key management (internal/crypto)"
```

---

### Task 3: internal/fingerprint — Hardware Fingerprint Collection

**Files:**
- Create: `internal/fingerprint/collector.go`
- Create: `internal/fingerprint/sources.go`
- Create: `internal/fingerprint/hash.go`
- Create: `internal/fingerprint/testdata/machine-id`
- Create: `internal/fingerprint/testdata/proc/cpuinfo`
- Create: `internal/fingerprint/testdata/sys/class/dmi/id/product_serial`
- Create: `internal/fingerprint/testdata/sys/class/dmi/id/product_uuid`
- Create: `internal/fingerprint/testdata/sys/class/net/eth0/address`
- Create: `internal/fingerprint/testdata/sys/class/net/lo/address`
- Create: `internal/fingerprint/testdata/sys/class/net/docker0/address`
- Create: `internal/fingerprint/testdata/sys/block/mmcblk0/device/cid`
- Create: `internal/fingerprint/collector_test.go`

**Interfaces:**
- Produces:
  - `type DeviceMeta struct { Hostname, OS, Arch string }`
  - `type Sources map[string]string`
  - `type Fingerprint struct { Sources Sources; Hash string }`
  - `type RequestFile struct { Version int; Device DeviceMeta; Fingerprint Fingerprint; RequestedAt time.Time }`
  - `func Collect() (*Fingerprint, error)`
  - `func ComputeHash(sources Sources) string`
  - `var ErrInsufficientFactors = errors.New("fingerprint: insufficient unique factors")`

- [ ] **Step 1: Create testdata mock files**

```bash
mkdir -p internal/fingerprint/testdata/proc
mkdir -p internal/fingerprint/testdata/sys/class/dmi/id
mkdir -p internal/fingerprint/testdata/sys/class/net/eth0
mkdir -p internal/fingerprint/testdata/sys/class/net/lo
mkdir -p internal/fingerprint/testdata/sys/class/net/docker0
mkdir -p internal/fingerprint/testdata/sys/block/mmcblk0/device

# machine-id
echo -n "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6" > internal/fingerprint/testdata/machine-id

# cpuinfo (ARM-like with Serial)
cat > internal/fingerprint/testdata/proc/cpuinfo << 'EOF'
processor       : 0
BogoMIPS        : 48.00
Features        : fp asimd evtstrm aes pmull sha1 sha2 crc32
CPU implementer : 0x41
CPU architecture: 8
CPU variant     : 0x0
CPU part        : 0xd08
CPU revision    : 3
Serial          : 1234567890abcdef
EOF

# dmi product_serial
echo -n "SYS-123456789" > internal/fingerprint/testdata/sys/class/dmi/id/product_serial

# dmi product_uuid
echo -n "550e8400-e29b-41d4-a716-446655440000" > internal/fingerprint/testdata/sys/class/dmi/id/product_uuid

# eth0 address (physical NIC)
echo -n "aa:bb:cc:dd:ee:ff" > internal/fingerprint/testdata/sys/class/net/eth0/address

# lo address (loopback — should be excluded)
echo -n "00:00:00:00:00:00" > internal/fingerprint/testdata/sys/class/net/lo/address

# docker0 address (virtual — should be excluded)
echo -n "02:42:ac:11:00:01" > internal/fingerprint/testdata/sys/class/net/docker0/address

# emmc cid
echo -n "45010053454d4d43202020202020202020123456" > internal/fingerprint/testdata/sys/block/mmcblk0/device/cid
```

- [ ] **Step 2: Write collector_test.go**

```go
package fingerprint

import (
    "testing"
)

func TestCollect_WithTestData(t *testing.T) {
    oldBasePath := basePath
    defer func() { basePath = oldBasePath }()
    basePath = "testdata"

    fp, err := Collect()
    if err != nil {
        t.Fatalf("Collect() error = %v", err)
    }
    if fp.Sources["machine_id"] == "" {
        t.Error("machine_id should not be empty")
    }
    if fp.Sources["cpu_serial"] == "" {
        t.Error("cpu_serial should not be empty (testdata has Serial)")
    }
    if fp.Sources["macs"] == "" {
        t.Error("macs should not be empty")
    }
    if fp.Hash == "" {
        t.Error("hash should not be empty")
    }
    // Verify macs are normalized (lowercase) and sorted
    macs := fp.Sources["macs"]
    if macs != "aa:bb:cc:dd:ee:ff" {
        t.Logf("macs = %s (may include real system NICs)", macs)
    }
}

func TestComputeHash_Deterministic(t *testing.T) {
    sources := Sources{
        "machine_id": "abc",
        "cpu_serial": "123",
    }
    h1 := ComputeHash(sources)
    h2 := ComputeHash(sources)
    if h1 != h2 {
        t.Errorf("ComputeHash not deterministic: %s != %s", h1, h2)
    }
}

func TestComputeHash_DifferentInputs(t *testing.T) {
    h1 := ComputeHash(Sources{"machine_id": "abc", "cpu_serial": "123"})
    h2 := ComputeHash(Sources{"machine_id": "xyz", "cpu_serial": "123"})
    if h1 == h2 {
        t.Error("different inputs should produce different hashes")
    }
}

func TestComputeHash_SkipsEmpty(t *testing.T) {
    h1 := ComputeHash(Sources{"machine_id": "abc", "cpu_serial": "", "macs": "aa:bb"})
    h2 := ComputeHash(Sources{"machine_id": "abc", "macs": "aa:bb"})
    if h1 != h2 {
        t.Error("empty values should be skipped, hashes should match")
    }
}

func TestCollect_InsufficientFactors(t *testing.T) {
    oldBasePath := basePath
    defer func() { basePath = oldBasePath }()
    basePath = "/nonexistent/path/that/does/not/exist"

    _, err := Collect()
    if err == nil {
        t.Error("expected error for insufficient factors, got nil")
    }
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/fingerprint/ -v`
Expected: FAIL — undefined references

- [ ] **Step 4: Implement internal/fingerprint/sources.go**

```go
package fingerprint

import (
    "os"
    "regexp"
    "runtime"
    "strings"
)

var (
    readFile  = os.ReadFile
    readDir   = func(path string) ([]string, error) {
        entries, err := os.ReadDir(path)
        if err != nil {
            return nil, err
        }
        names := make([]string, len(entries))
        for i, e := range entries {
            names[i] = e.Name()
        }
        return names, nil
    }
    hostname = os.Hostname
    basePath = ""
)

func path(p string) string {
    if basePath != "" {
        return basePath + "/" + p
    }
    return p
}

var virtualNICPattern = regexp.MustCompile(`^(lo|docker\d*|veth\w+|br-.*|tun\d*|tap\d*|virbr\d*|cali\w+|flannel\w+)$`)

func collectMachineID() string {
    data, err := readFile(path("/etc/machine-id"))
    if err != nil {
        return ""
    }
    return strings.TrimSpace(string(data))
}

func collectCPUSerial() string {
    data, err := readFile(path("/proc/cpuinfo"))
    if err != nil {
        return ""
    }
    for _, line := range strings.Split(string(data), "\n") {
        line = strings.TrimSpace(line)
        if strings.HasPrefix(line, "Serial") {
            parts := strings.SplitN(line, ":", 2)
            if len(parts) == 2 {
                val := strings.TrimSpace(parts[1])
                if val != "" {
                    return val
                }
            }
        }
    }
    return ""
}

func collectProductSerial() string {
    data, err := readFile(path("/sys/class/dmi/id/product_serial"))
    if err != nil {
        return ""
    }
    val := strings.TrimSpace(string(data))
    if val == "" || val == "To be filled by O.E.M." || val == "Not Specified" {
        return ""
    }
    return val
}

func collectProductUUID() string {
    data, err := readFile(path("/sys/class/dmi/id/product_uuid"))
    if err != nil {
        return ""
    }
    val := strings.TrimSpace(string(data))
    if val == "" {
        return ""
    }
    return val
}

func collectMACs() string {
    entries, err := readDir(path("/sys/class/net"))
    if err != nil {
        return ""
    }
    var macs []string
    for _, iface := range entries {
        if virtualNICPattern.MatchString(iface) {
            continue
        }
        data, err := readFile(path("/sys/class/net/" + iface + "/address"))
        if err != nil {
            continue
        }
        mac := strings.TrimSpace(string(data))
        if mac != "" {
            macs = append(macs, strings.ToLower(mac))
        }
    }
    if len(macs) == 0 {
        return ""
    }
    return strings.Join(macs, ",")
}

func collectEMMCCID() string {
    entries, err := readDir(path("/sys/block"))
    if err != nil {
        return ""
    }
    for _, entry := range entries {
        if !strings.HasPrefix(entry, "mmcblk") {
            continue
        }
        data, err := readFile(path("/sys/block/" + entry + "/device/cid"))
        if err != nil {
            continue
        }
        val := strings.TrimSpace(string(data))
        if val != "" {
            return val
        }
    }
    return ""
}

// GetDeviceMeta returns device metadata not used for fingerprint binding.
func GetDeviceMeta() DeviceMeta {
    h, _ := hostname()
    return DeviceMeta{
        Hostname: h,
        OS:       runtime.GOOS,
        Arch:     runtime.GOARCH,
    }
}
```

- [ ] **Step 5: Implement internal/fingerprint/hash.go**

```go
package fingerprint

import (
    "crypto/sha256"
    "fmt"
    "sort"
    "strings"
)

func ComputeHash(sources Sources) string {
    keys := make([]string, 0, len(sources))
    for k, v := range sources {
        if v != "" {
            keys = append(keys, k)
        }
    }
    sort.Strings(keys)

    var sb strings.Builder
    for i, k := range keys {
        if i > 0 {
            sb.WriteByte('\n')
        }
        sb.WriteString(k)
        sb.WriteByte('=')
        sb.WriteString(sources[k])
    }
    h := sha256.Sum256([]byte(sb.String()))
    return fmt.Sprintf("sha256:%x", h)
}
```

- [ ] **Step 6: Implement internal/fingerprint/collector.go**

```go
package fingerprint

import (
    "errors"
    "time"
)

var ErrInsufficientFactors = errors.New("fingerprint: insufficient unique factors (need at least 2)")

type DeviceMeta struct {
    Hostname string `json:"hostname"`
    OS       string `json:"os"`
    Arch     string `json:"arch"`
}

type Sources map[string]string

type Fingerprint struct {
    Sources Sources `json:"sources"`
    Hash    string  `json:"hash"`
}

type RequestFile struct {
    Version     int         `json:"version"`
    Device      DeviceMeta  `json:"device"`
    Fingerprint Fingerprint `json:"fingerprint"`
    RequestedAt time.Time   `json:"requested_at"`
}

func Collect() (*Fingerprint, error) {
    sources := Sources{
        "machine_id":     collectMachineID(),
        "cpu_serial":     collectCPUSerial(),
        "product_serial": collectProductSerial(),
        "product_uuid":   collectProductUUID(),
        "macs":           collectMACs(),
        "emmc_cid":       collectEMMCCID(),
    }

    // Count non-empty factors
    count := 0
    for _, v := range sources {
        if v != "" {
            count++
        }
    }
    if count < 2 {
        return nil, ErrInsufficientFactors
    }

    return &Fingerprint{
        Sources: sources,
        Hash:    ComputeHash(sources),
    }, nil
}
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `go test ./internal/fingerprint/ -v`
Expected: all PASS

- [ ] **Step 8: Commit**

```bash
git add internal/fingerprint/
git commit -m "feat: add hardware fingerprint collection"
```

---

### Task 4: internal/license — License Format, Signing, Verification

**Files:**
- Create: `internal/license/format.go`
- Create: `internal/license/sign.go`
- Create: `internal/license/verify.go`
- Create: `internal/license/license_test.go`

**Interfaces:**
- Consumes: `internal/crypto` — `Sign()`, `Verify()` functions; `ed25519.PrivateKey`, `ed25519.PublicKey` types
- Produces:
  - `type LicensePayload struct { Version int; KID string; DeviceHash string; IssuedAt, ExpiresAt time.Time; Features []string; Metadata string }`
  - `func SignLicense(payload LicensePayload, priv ed25519.PrivateKey) ([]byte, error)`
  - `func VerifyLicense(licenseData []byte, pub ed25519.PublicKey) (*LicensePayload, error)`
  - `var ErrInvalidFormat = errors.New("license: invalid format")`
  - `var ErrInvalidSignature = errors.New("license: signature verification failed")`

- [ ] **Step 1: Write license_test.go**

```go
package license

import (
    "crypto/ed25519"
    "testing"
    "time"
)

// test key pair generated fresh for each test
func testKeyPair(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
    t.Helper()
    pub, priv, err := ed25519.GenerateKey(nil)
    if err != nil {
        t.Fatalf("failed to generate test key: %v", err)
    }
    return priv, pub
}

func TestSignAndVerifyLicense(t *testing.T) {
    priv, pub := testKeyPair(t)
    payload := LicensePayload{
        Version:    1,
        DeviceHash: "sha256:abcdef123456",
        IssuedAt:   time.Now().Truncate(time.Second),
        ExpiresAt:  time.Now().Add(365 * 24 * time.Hour).Truncate(time.Second),
    }

    data, err := SignLicense(payload, priv)
    if err != nil {
        t.Fatalf("SignLicense() error = %v", err)
    }
    if len(data) == 0 {
        t.Fatal("SignLicense() returned empty data")
    }

    decoded, err := VerifyLicense(data, pub)
    if err != nil {
        t.Fatalf("VerifyLicense() error = %v", err)
    }
    if decoded.DeviceHash != payload.DeviceHash {
        t.Errorf("DeviceHash = %s, want %s", decoded.DeviceHash, payload.DeviceHash)
    }
    if !decoded.ExpiresAt.Equal(payload.ExpiresAt) {
        t.Errorf("ExpiresAt = %v, want %v", decoded.ExpiresAt, payload.ExpiresAt)
    }
}

func TestVerifyLicense_WrongKey(t *testing.T) {
    priv, _ := testKeyPair(t)
    _, wrongPub := testKeyPair(t)

    payload := LicensePayload{
        Version:    1,
        DeviceHash: "sha256:abcdef123456",
        ExpiresAt:  time.Now().Add(365 * 24 * time.Hour),
    }
    data, _ := SignLicense(payload, priv)

    _, err := VerifyLicense(data, wrongPub)
    if err == nil {
        t.Error("expected error when verifying with wrong public key")
    }
}

func TestVerifyLicense_Tampered(t *testing.T) {
    priv, pub := testKeyPair(t)
    payload := LicensePayload{
        Version:    1,
        DeviceHash: "sha256:abcdef123456",
        ExpiresAt:  time.Now().Add(365 * 24 * time.Hour),
    }
    data, _ := SignLicense(payload, priv)

    // Tamper with the license data (modify one byte)
    tampered := make([]byte, len(data))
    copy(tampered, data)
    tampered[len(tampered)-2] ^= 0xFF

    _, err := VerifyLicense(tampered, pub)
    if err == nil {
        t.Error("expected error for tampered license")
    }
}

func TestVerifyLicense_InvalidFormat(t *testing.T) {
    _, pub := testKeyPair(t)
    _, err := VerifyLicense([]byte("not-a-valid-license"), pub)
    if err == nil {
        t.Error("expected error for invalid format")
    }
}

func TestSignLicense_Features(t *testing.T) {
    priv, pub := testKeyPair(t)
    payload := LicensePayload{
        Version:    1,
        DeviceHash: "sha256:abcdef123456",
        ExpiresAt:  time.Now().Add(365 * 24 * time.Hour),
        Features:   []string{"module_a", "module_b"},
    }
    data, _ := SignLicense(payload, priv)
    decoded, err := VerifyLicense(data, pub)
    if err != nil {
        t.Fatalf("VerifyLicense() error = %v", err)
    }
    if len(decoded.Features) != 2 {
        t.Errorf("Features length = %d, want 2", len(decoded.Features))
    }
}

func TestSignLicense_NilFeatures(t *testing.T) {
    priv, pub := testKeyPair(t)
    payload := LicensePayload{
        Version:    1,
        DeviceHash: "sha256:abcdef123456",
        ExpiresAt:  time.Now().Add(365 * 24 * time.Hour),
        Features:   nil,
    }
    data, _ := SignLicense(payload, priv)
    decoded, err := VerifyLicense(data, pub)
    if err != nil {
        t.Fatalf("VerifyLicense() error = %v", err)
    }
    if decoded.Features != nil {
        t.Error("Features should be nil when not set")
    }
}

func TestSignLicense_KID(t *testing.T) {
    priv, pub := testKeyPair(t)
    payload := LicensePayload{
        Version:    1,
        KID:        "2026-primary",
        DeviceHash: "sha256:abcdef123456",
        ExpiresAt:  time.Now().Add(365 * 24 * time.Hour),
    }
    data, _ := SignLicense(payload, priv)
    decoded, err := VerifyLicense(data, pub)
    if err != nil {
        t.Fatalf("VerifyLicense() error = %v", err)
    }
    if decoded.KID != "2026-primary" {
        t.Errorf("KID = %s, want '2026-primary'", decoded.KID)
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/license/ -v`
Expected: FAIL — undefined symbols

- [ ] **Step 3: Implement internal/license/format.go**

```go
package license

import "time"

type LicensePayload struct {
    Version    int       `json:"version"`
    KID        string    `json:"kid,omitempty"`
    DeviceHash string    `json:"device_hash"`
    IssuedAt   time.Time `json:"issued_at"`
    ExpiresAt  time.Time `json:"expires_at"`
    Features   []string  `json:"features,omitempty"`
    Metadata   string    `json:"metadata,omitempty"`
}
```

- [ ] **Step 4: Implement internal/license/sign.go**

```go
package license

import (
    "crypto/ed25519"
    "encoding/base64"
    "encoding/json"
)

func SignLicense(payload LicensePayload, priv ed25519.PrivateKey) ([]byte, error) {
    jsonBytes, err := json.Marshal(payload)
    if err != nil {
        return nil, err
    }
    sig := ed25519.Sign(priv, jsonBytes)

    encoded := base64.URLEncoding.WithPadding(base64.NoPadding)
    result := encoded.EncodeToString(jsonBytes) + "." + encoded.EncodeToString(sig)
    return []byte(result), nil
}
```

- [ ] **Step 5: Implement internal/license/verify.go**

```go
package license

import (
    "crypto/ed25519"
    "encoding/base64"
    "encoding/json"
    "errors"
    "strings"
)

var (
    ErrInvalidFormat    = errors.New("license: invalid format")
    ErrInvalidSignature = errors.New("license: signature verification failed")
)

func VerifyLicense(licenseData []byte, pub ed25519.PublicKey) (*LicensePayload, error) {
    parts := strings.SplitN(string(licenseData), ".", 2)
    if len(parts) != 2 {
        return nil, ErrInvalidFormat
    }

    encoded := base64.URLEncoding.WithPadding(base64.NoPadding)
    jsonBytes, err := encoded.DecodeString(parts[0])
    if err != nil {
        return nil, ErrInvalidFormat
    }
    sig, err := encoded.DecodeString(parts[1])
    if err != nil {
        return nil, ErrInvalidFormat
    }

    if !ed25519.Verify(pub, jsonBytes, sig) {
        return nil, ErrInvalidSignature
    }

    var payload LicensePayload
    if err := json.Unmarshal(jsonBytes, &payload); err != nil {
        return nil, ErrInvalidFormat
    }
    return &payload, nil
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `go test ./internal/license/ -v`
Expected: all PASS

- [ ] **Step 7: Commit**

```bash
git add internal/license/
git commit -m "feat: add license signing and verification"
```

---

### Task 5: internal/grace — Grace Period State Machine

**Files:**
- Create: `internal/grace/grace.go`
- Create: `internal/grace/grace_test.go`

**Interfaces:**
- Produces:
  - `type Status int` with constants `StatusValid`, `StatusGracePeriod`, `StatusExpired`, `StatusInvalid`
  - `type Tracker struct { GraceDuration time.Duration; MarkerPath string }`
  - `func (t *Tracker) Evaluate(pass bool, now time.Time) Status`

- [ ] **Step 1: Write grace_test.go**

```go
package grace

import (
    "os"
    "path/filepath"
    "testing"
    "time"
)

func TestEvaluate_Valid(t *testing.T) {
    dir := t.TempDir()
    tracker := &Tracker{
        GraceDuration: 7 * 24 * time.Hour,
        MarkerPath:    filepath.Join(dir, ".grace_start"),
    }
    status := tracker.Evaluate(true, time.Now())
    if status != StatusValid {
        t.Errorf("expected StatusValid, got %v", status)
    }
}

func TestEvaluate_EntersGracePeriod(t *testing.T) {
    dir := t.TempDir()
    tracker := &Tracker{
        GraceDuration: 7 * 24 * time.Hour,
        MarkerPath:    filepath.Join(dir, ".grace_start"),
    }
    now := time.Now()

    status := tracker.Evaluate(false, now)
    if status != StatusGracePeriod {
        t.Errorf("expected StatusGracePeriod, got %v", status)
    }

    // Marker file should be created
    if _, err := os.Stat(tracker.MarkerPath); os.IsNotExist(err) {
        t.Error("marker file should exist after entering grace period")
    }
}

func TestEvaluate_GracePeriodExpires(t *testing.T) {
    dir := t.TempDir()
    tracker := &Tracker{
        GraceDuration: 7 * 24 * time.Hour,
        MarkerPath:    filepath.Join(dir, ".grace_start"),
    }
    now := time.Now()

    // Enter grace period
    tracker.Evaluate(false, now)

    // Advance past grace duration
    later := now.Add(8 * 24 * time.Hour)
    status := tracker.Evaluate(false, later)
    if status != StatusExpired {
        t.Errorf("expected StatusExpired, got %v", status)
    }
}

func TestEvaluate_RecoversFromGracePeriod(t *testing.T) {
    dir := t.TempDir()
    tracker := &Tracker{
        GraceDuration: 7 * 24 * time.Hour,
        MarkerPath:    filepath.Join(dir, ".grace_start"),
    }
    now := time.Now()

    // Enter grace period
    tracker.Evaluate(false, now)

    // Recover with valid license
    status := tracker.Evaluate(true, now.Add(1*time.Hour))
    if status != StatusValid {
        t.Errorf("expected StatusValid after recovery, got %v", status)
    }

    // Marker file should be removed
    if _, err := os.Stat(tracker.MarkerPath); !os.IsNotExist(err) {
        t.Error("marker file should be removed after recovery")
    }
}

func TestEvaluate_RestartPreservesGracePeriod(t *testing.T) {
    dir := t.TempDir()
    now := time.Now()

    // Simulate first session
    tracker1 := &Tracker{
        GraceDuration: 7 * 24 * time.Hour,
        MarkerPath:    filepath.Join(dir, ".grace_start"),
    }
    tracker1.Evaluate(false, now)

    // Simulate restart (new tracker, same marker)
    tracker2 := &Tracker{
        GraceDuration: 7 * 24 * time.Hour,
        MarkerPath:    filepath.Join(dir, ".grace_start"),
    }
    status := tracker2.Evaluate(false, now.Add(1*time.Hour))
    if status != StatusGracePeriod {
        t.Errorf("expected StatusGracePeriod after restart, got %v", status)
    }
}

func TestEvaluate_CorruptMarker(t *testing.T) {
    dir := t.TempDir()
    markerPath := filepath.Join(dir, ".grace_start")
    os.WriteFile(markerPath, []byte("not-a-timestamp"), 0644)

    tracker := &Tracker{
        GraceDuration: 7 * 24 * time.Hour,
        MarkerPath:    markerPath,
    }
    status := tracker.Evaluate(false, time.Now())
    // Corrupt marker: conservative — treat as first day of grace period
    if status != StatusGracePeriod {
        t.Errorf("expected StatusGracePeriod for corrupt marker, got %v", status)
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/grace/ -v`
Expected: FAIL — undefined symbols

- [ ] **Step 3: Implement internal/grace/grace.go**

```go
package grace

import (
    "os"
    "strconv"
    "strings"
    "time"
)

type Status int

const (
    StatusValid       Status = iota
    StatusGracePeriod
    StatusExpired
    StatusInvalid
)

func (s Status) String() string {
    switch s {
    case StatusValid:
        return "Valid"
    case StatusGracePeriod:
        return "GracePeriod"
    case StatusExpired:
        return "Expired"
    case StatusInvalid:
        return "Invalid"
    default:
        return "Unknown"
    }
}

type Tracker struct {
    GraceDuration time.Duration
    MarkerPath    string
}

func (t *Tracker) Evaluate(pass bool, now time.Time) Status {
    if pass {
        // Remove marker if it exists (recovery from grace period)
        os.Remove(t.MarkerPath)
        return StatusValid
    }

    // Read marker to get grace period start time
    graceStart, err := readMarker(t.MarkerPath)
    if err != nil {
        // No marker yet — enter grace period
        writeMarker(t.MarkerPath, now)
        return StatusGracePeriod
    }

    // Check if grace period has expired
    if now.Sub(graceStart) > t.GraceDuration {
        return StatusExpired
    }
    return StatusGracePeriod
}

func readMarker(path string) (time.Time, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return time.Time{}, err
    }
    unix, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
    if err != nil {
        return time.Time{}, err
    }
    return time.Unix(unix, 0), nil
}

func writeMarker(path string, t time.Time) error {
    return os.WriteFile(path, []byte(strconv.FormatInt(t.Unix(), 10)), 0644)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/grace/ -v`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add internal/grace/
git commit -m "feat: add grace period state machine"
```

---

### Task 6: pkg/sdk — Public SDK API

**Files:**
- Create: `pkg/sdk/sdk.go`
- Create: `pkg/sdk/sdk_test.go`
- Create: `pkg/sdk/testdata/test-key.priv`
- Create: `pkg/sdk/testdata/test-key.pub`
- Create: `pkg/sdk/testdata/valid-license.bin`

**Interfaces:**
- Consumes:
  - `internal/fingerprint` — `Collect()`, `ComputeHash()`, `GetDeviceMeta()`, `RequestFile`, `Fingerprint`
  - `internal/license` — `VerifyLicense()`, `LicensePayload`, `ErrInvalidFormat`, `ErrInvalidSignature`
  - `internal/grace` — `Tracker`, `Status`, `StatusValid`, `StatusGracePeriod`, `StatusExpired`, `StatusInvalid`
- Produces:
  - `type Config struct { LicensePath string; PublicKey []byte; MarkerPath string; GraceDuration time.Duration }`
  - `func Init(cfg Config) (*SDK, error)`
  - `func (s *SDK) Verify() *VerifyResult`
  - `func (s *SDK) LicenseInfo() *LicenseInfo`
  - `type VerifyResult struct { Status grace.Status; Message string; Remain time.Duration }`
  - `type LicenseInfo struct { DeviceHash string; ExpiresAt time.Time; Features []string }`

- [ ] **Step 1: Generate test keys and license**

```bash
mkdir -p pkg/sdk/testdata
cd pkg/sdk/testdata

# Generate test keys using Go
go run -e - << 'GOEOF'
package main

import (
    "crypto/ed25519"
    "crypto/rand"
    "encoding/json"
    "encoding/pem"
    "os"
    "time"
)

func main() {
    pub, priv, _ := ed25519.GenerateKey(rand.Reader)

    privPEM := pem.EncodeToMemory(&pem.Block{Type: "ED25519 PRIVATE KEY", Bytes: priv})
    pubPEM := pem.EncodeToMemory(&pem.Block{Type: "ED25519 PUBLIC KEY", Bytes: pub})
    os.WriteFile("test-key.priv", privPEM, 0644)
    os.WriteFile("test-key.pub", pubPEM, 0644)
}
GOEOF
```

Actually, since we can't easily run Go scripts inline, let's just create test keys programmatically in the test setup.

- [ ] **Step 2: Write sdk_test.go**

```go
package sdk

import (
    "crypto/ed25519"
    "crypto/rand"
    "encoding/pem"
    "os"
    "path/filepath"
    "testing"
    "time"

    "device-secret/internal/fingerprint"
    "device-secret/internal/grace"
    "device-secret/internal/license"
)

const testGraceDuration = 1 * time.Hour

func newTestKeys(t *testing.T) (priv ed25519.PrivateKey, pubPEM []byte) {
    t.Helper()
    pub, priv, err := ed25519.GenerateKey(rand.Reader)
    if err != nil {
        t.Fatalf("GenerateKey error: %v", err)
    }
    pubPEM = pem.EncodeToMemory(&pem.Block{Type: "ED25519 PUBLIC KEY", Bytes: pub})
    return priv, pubPEM
}

func makeLicense(t *testing.T, priv ed25519.PrivateKey, hash string, expiresAt time.Time) []byte {
    t.Helper()
    data, err := license.SignLicense(license.LicensePayload{
        Version:    1,
        DeviceHash: hash,
        IssuedAt:   time.Now().Truncate(time.Second),
        ExpiresAt:  expiresAt,
    }, priv)
    if err != nil {
        t.Fatalf("SignLicense error: %v", err)
    }
    return data
}

func TestInit_MissingLicenseFile(t *testing.T) {
    _, pubPEM := newTestKeys(t)
    _, err := Init(Config{
        LicensePath: "/nonexistent/path/license.bin",
        PublicKey:   pubPEM,
    })
    if err == nil {
        t.Error("expected error for missing license file")
    }
}

func TestInit_InvalidPublicKey(t *testing.T) {
    dir := t.TempDir()
    licPath := filepath.Join(dir, "license.bin")
    os.WriteFile(licPath, []byte("dummy"), 0644)

    _, err := Init(Config{
        LicensePath: licPath,
        PublicKey:   []byte("not-a-valid-pem"),
    })
    if err == nil {
        t.Error("expected error for invalid public key")
    }
}

func TestVerify_InvalidSignature(t *testing.T) {
    dir := t.TempDir()
    licPath := filepath.Join(dir, "license.bin")
    markerPath := filepath.Join(dir, ".grace_start")

    priv, pubPEM := newTestKeys(t)
    // Use a different key to sign — this ensures wrong signature
    wrongPriv, _ := newTestKeys(t)
    licData := makeLicense(t, wrongPriv, "sha256:test", time.Now().Add(365*24*time.Hour))
    os.WriteFile(licPath, licData, 0644)

    sdk, err := Init(Config{
        LicensePath:   licPath,
        PublicKey:     pubPEM,
        MarkerPath:    markerPath,
        GraceDuration: testGraceDuration,
    })
    if err != nil {
        t.Fatalf("Init() should succeed even with bad signature (Verify() reports it): %v", err)
    }

    result := sdk.Verify()
    if result.Status != grace.StatusInvalid {
        t.Errorf("expected StatusInvalid for wrong signature, got %v", result.Status)
    }
}

func TestInit_ValidLicense(t *testing.T) {
    dir := t.TempDir()
    licPath := filepath.Join(dir, "license.bin")

    priv, pubPEM := newTestKeys(t)
    // Use a hash that will match — the SDK's fingerprint.Collect() runs on the real system
    // For this test we just verify Init succeeds. The Verify() result depends on
    // whether current system fingerprint matches license hash.
    // We use the sdk's internal state to verify basic Init behavior.
    licData := makeLicense(t, priv, "sha256:will-not-match-real-fingerprint", time.Now().Add(365*24*time.Hour))
    os.WriteFile(licPath, licData, 0644)

    sdk, err := Init(Config{
        LicensePath:   licPath,
        PublicKey:     pubPEM,
        MarkerPath:    filepath.Join(dir, ".grace_start"),
        GraceDuration: testGraceDuration,
    })
    if err != nil {
        t.Fatalf("Init() error = %v", err)
    }
    if sdk == nil {
        t.Fatal("Init() returned nil SDK")
    }

    info := sdk.LicenseInfo()
    if info == nil {
        t.Fatal("LicenseInfo() should not be nil when license is valid")
    }
    if info.ExpiresAt.IsZero() {
        t.Error("ExpiresAt should not be zero")
    }
}

func TestExpiresAt_Remain(t *testing.T) {
    dir := t.TempDir()
    licPath := filepath.Join(dir, "license.bin")
    markerPath := filepath.Join(dir, ".grace_start")

    // Collect real fingerprint so hash matches
    fp, err := fingerprint.Collect()
    if err != nil {
        t.Skipf("cannot collect fingerprint on this system: %v", err)
    }

    priv, pubPEM := newTestKeys(t)
    licData := makeLicense(t, priv, fp.Hash, time.Now().Add(30*24*time.Hour))
    os.WriteFile(licPath, licData, 0644)

    sdk, _ := Init(Config{
        LicensePath:   licPath,
        PublicKey:     pubPEM,
        MarkerPath:    markerPath,
        GraceDuration: testGraceDuration,
    })

    result := sdk.Verify()
    if result.Status != grace.StatusValid {
        t.Fatalf("expected StatusValid, got %v: %s", result.Status, result.Message)
    }
    if result.Remain <= 0 {
        t.Errorf("Remain should be positive for future expiry, got %v", result.Remain)
    }
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./pkg/sdk/ -v`
Expected: FAIL — undefined: Init, Config, etc.

- [ ] **Step 4: Implement pkg/sdk/sdk.go**

```go
package sdk

import (
    "crypto/ed25519"
    "errors"
    "fmt"
    "time"

    "device-secret/internal/fingerprint"
    "device-secret/internal/grace"
    "device-secret/internal/license"
)

type Config struct {
    LicensePath   string
    PublicKey     []byte
    MarkerPath    string
    GraceDuration time.Duration
}

type SDK struct {
    payload     *license.LicensePayload
    pubKey      ed25519.PublicKey
    tracker     *grace.Tracker
    initPassed  bool
}

type VerifyResult struct {
    Status  grace.Status
    Message string
    Remain  time.Duration
}

type LicenseInfo struct {
    DeviceHash string
    ExpiresAt  time.Time
    Features   []string
}

func Init(cfg Config) (*SDK, error) {
    // Parse public key
    pubKey, err := parsePublicKey(cfg.PublicKey)
    if err != nil {
        return nil, fmt.Errorf("sdk: invalid public key: %w", err)
    }

    // Defaults
    if cfg.GraceDuration == 0 {
        cfg.GraceDuration = 7 * 24 * time.Hour
    }
    if cfg.MarkerPath == "" {
        cfg.MarkerPath = "/var/lib/device-secret/.grace_start"
    }

    s := &SDK{
        pubKey: pubKey,
        tracker: &grace.Tracker{
            GraceDuration: cfg.GraceDuration,
            MarkerPath:    cfg.MarkerPath,
        },
    }

    // Read and verify license file
    licData, err := osReadFile(cfg.LicensePath)
    if err != nil {
        return nil, fmt.Errorf("sdk: cannot read license file: %w", err)
    }

    s.payload, err = license.VerifyLicense(licData, pubKey)
    if err != nil {
        // Init succeeds — Verify() will report the failure
        s.initPassed = false
        return s, nil
    }

    s.initPassed = true
    return s, nil
}

func (s *SDK) Verify() *VerifyResult {
    // Check init-time signature verification
    if !s.initPassed {
        return &VerifyResult{
            Status:  grace.StatusInvalid,
            Message: "license signature verification failed",
            Remain:  0,
        }
    }

    // Collect current device fingerprint
    fp, err := fingerprint.Collect()
    if err != nil {
        return &VerifyResult{
            Status:  grace.StatusInvalid,
            Message: fmt.Sprintf("fingerprint collection failed: %v", err),
            Remain:  0,
        }
    }

    // Verify fingerprint match
    if fp.Hash != s.payload.DeviceHash {
        return s.evaluateGracePeriod(false, "device fingerprint mismatch")
    }

    // Verify expiry
    now := time.Now()
    if now.After(s.payload.ExpiresAt) {
        return s.evaluateGracePeriod(false, "license has expired")
    }

    // All checks passed
    remain := s.payload.ExpiresAt.Sub(now)
    return &VerifyResult{
        Status:  s.tracker.Evaluate(true, now),
        Message: fmt.Sprintf("valid, expires in %v", remain.Round(time.Hour)),
        Remain:  remain,
    }
}

func (s *SDK) LicenseInfo() *LicenseInfo {
    if s.payload == nil {
        return nil
    }
    return &LicenseInfo{
        DeviceHash: s.payload.DeviceHash,
        ExpiresAt:  s.payload.ExpiresAt,
        Features:   s.payload.Features,
    }
}

func (s *SDK) evaluateGracePeriod(pass bool, reason string) *VerifyResult {
    now := time.Now()
    status := s.tracker.Evaluate(pass, now)

    var message string
    var remain time.Duration

    switch status {
    case grace.StatusGracePeriod:
        remain = s.tracker.GraceDuration
        message = fmt.Sprintf("WARNING: %s — grace period active, %v remaining", reason, remain)
    case grace.StatusExpired:
        remain = 0
        message = fmt.Sprintf("CRITICAL: %s — grace period expired, license invalid", reason)
    default:
        remain = 0
        message = reason
    }

    return &VerifyResult{
        Status:  status,
        Message: message,
        Remain:  remain,
    }
}

// osReadFile is a variable so tests can replace it.
var osReadFile = func(path string) ([]byte, error) {
    return os.ReadFile(path) // nop
}

func parsePublicKey(pemBytes []byte) (ed25519.PublicKey, error) {
    // Use the crypto package's parser
    block, _ := pem.Decode(pemBytes) // nop
    if block == nil || block.Type ... {
        return nil, errors.New("sdk: invalid PEM data")
    }
    ...
}
```

Wait, I need to be careful here. The SDK depends on `internal/crypto` for PEM parsing, but I'm duplicating PEM parsing. Let me refactor — `pkg/sdk` should import `internal/crypto` for key parsing.

Actually looking at the design doc again, `internal/crypto` has `ParsePublicKey`. The SDK should import it.

But wait — `internal/` packages can't be imported by external projects, but `pkg/sdk` is in the same module, so `pkg/sdk` CAN import `internal/crypto`. That's the whole point of `internal/` — same module can import it, external modules can't.

So let me fix the sdk.go to use `internal/crypto` properly and avoid the `os` import issue.

Let me rewrite the implementation properly:<｜end▁of▁thinking｜>

<｜｜DSML｜｜tool_calls>
<｜｜DSML｜｜invoke name="Bash">
<｜｜DSML｜｜parameter name="command" string="true">cat >> /Users/bingxu/code/kelin-go/device-secret/docs/superpowers/plans/2026-08-11-device-secret.md << 'PLANEOF'

- [ ] **Step 4: Implement pkg/sdk/sdk.go**

```go
package sdk

import (
    "crypto/ed25519"
    "fmt"
    "os"
    "time"

    "device-secret/internal/crypto"
    "device-secret/internal/fingerprint"
    "device-secret/internal/grace"
    "device-secret/internal/license"
)

type Config struct {
    LicensePath   string
    PublicKey     []byte // PEM-encoded Ed25519 public key
    MarkerPath    string // grace period marker file path
    GraceDuration time.Duration
}

type SDK struct {
    payload    *license.LicensePayload
    pubKey     ed25519.PublicKey
    tracker    *grace.Tracker
    initPassed bool
}

type VerifyResult struct {
    Status  grace.Status
    Message string
    Remain  time.Duration
}

type LicenseInfo struct {
    DeviceHash string
    ExpiresAt  time.Time
    Features   []string
}

func Init(cfg Config) (*SDK, error) {
    pubKey, err := crypto.ParsePublicKey(cfg.PublicKey)
    if err != nil {
        return nil, fmt.Errorf("sdk: invalid public key: %w", err)
    }

    if cfg.GraceDuration == 0 {
        cfg.GraceDuration = 7 * 24 * time.Hour
    }
    if cfg.MarkerPath == "" {
        cfg.MarkerPath = "/var/lib/device-secret/.grace_start"
    }

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
    return s, nil
}

func (s *SDK) Verify() *VerifyResult {
    if !s.initPassed {
        return &VerifyResult{
            Status:  grace.StatusInvalid,
            Message: "license signature verification failed",
            Remain:  0,
        }
    }

    fp, err := fingerprint.Collect()
    if err != nil {
        return &VerifyResult{
            Status:  grace.StatusInvalid,
            Message: fmt.Sprintf("fingerprint collection failed: %v", err),
            Remain:  0,
        }
    }

    if fp.Hash != s.payload.DeviceHash {
        return s.evaluateGracePeriod(false, "device fingerprint mismatch")
    }

    now := time.Now()
    if now.After(s.payload.ExpiresAt) {
        return s.evaluateGracePeriod(false, "license has expired")
    }

    remain := s.payload.ExpiresAt.Sub(now)
    return &VerifyResult{
        Status:  s.tracker.Evaluate(true, now),
        Message: fmt.Sprintf("valid, expires in %v", remain.Round(time.Hour)),
        Remain:  remain,
    }
}

func (s *SDK) LicenseInfo() *LicenseInfo {
    if s.payload == nil {
        return nil
    }
    return &LicenseInfo{
        DeviceHash: s.payload.DeviceHash,
        ExpiresAt:  s.payload.ExpiresAt,
        Features:   s.payload.Features,
    }
}

func (s *SDK) evaluateGracePeriod(pass bool, reason string) *VerifyResult {
    now := time.Now()
    status := s.tracker.Evaluate(pass, now)

    var message string
    var remain time.Duration

    switch status {
    case grace.StatusGracePeriod:
        remain = s.tracker.GraceDuration
        message = fmt.Sprintf("WARNING: %s — grace period active, %v remaining", reason, remain)
    case grace.StatusExpired:
        remain = 0
        message = fmt.Sprintf("CRITICAL: %s — grace period expired, license invalid", reason)
    default:
        remain = 0
        message = reason
    }

    return &VerifyResult{
        Status:  status,
        Message: message,
        Remain:  remain,
    }
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./pkg/sdk/ -v`
Expected: all PASS (note: the `TestInit_ValidLicense` test verifies basic init; fingerprint matching tests will fail on CI if test keys don't match the test system's actual fingerprint — that's expected and those tests should be structured to test init behavior, not fingerprint matching)

- [ ] **Step 6: Commit**

```bash
git add pkg/sdk/
git commit -m "feat: add public SDK API (pkg/sdk)"
```

---

### Task 7: cmd/fingerprint — Fingerprint CLI

**Files:**
- Modify: `cmd/fingerprint/main.go` (replace stub)

**Interfaces:**
- Consumes: `internal/fingerprint` — `Collect()`, `GetDeviceMeta()`, `RequestFile`
- Produces: CLI binary `bin/fingerprint`

- [ ] **Step 1: Write cmd/fingerprint/main.go**

```go
package main

import (
    "encoding/json"
    "flag"
    "fmt"
    "os"
    "time"

    "device-secret/internal/fingerprint"
)

func main() {
    output := flag.String("o", "", "output path (default: stdout)")
    pretty := flag.Bool("pretty", false, "pretty-print JSON output")
    flag.Parse()

    fp, err := fingerprint.Collect()
    if err != nil {
        fmt.Fprintf(os.Stderr, "fingerprint: %v\n", err)
        os.Exit(1)
    }

    req := fingerprint.RequestFile{
        Version:     1,
        Device:      fingerprint.GetDeviceMeta(),
        Fingerprint: *fp,
        RequestedAt: time.Now(),
    }

    var data []byte
    if *pretty {
        data, err = json.MarshalIndent(req, "", "  ")
    } else {
        data, err = json.Marshal(req)
    }
    if err != nil {
        fmt.Fprintf(os.Stderr, "fingerprint: failed to encode output: %v\n", err)
        os.Exit(1)
    }

    if *output != "" {
        if err := os.WriteFile(*output, data, 0644); err != nil {
            fmt.Fprintf(os.Stderr, "fingerprint: failed to write %s: %v\n", *output, err)
            os.Exit(1)
        }
        fmt.Printf("Request file written to %s\n", *output)
    } else {
        fmt.Println(string(data))
    }
}
```

- [ ] **Step 2: Build and smoke-test the CLI**

```bash
go build -o bin/fingerprint ./cmd/fingerprint
./bin/fingerprint -pretty
```

Expected: prints JSON request file to stdout. Verify `device.hostname` matches `hostname`, `fingerprint.hash` starts with `sha256:`, and `fingerprint.sources` has non-empty values.

- [ ] **Step 3: Test output to file**

```bash
./bin/fingerprint -o /tmp/test-request.json
cat /tmp/test-request.json | python3 -m json.tool
rm /tmp/test-request.json
```

Expected: valid JSON, no errors.

- [ ] **Step 4: Commit**

```bash
git add cmd/fingerprint/main.go
git commit -m "feat: implement fingerprint CLI"
```

---

### Task 8: cmd/license-gen — License Generation CLI

**Files:**
- Modify: `cmd/license-gen/main.go` (replace stub)

**Interfaces:**
- Consumes:
  - `internal/crypto` — `ParsePrivateKey()`
  - `internal/license` — `SignLicense()`, `LicensePayload`
  - `internal/fingerprint` — `RequestFile`
- Produces: CLI binary `bin/license-gen`

- [ ] **Step 1: Write cmd/license-gen/main.go**

```go
package main

import (
    "encoding/json"
    "flag"
    "fmt"
    "os"
    "time"

    "device-secret/internal/crypto"
    "device-secret/internal/fingerprint"
    "device-secret/internal/license"
)

func main() {
    requestPath := flag.String("request", "", "request file path (required)")
    keyPath := flag.String("key", "", "Ed25519 private key PEM path (required)")
    expires := flag.String("expires", "", "expiry time, ISO8601 or relative like '+365d' (required)")
    features := flag.String("features", "", "comma-separated feature modules (optional)")
    metadata := flag.String("metadata", "", "metadata note (optional)")
    kid := flag.String("kid", "", "key ID for rotation (optional)")
    output := flag.String("o", "", "output path (default: stdout)")
    pretty := flag.Bool("pretty", false, "pretty-print for debugging (do not use for production)")
    flag.Parse()

    if *requestPath == "" || *keyPath == "" || *expires == "" {
        fmt.Fprintf(os.Stderr, "usage: license-gen -request <path> -key <path> -expires <time>\n")
        os.Exit(1)
    }

    // Parse expiry
    expiresAt, err := parseExpiry(*expires)
    if err != nil {
        fmt.Fprintf(os.Stderr, "license-gen: invalid expiry: %v\n", err)
        os.Exit(1)
    }

    // Read request file
    reqData, err := os.ReadFile(*requestPath)
    if err != nil {
        fmt.Fprintf(os.Stderr, "license-gen: cannot read request file: %v\n", err)
        os.Exit(1)
    }
    var req fingerprint.RequestFile
    if err := json.Unmarshal(reqData, &req); err != nil {
        fmt.Fprintf(os.Stderr, "license-gen: invalid request file: %v\n", err)
        os.Exit(1)
    }

    // Read private key
    keyPEM, err := os.ReadFile(*keyPath)
    if err != nil {
        fmt.Fprintf(os.Stderr, "license-gen: cannot read key file: %v\n", err)
        os.Exit(1)
    }
    priv, err := crypto.ParsePrivateKey(keyPEM)
    if err != nil {
        fmt.Fprintf(os.Stderr, "license-gen: invalid private key: %v\n", err)
        os.Exit(1)
    }

    // Parse features
    var featList []string
    if *features != "" {
        featList = splitAndTrim(*features, ",")
    }

    // Sign license
    payload := license.LicensePayload{
        Version:    1,
        KID:        *kid,
        DeviceHash: req.Fingerprint.Hash,
        IssuedAt:   time.Now(),
        ExpiresAt:  expiresAt,
        Features:   featList,
        Metadata:   *metadata,
    }

    licData, err := license.SignLicense(payload, priv)
    if err != nil {
        fmt.Fprintf(os.Stderr, "license-gen: signing failed: %v\n", err)
        os.Exit(1)
    }

    if *pretty {
        // Debug mode: output the JSON payload (unsigned) for inspection
        dbg, _ := json.MarshalIndent(payload, "", "  ")
        fmt.Println(string(dbg))
        return
    }

    if *output != "" {
        if err := os.WriteFile(*output, licData, 0644); err != nil {
            fmt.Fprintf(os.Stderr, "license-gen: failed to write %s: %v\n", *output, err)
            os.Exit(1)
        }
        fmt.Printf("License written to %s\n", *output)
    } else {
        fmt.Println(string(licData))
    }
}

func parseExpiry(s string) (time.Time, error) {
    // Try relative duration first: "+365d", "+30d"
    if len(s) > 1 && s[0] == '+' {
        d, err := time.ParseDuration(s[1:] + "h") // crude: use "d" as hour placeholder
        if err == nil {
            return time.Now().Add(d), nil
        }
        // Better relative parsing
    }
    // ... handle relative durations properly
    // Try ISO8601
    formats := []string{
        time.RFC3339,
        "2006-01-02T15:04:05Z",
        "2006-01-02",
    }
    for _, f := range formats {
        if t, err := time.Parse(f, s); err == nil {
            return t, nil
        }
    }
    return time.Time{}, fmt.Errorf("cannot parse %q", s)
}

func splitAndTrim(s, sep string) []string {
    parts := []string{}
    for _, p := range split(s, sep) {
        p = trim(p)
        if p != "" {
            parts = append(parts, p)
        }
    }
    return parts
}

func split(s, sep string) []string {
    // minimal split implementation to avoid importing strings
    result := []string{}
    current := ""
    for _, c := range s {
        if string(c) == sep {
            result = append(result, current)
            current = ""
            continue
        }
        current += string(c)
    }
    result = append(result, current)
    return result
}

func trim(s string) string {
    // minimal trim
    start, end := 0, len(s)
    for start < end && (s[start] == ' ' || s[start] == '\t') {
        start++
    }
    for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
        end--
    }
    return s[start:end]
}
```

Wait — that's silly. Just import "strings". Let me simplify this. And the relative duration parsing is hacky. Let me rewrite properly.

- [ ] **Step 1 (rewrite): Write cmd/license-gen/main.go**

```go
package main

import (
    "encoding/json"
    "flag"
    "fmt"
    "os"
    "strconv"
    "strings"
    "time"

    "device-secret/internal/crypto"
    "device-secret/internal/fingerprint"
    "device-secret/internal/license"
)

func main() {
    requestPath := flag.String("request", "", "request file path (required)")
    keyPath := flag.String("key", "", "Ed25519 private key PEM path (required)")
    expires := flag.String("expires", "", "expiry: ISO8601 datetime or relative like '+365d' (required)")
    features := flag.String("features", "", "comma-separated feature modules (optional)")
    metadata := flag.String("metadata", "", "metadata note (optional)")
    kid := flag.String("kid", "", "key ID for rotation (optional)")
    output := flag.String("o", "", "output path (default: stdout)")
    flag.Parse()

    if *requestPath == "" || *keyPath == "" || *expires == "" {
        fmt.Fprintf(os.Stderr, "usage: license-gen -request <path> -key <path> -expires <time>\n")
        os.Exit(1)
    }

    expiresAt, err := parseExpiry(*expires)
    if err != nil {
        fmt.Fprintf(os.Stderr, "license-gen: invalid expiry %q: %v\n", *expires, err)
        os.Exit(1)
    }

    // Read request file
    reqData, err := os.ReadFile(*requestPath)
    if err != nil {
        fmt.Fprintf(os.Stderr, "license-gen: cannot read request file: %v\n", err)
        os.Exit(1)
    }
    var req fingerprint.RequestFile
    if err := json.Unmarshal(reqData, &req); err != nil {
        fmt.Fprintf(os.Stderr, "license-gen: invalid request file: %v\n", err)
        os.Exit(1)
    }

    // Read private key
    keyPEM, err := os.ReadFile(*keyPath)
    if err != nil {
        fmt.Fprintf(os.Stderr, "license-gen: cannot read key file: %v\n", err)
        os.Exit(1)
    }
    priv, err := crypto.ParsePrivateKey(keyPEM)
    if err != nil {
        fmt.Fprintf(os.Stderr, "license-gen: invalid private key: %v\n", err)
        os.Exit(1)
    }

    var featList []string
    if *features != "" {
        for _, f := range strings.Split(*features, ",") {
            f = strings.TrimSpace(f)
            if f != "" {
                featList = append(featList, f)
            }
        }
    }

    payload := license.LicensePayload{
        Version:    1,
        KID:        *kid,
        DeviceHash: req.Fingerprint.Hash,
        IssuedAt:   time.Now(),
        ExpiresAt:  expiresAt,
        Features:   featList,
        Metadata:   *metadata,
    }

    licData, err := license.SignLicense(payload, priv)
    if err != nil {
        fmt.Fprintf(os.Stderr, "license-gen: signing failed: %v\n", err)
        os.Exit(1)
    }

    if *output != "" {
        if err := os.WriteFile(*output, licData, 0644); err != nil {
            fmt.Fprintf(os.Stderr, "license-gen: failed to write %s: %v\n", *output, err)
            os.Exit(1)
        }
        fmt.Printf("License written to %s\n", *output)
    } else {
        fmt.Println(string(licData))
    }
}

func parseExpiry(s string) (time.Time, error) {
    // Relative duration: "+365d", "+30d"
    if strings.HasPrefix(s, "+") && strings.HasSuffix(s, "d") {
        days, err := strconv.Atoi(s[1 : len(s)-1])
        if err != nil {
            return time.Time{}, fmt.Errorf("invalid relative duration: %s", s)
        }
        return time.Now().Add(time.Duration(days) * 24 * time.Hour), nil
    }

    // ISO8601 formats
    formats := []string{
        time.RFC3339,
        "2006-01-02T15:04:05Z",
        "2006-01-02",
    }
    for _, f := range formats {
        if t, err := time.Parse(f, s); err == nil {
            return t, nil
        }
    }
    return time.Time{}, fmt.Errorf("unsupported format: %s (use ISO8601 or +Nd)", s)
}
```

- [ ] **Step 2: Build the CLI**

```bash
go build -o bin/license-gen ./cmd/license-gen
```

- [ ] **Step 3: End-to-end smoke test**

```bash
# Generate a test key pair
go run -e << 'GOEOF'
package main
import (
    "device-secret/internal/crypto"
    "os"
)
func main() {
    priv, pub, _ := crypto.GenerateKeyPair()
    privPEM, _ := crypto.MarshalPrivateKey(priv)
    pubPEM, _ := crypto.MarshalPublicKey(pub)
    os.WriteFile("/tmp/test-key.priv", privPEM, 0644)
    os.WriteFile("/tmp/test-key.pub", pubPEM, 0644)
}
GOEOF
```

Note: If the above inline Go script is problematic, create a temporary `cmd/keygen/main.go`:

```bash
mkdir -p /tmp/keygen
cat > /tmp/keygen/main.go << 'GOEOF'
package main
import ("device-secret/internal/crypto"; "os"; "fmt")
func main() {
    priv, pub, _ := crypto.GenerateKeyPair()
    p1, _ := crypto.MarshalPrivateKey(priv)
    p2, _ := crypto.MarshalPublicKey(pub)
    os.WriteFile("/tmp/test-key.priv", p1, 0644)
    os.WriteFile("/tmp/test-key.pub", p2, 0644)
    fmt.Println("keys generated")
}
GOEOF
go run /tmp/keygen/main.go
rm -rf /tmp/keygen
```

Then test the full flow:

```bash
# 1. Generate fingerprint request
./bin/fingerprint -o /tmp/test-request.json

# 2. Generate license
./bin/license-gen -request /tmp/test-request.json -key /tmp/test-key.priv -expires +365d -o /tmp/test-license.bin

# 3. Verify the license file is not empty and has the right format (base64.base64)
cat /tmp/test-license.bin
```

Expected: license.bin contains a base64 string, a dot, then another base64 string.

- [ ] **Step 4: Commit**

```bash
git add cmd/license-gen/main.go
git commit -m "feat: implement license-gen CLI"
```

---

### Task 9: Integration Tests & Key Generation Utility

**Files:**
- Create: `cmd/keygen/main.go` (utility to generate Ed25519 key pairs)
- Create: `internal/fingerprint/collector_integration_test.go` (build tag: integration)
- Update: `Makefile` (add keygen target)

**Interfaces:**
- Consumes: all previous tasks
- Produces: integration test suite, keygen utility

- [ ] **Step 1: Create keygen utility**

File: `cmd/keygen/main.go`

```go
package main

import (
    "flag"
    "fmt"
    "os"

    "device-secret/internal/crypto"
)

func main() {
    outPriv := flag.String("out", "private.pem", "private key output path")
    outPub := flag.String("pub", "public.pem", "public key output path")
    flag.Parse()

    priv, pub, err := crypto.GenerateKeyPair()
    if err != nil {
        fmt.Fprintf(os.Stderr, "keygen: %v\n", err)
        os.Exit(1)
    }

    privPEM, err := crypto.MarshalPrivateKey(priv)
    if err != nil {
        fmt.Fprintf(os.Stderr, "keygen: %v\n", err)
        os.Exit(1)
    }
    pubPEM, err := crypto.MarshalPublicKey(pub)
    if err != nil {
        fmt.Fprintf(os.Stderr, "keygen: %v\n", err)
        os.Exit(1)
    }

    if err := os.WriteFile(*outPriv, privPEM, 0600); err != nil {
        fmt.Fprintf(os.Stderr, "keygen: %v\n", err)
        os.Exit(1)
    }
    if err := os.WriteFile(*outPub, pubPEM, 0644); err != nil {
        fmt.Fprintf(os.Stderr, "keygen: %v\n", err)
        os.Exit(1)
    }

    fmt.Printf("Private key: %s\nPublic key:  %s\n", *outPriv, *outPub)
}
```

- [ ] **Step 2: Update Makefile with keygen target**

Add to Makefile:

```makefile
build: build-fingerprint build-license-gen build-keygen

build-keygen:
	CGO_ENABLED=0 go build -o bin/keygen ./cmd/keygen
```

- [ ] **Step 3: Create integration test**

File: `internal/fingerprint/collector_integration_test.go`

```go
//go:build integration
// +build integration

package fingerprint

import (
    "testing"
)

func TestCollect_RealSystem(t *testing.T) {
    // This test runs on real hardware, not mock filesystem.
    // It verifies the collector works on the actual platform.

    // Reset any test overrides
    basePath = ""
    readFile = nil
    readDir = nil

    fp, err := Collect()
    if err != nil {
        t.Fatalf("Collect() failed on real system: %v", err)
    }

    if fp.Hash == "" {
        t.Error("hash should not be empty on real system")
    }
    t.Logf("Platform: %s/%s", GetDeviceMeta().OS, GetDeviceMeta().Arch)
    t.Logf("Hash: %s", fp.Hash)
    t.Logf("Sources: %+v", fp.Sources)

    // Verify deterministic: collect again, hash must match
    fp2, err := Collect()
    if err != nil {
        t.Fatalf("second Collect() failed: %v", err)
    }
    if fp.Hash != fp2.Hash {
        t.Errorf("fingerprint not deterministic: %s != %s", fp.Hash, fp2.Hash)
    }
}
```

- [ ] **Step 4: Run integration tests (on real hardware)**

```bash
go test -tags=integration ./internal/fingerprint/ -v
```

Expected: PASS on both ARM (RK3568) and x86 hardware. Two consecutive collections produce identical hash.

- [ ] **Step 5: Full end-to-end test**

```bash
# Generate keys
./bin/keygen -out /tmp/private.pem -pub /tmp/public.pem

# Generate fingerprint
./bin/fingerprint -o /tmp/request.json

# Generate license (1 year)
./bin/license-gen -request /tmp/request.json -key /tmp/private.pem -expires +365d -o /tmp/license.bin

# Write a small Go program to verify the license
cat > /tmp/verify/main.go << 'GOEOF'
package main
import (
    "fmt"
    "os"
    "device-secret/pkg/sdk"
)
func main() {
    pubKey, _ := os.ReadFile("/tmp/public.pem")
    s, err := sdk.Init(sdk.Config{
        LicensePath: "/tmp/license.bin",
        PublicKey:   pubKey,
        MarkerPath:  "/tmp/.grace_start",
    })
    if err != nil {
        fmt.Printf("Init error: %v\n", err)
        os.Exit(1)
    }
    result := s.Verify()
    fmt.Printf("Status: %v\n", result.Status)
    fmt.Printf("Message: %s\n", result.Message)
    fmt.Printf("Remain: %v\n", result.Remain)
    if result.Status != 0 { // 0 = StatusValid
        os.Exit(1)
    }
}
GOEOF
go run /tmp/verify/main.go
rm -rf /tmp/verify
```

Expected: `Status: Valid`, `Remain: ~8760h` (365 days).

- [ ] **Step 6: Commit**

```bash
git add cmd/keygen/main.go Makefile internal/fingerprint/collector_integration_test.go
git commit -m "feat: add keygen utility and integration tests"
```

---

### Task 10: Final Verification & Build

**Files:**
- No new files

- [ ] **Step 1: Run all unit tests**

```bash
go test ./...
```

Expected: all PASS.

- [ ] **Step 2: Run linter**

```bash
golangci-lint run ./...
```

- [ ] **Step 3: Build all binaries**

```bash
make build
```

Expected: `bin/fingerprint`, `bin/license-gen`, `bin/keygen` all produced.

- [ ] **Step 4: Verify binary properties**

```bash
file bin/fingerprint
file bin/license-gen
file bin/keygen
```

Expected: all show "statically linked" or "ELF 64-bit LSB executable".

- [ ] **Step 5: Commit any remaining changes**

```bash
git add -A
git commit -m "chore: final verification, all tests pass"
```
