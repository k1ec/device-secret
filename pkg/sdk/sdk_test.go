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

func writeLicense(t *testing.T, dir string, licData []byte) string {
	t.Helper()
	licPath := filepath.Join(dir, "license.bin")
	if err := os.WriteFile(licPath, licData, 0o644); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}
	return licPath
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
	if err := os.WriteFile(licPath, []byte("dummy"), 0o644); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

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

	_, pubPEM := newTestKeys(t)
	// Use a different key to sign — this ensures wrong signature
	wrongPriv, _ := newTestKeys(t)
	licData := makeLicense(t, wrongPriv, "sha256:test", time.Now().Add(365*24*time.Hour))
	if err := os.WriteFile(licPath, licData, 0o644); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

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
	// Use a hash that will not match any real device — this test only
	// verifies Init behavior, not fingerprint matching.
	licData := makeLicense(t, priv, "sha256:will-not-match-real-fingerprint", time.Now().Add(365*24*time.Hour))
	if err := os.WriteFile(licPath, licData, 0o644); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

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
	if err := os.WriteFile(licPath, licData, 0o644); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	sdk, err := Init(Config{
		LicensePath:   licPath,
		PublicKey:     pubPEM,
		MarkerPath:    markerPath,
		GraceDuration: testGraceDuration,
	})
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	result := sdk.Verify()
	if result.Status != grace.StatusValid {
		t.Fatalf("expected StatusValid, got %v: %s", result.Status, result.Message)
	}
	if result.Remain <= 0 {
		t.Errorf("Remain should be positive for future expiry, got %v", result.Remain)
	}
}

func TestInit_DefaultGraceDuration(t *testing.T) {
	dir := t.TempDir()
	priv, pubPEM := newTestKeys(t)
	licData := makeLicense(t, priv, "sha256:test", time.Now().Add(24*time.Hour))
	licPath := writeLicense(t, dir, licData)

	// GraceDuration omitted — Init must default to 7 days.
	sdk, err := Init(Config{
		LicensePath: licPath,
		PublicKey:   pubPEM,
		MarkerPath:  filepath.Join(dir, ".grace_start"),
	})
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	if got := sdk.tracker.GraceDuration; got != 7*24*time.Hour {
		t.Errorf("GraceDuration = %v, want 168h (7 days)", got)
	}
}

func TestApplyDefaults(t *testing.T) {
	// Zero Config gets the 7-day grace period and default marker path.
	var cfg Config
	applyDefaults(&cfg)
	if cfg.GraceDuration != 7*24*time.Hour {
		t.Errorf("GraceDuration = %v, want 168h (7 days)", cfg.GraceDuration)
	}
	if cfg.MarkerPath != "/var/lib/device-secret/.grace_start" {
		t.Errorf("MarkerPath = %q, want /var/lib/device-secret/.grace_start", cfg.MarkerPath)
	}

	// Explicit values must not be overwritten.
	cfg = Config{GraceDuration: 5 * time.Minute, MarkerPath: "/tmp/marker"}
	applyDefaults(&cfg)
	if cfg.GraceDuration != 5*time.Minute {
		t.Errorf("GraceDuration = %v, want explicit 5m", cfg.GraceDuration)
	}
	if cfg.MarkerPath != "/tmp/marker" {
		t.Errorf("MarkerPath = %q, want explicit /tmp/marker", cfg.MarkerPath)
	}
}

func TestInit_CreatesMarkerParentDir(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "a", "b") // does not exist yet
	priv, pubPEM := newTestKeys(t)
	licData := makeLicense(t, priv, "sha256:test", time.Now().Add(24*time.Hour))
	licPath := writeLicense(t, dir, licData)

	if _, err := Init(Config{
		LicensePath:   licPath,
		PublicKey:     pubPEM,
		MarkerPath:    filepath.Join(nested, ".grace_start"),
		GraceDuration: testGraceDuration,
	}); err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	if fi, err := os.Stat(nested); err != nil || !fi.IsDir() {
		t.Errorf("marker parent dir %s not created (err=%v)", nested, err)
	}
}

func TestVerify_NilReceiver(t *testing.T) {
	var s *SDK
	if r := s.Verify(); r == nil || r.Status != grace.StatusInvalid {
		t.Errorf("Verify() on nil receiver = %+v, want StatusInvalid", r)
	}
	if s.LicenseInfo() != nil {
		t.Error("LicenseInfo() on nil receiver should return nil")
	}
}

func TestLicenseInfo_NilWhenLicenseInvalid(t *testing.T) {
	dir := t.TempDir()
	priv, pubPEM := newTestKeys(t)
	licData := makeLicense(t, priv, "sha256:test", time.Now().Add(24*time.Hour))
	licData[len(licData)-1] ^= 0xff // corrupt the signature

	licPath := writeLicense(t, dir, licData)
	sdk, err := Init(Config{
		LicensePath:   licPath,
		PublicKey:     pubPEM,
		MarkerPath:    filepath.Join(dir, ".grace_start"),
		GraceDuration: testGraceDuration,
	})
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	if info := sdk.LicenseInfo(); info != nil {
		t.Errorf("LicenseInfo() = %+v, want nil for invalid license", info)
	}
}

func TestVerify_GracePeriodLifecycle(t *testing.T) {
	if _, err := fingerprint.Collect(); err != nil {
		t.Skipf("cannot collect fingerprint on this system: %v", err)
	}

	dir := t.TempDir()
	markerPath := filepath.Join(dir, ".grace_start")

	priv, pubPEM := newTestKeys(t)
	// License bound to a hash that will never match the real device.
	licData := makeLicense(t, priv, "sha256:does-not-match-any-device", time.Now().Add(24*time.Hour))
	licPath := writeLicense(t, dir, licData)

	sdk, err := Init(Config{
		LicensePath:   licPath,
		PublicKey:     pubPEM,
		MarkerPath:    markerPath,
		GraceDuration: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	// First failure enters the grace period and persists the marker.
	r := sdk.Verify()
	if r.Status != grace.StatusGracePeriod {
		t.Fatalf("first Verify() = %v (%s), want GracePeriod", r.Status, r.Message)
	}
	if _, err := os.Stat(markerPath); err != nil {
		t.Errorf("marker file not created after first failure: %v", err)
	}

	// After the duration elapses, the next failure expires the license.
	time.Sleep(200 * time.Millisecond)
	r = sdk.Verify()
	if r.Status != grace.StatusExpired {
		t.Errorf("second Verify() = %v (%s), want Expired", r.Status, r.Message)
	}
}
