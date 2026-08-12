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
