// Package sdk is the public, embeddable verification API for the
// device-secret licensing system. Applications call Init once at startup and
// Verify whenever a licensing decision is needed.
//
// All public functions return errors instead of panicking.
package sdk

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

// Defaults applied by Init when the corresponding Config fields are zero.
const (
	defaultGraceDuration = 30 * 24 * time.Hour // 30 days
	defaultMarkerPath    = "/var/lib/device-secret/.grace_start"
)

// Config configures the SDK.
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

// SDK is the license verification entry point. Construct it with Init.
type SDK struct {
	payload    *license.LicensePayload
	pubKey     ed25519.PublicKey
	tracker    *grace.Tracker
	initPassed bool
}

// VerifyResult is the outcome of a verification, including grace period
// status and, on success, the time remaining until expiry.
type VerifyResult struct {
	Status  grace.Status
	Message string
	Remain  time.Duration
}

// LicenseInfo exposes the verified license payload to the application.
// It is nil when the license could not be verified.
type LicenseInfo struct {
	KID        string // Key ID from the license payload
	DeviceHash string
	ExpiresAt  time.Time
	Features   []string
}

// Init parses the public key, loads and signature-verifies the license file,
// and prepares the grace period tracker. It never panics.
//
// A license with an invalid signature or format does not fail Init: the SDK
// is returned and Verify() reports StatusInvalid. Init only fails on missing
// license file, invalid public key, or an unwritable marker directory.
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
	// state can be persisted on fresh deployments. Without this, marker
	// writes silently fail and the grace period never expires.
	if dir := filepath.Dir(cfg.MarkerPath); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("sdk: cannot create marker directory: %w", err)
		}
	}

	return s, nil
}

// applyDefaults fills zero Config fields with their documented defaults.
func applyDefaults(cfg *Config) {
	if cfg.GraceDuration == 0 {
		cfg.GraceDuration = defaultGraceDuration
	}
	if cfg.MarkerPath == "" {
		cfg.MarkerPath = defaultMarkerPath
	}
}

// Verify re-collects the device fingerprint, checks the license signature,
// device fingerprint match, and expiry, applying the grace period as needed.
// It never panics, including on a nil receiver.
func (s *SDK) Verify() *VerifyResult {
	if s == nil {
		return &VerifyResult{
			Status:  grace.StatusInvalid,
			Message: "sdk: Verify() called on nil SDK",
		}
	}

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

// LicenseInfo returns the verified license payload, or nil when the license
// failed verification or the receiver is nil. It never panics.
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

// evaluateGracePeriod runs the tracker against a failed check (pass=false)
// and renders a human-readable result.
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
