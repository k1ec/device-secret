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
