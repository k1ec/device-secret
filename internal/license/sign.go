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
