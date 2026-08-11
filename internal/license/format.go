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
