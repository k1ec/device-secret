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
