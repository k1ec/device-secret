//go:build integration
// +build integration

package fingerprint

import (
	"os"
	"runtime"
	"testing"
)

func TestCollect_RealSystem(t *testing.T) {
	// This test runs on real hardware, not mock filesystem.
	// It verifies the collector works on the actual platform.
	if runtime.GOOS != "linux" {
		t.Skip("integration test requires Linux (collector reads /proc, /sys, /etc/machine-id)")
	}

	// Reset any test overrides to real filesystem access
	basePath = ""
	readFile = os.ReadFile
	readDir = func(path string) ([]string, error) {
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
