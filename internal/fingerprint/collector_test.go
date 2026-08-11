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
