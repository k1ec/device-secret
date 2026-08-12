package sdk

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"testing"
	"testing/fstest"
)

func testPEMBytes(t *testing.T) []byte {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "ED25519 PUBLIC KEY", Bytes: pub})
}

func TestLoadKeys_SingleDefault(t *testing.T) {
	pemBytes := testPEMBytes(t)
	mapFS := fstest.MapFS{
		"default.pem": &fstest.MapFile{Data: pemBytes},
	}
	keys, err := loadKeys(mapFS)
	if err != nil {
		t.Fatalf("loadKeys() error = %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if _, ok := keys[""]; !ok {
		t.Error(`expected key with kid="" from default.pem`)
	}
}

func TestLoadKeys_MultipleKids(t *testing.T) {
	pem1 := testPEMBytes(t)
	pem2 := testPEMBytes(t)
	pem3 := testPEMBytes(t)
	mapFS := fstest.MapFS{
		"default.pem":       &fstest.MapFile{Data: pem1},
		"2026-primary.pem":  &fstest.MapFile{Data: pem2},
		"2027-rotation.pem": &fstest.MapFile{Data: pem3},
	}
	keys, err := loadKeys(mapFS)
	if err != nil {
		t.Fatalf("loadKeys() error = %v", err)
	}
	if len(keys) != 3 {
		t.Fatalf("expected 3 keys, got %d", len(keys))
	}
	for _, kid := range []string{"", "2026-primary", "2027-rotation"} {
		if _, ok := keys[kid]; !ok {
			t.Errorf("missing key for kid %q", kid)
		}
	}
}

func TestLoadKeys_InvalidKidName(t *testing.T) {
	pemBytes := testPEMBytes(t)
	badNames := []string{
		"../evil.pem",
		"has space.pem",
		".pem",
		"kid=bad.pem",
	}
	for _, name := range badNames {
		mapFS := fstest.MapFS{
			name: &fstest.MapFile{Data: pemBytes},
		}
		_, err := loadKeys(mapFS)
		if err == nil {
			t.Errorf("loadKeys(%q) expected error for invalid kid name", name)
		}
	}
}

func TestLoadKeys_InvalidPEM(t *testing.T) {
	mapFS := fstest.MapFS{
		"default.pem": &fstest.MapFile{Data: []byte("not valid pem")},
	}
	_, err := loadKeys(mapFS)
	if err == nil {
		t.Error("loadKeys() expected error for invalid PEM content")
	}
}

func TestLoadKeys_EmptyDir(t *testing.T) {
	mapFS := fstest.MapFS{}
	_, err := loadKeys(mapFS)
	if err == nil {
		t.Error("loadKeys() expected error for empty directory")
	}
}

func TestLoadKeys_DuplicateKid(t *testing.T) {
	pem1 := testPEMBytes(t)
	pem2 := testPEMBytes(t)
	mapFS := fstest.MapFS{
		"2026.pem":         &fstest.MapFile{Data: pem1},
		"2026-primary.pem": &fstest.MapFile{Data: pem2},
	}
	keys, err := loadKeys(mapFS)
	if err != nil {
		t.Fatalf("loadKeys() error = %v", err)
	}
	if len(keys) != 2 {
		t.Errorf("different filenames produce different kids, expected 2 keys, got %d", len(keys))
	}
}

func TestLoadKeys_NonPEMIgnored(t *testing.T) {
	pemBytes := testPEMBytes(t)
	mapFS := fstest.MapFS{
		"default.pem": &fstest.MapFile{Data: pemBytes},
		"README.txt":  &fstest.MapFile{Data: []byte("not a key")},
		"notes.md":    &fstest.MapFile{Data: []byte("# notes")},
	}
	keys, err := loadKeys(mapFS)
	if err != nil {
		t.Fatalf("loadKeys() error = %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("non-.pem files should be ignored, got %d keys", len(keys))
	}
}
