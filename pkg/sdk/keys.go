package sdk

import (
	"crypto/ed25519"
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"

	"device-secret/internal/crypto"
)

// validKidRE defines the allowed characters and length for a kid.
// Must match ^[a-zA-Z0-9_-]{1,64}$
var validKidRE = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

// loadKeys scans an fs.FS for *.pem files, extracts the kid from each
// filename (name without .pem extension; "default" maps to ""), and
// returns a map from kid to parsed Ed25519 public key.
func loadKeys(keyFS fs.FS) (map[string]ed25519.PublicKey, error) {
	entries, err := fs.ReadDir(keyFS, ".")
	if err != nil {
		return nil, fmt.Errorf("cannot read key directory: %w", err)
	}

	keys := make(map[string]ed25519.PublicKey)
	hasPEM := false

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if filepath.Ext(name) != ".pem" {
			continue
		}

		hasPEM = true
		kid := strings.TrimSuffix(name, ".pem")

		// "default" maps to empty-string kid (matches licenses without kid)
		if kid == "default" {
			kid = ""
		} else if !validKidRE.MatchString(kid) {
			return nil, fmt.Errorf("invalid kid %q in key file %q: must match %s", kid, name, validKidRE.String())
		}

		if _, exists := keys[kid]; exists {
			return nil, fmt.Errorf("duplicate kid %q", kid)
		}

		pemBytes, err := fs.ReadFile(keyFS, name)
		if err != nil {
			return nil, fmt.Errorf("cannot read key file %q: %w", name, err)
		}

		pubKey, err := crypto.ParsePublicKey(pemBytes)
		if err != nil {
			return nil, fmt.Errorf("invalid PEM in key file %q: %w", name, err)
		}

		keys[kid] = pubKey
	}

	if !hasPEM {
		return nil, fmt.Errorf("no key files found in KeyFS")
	}

	return keys, nil
}
