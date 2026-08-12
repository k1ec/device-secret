package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"device-secret/internal/crypto"
	"device-secret/internal/fingerprint"
	"device-secret/internal/license"
)

var validKidRE = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

func main() {
	requestPath := flag.String("request", "", "request file path (required)")
	keyPath := flag.String("key", "", "Ed25519 private key PEM path (required)")
	expires := flag.String("expires", "", "expiry: ISO8601 datetime or relative like '+365d' (required)")
	features := flag.String("features", "", "comma-separated feature modules (optional)")
	metadata := flag.String("metadata", "", "metadata note (optional)")
	kid := flag.String("kid", "", "key ID for rotation (optional)")
	output := flag.String("o", "", "output path (default: stdout)")
	flag.Parse()

	// Validate kid format if provided
	if *kid != "" {
		if !validKidRE.MatchString(*kid) {
			fmt.Fprintf(os.Stderr, "license-gen: invalid kid %q: must match %s (1-64 chars: letters, digits, hyphens, underscores)\n", *kid, validKidRE.String())
			os.Exit(1)
		}
	}

	if *requestPath == "" || *keyPath == "" || *expires == "" {
		fmt.Fprintf(os.Stderr, "usage: license-gen -request <path> -key <path> -expires <time>\n")
		os.Exit(1)
	}

	expiresAt, err := parseExpiry(*expires)
	if err != nil {
		fmt.Fprintf(os.Stderr, "license-gen: invalid expiry %q: %v\n", *expires, err)
		os.Exit(1)
	}

	// Read request file
	reqData, err := os.ReadFile(*requestPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "license-gen: cannot read request file: %v\n", err)
		os.Exit(1)
	}
	var req fingerprint.RequestFile
	if err := json.Unmarshal(reqData, &req); err != nil {
		fmt.Fprintf(os.Stderr, "license-gen: invalid request file: %v\n", err)
		os.Exit(1)
	}

	// Read private key
	keyPEM, err := os.ReadFile(*keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "license-gen: cannot read key file: %v\n", err)
		os.Exit(1)
	}
	priv, err := crypto.ParsePrivateKey(keyPEM)
	if err != nil {
		fmt.Fprintf(os.Stderr, "license-gen: invalid private key: %v\n", err)
		os.Exit(1)
	}

	var featList []string
	if *features != "" {
		for _, f := range strings.Split(*features, ",") {
			f = strings.TrimSpace(f)
			if f != "" {
				featList = append(featList, f)
			}
		}
	}

	payload := license.LicensePayload{
		Version:    1,
		KID:        *kid,
		DeviceHash: req.Fingerprint.Hash,
		IssuedAt:   time.Now(),
		ExpiresAt:  expiresAt,
		Features:   featList,
		Metadata:   *metadata,
	}

	licData, err := license.SignLicense(payload, priv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "license-gen: signing failed: %v\n", err)
		os.Exit(1)
	}

	if *output != "" {
		if err := os.WriteFile(*output, licData, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "license-gen: failed to write %s: %v\n", *output, err)
			os.Exit(1)
		}
		fmt.Printf("License written to %s\n", *output)
	} else {
		fmt.Println(string(licData))
	}
}

func parseExpiry(s string) (time.Time, error) {
	// Relative duration: "+365d", "+30d"
	if strings.HasPrefix(s, "+") && strings.HasSuffix(s, "d") {
		days, err := strconv.Atoi(s[1 : len(s)-1])
		if err != nil {
			return time.Time{}, fmt.Errorf("invalid relative duration: %s", s)
		}
		return time.Now().Add(time.Duration(days) * 24 * time.Hour), nil
	}

	// ISO8601 formats
	formats := []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02",
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unsupported format: %s (use ISO8601 or +Nd)", s)
}
