package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"device-secret/internal/fingerprint"
)

func main() {
	output := flag.String("o", "", "output path (default: stdout)")
	pretty := flag.Bool("pretty", false, "pretty-print JSON output")
	flag.Parse()

	fp, err := fingerprint.Collect()
	if err != nil {
		fmt.Fprintf(os.Stderr, "fingerprint: %v\n", err)
		os.Exit(1)
	}

	req := fingerprint.RequestFile{
		Version:     1,
		Device:      fingerprint.GetDeviceMeta(),
		Fingerprint: *fp,
		RequestedAt: time.Now(),
	}

	var data []byte
	if *pretty {
		data, err = json.MarshalIndent(req, "", "  ")
	} else {
		data, err = json.Marshal(req)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "fingerprint: failed to encode output: %v\n", err)
		os.Exit(1)
	}

	if *output != "" {
		if err := os.WriteFile(*output, data, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "fingerprint: failed to write %s: %v\n", *output, err)
			os.Exit(1)
		}
		fmt.Printf("Request file written to %s\n", *output)
	} else {
		fmt.Println(string(data))
	}
}
