package grace

import (
	"os"
	"strconv"
	"strings"
	"time"
)

type Status int

const (
	StatusValid Status = iota
	StatusGracePeriod
	StatusExpired
	StatusInvalid
)

func (s Status) String() string {
	switch s {
	case StatusValid:
		return "Valid"
	case StatusGracePeriod:
		return "GracePeriod"
	case StatusExpired:
		return "Expired"
	case StatusInvalid:
		return "Invalid"
	default:
		return "Unknown"
	}
}

type Tracker struct {
	GraceDuration time.Duration
	MarkerPath    string
}

func (t *Tracker) Evaluate(pass bool, now time.Time) Status {
	if pass {
		// Remove marker if it exists (recovery from grace period)
		os.Remove(t.MarkerPath)
		return StatusValid
	}

	// Read marker to get grace period start time
	graceStart, err := readMarker(t.MarkerPath)
	if err != nil {
		// No marker yet — enter grace period
		writeMarker(t.MarkerPath, now)
		return StatusGracePeriod
	}

	// Check if grace period has expired
	if now.Sub(graceStart) > t.GraceDuration {
		return StatusExpired
	}
	return StatusGracePeriod
}

func readMarker(path string) (time.Time, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, err
	}
	unix, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(unix, 0), nil
}

func writeMarker(path string, t time.Time) error {
	return os.WriteFile(path, []byte(strconv.FormatInt(t.Unix(), 10)), 0644)
}
