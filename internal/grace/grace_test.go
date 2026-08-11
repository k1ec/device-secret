package grace

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEvaluate_Valid(t *testing.T) {
	dir := t.TempDir()
	tracker := &Tracker{
		GraceDuration: 7 * 24 * time.Hour,
		MarkerPath:    filepath.Join(dir, ".grace_start"),
	}
	status := tracker.Evaluate(true, time.Now())
	if status != StatusValid {
		t.Errorf("expected StatusValid, got %v", status)
	}
}

func TestEvaluate_EntersGracePeriod(t *testing.T) {
	dir := t.TempDir()
	tracker := &Tracker{
		GraceDuration: 7 * 24 * time.Hour,
		MarkerPath:    filepath.Join(dir, ".grace_start"),
	}
	now := time.Now()

	status := tracker.Evaluate(false, now)
	if status != StatusGracePeriod {
		t.Errorf("expected StatusGracePeriod, got %v", status)
	}

	// Marker file should be created
	if _, err := os.Stat(tracker.MarkerPath); os.IsNotExist(err) {
		t.Error("marker file should exist after entering grace period")
	}
}

func TestEvaluate_GracePeriodExpires(t *testing.T) {
	dir := t.TempDir()
	tracker := &Tracker{
		GraceDuration: 7 * 24 * time.Hour,
		MarkerPath:    filepath.Join(dir, ".grace_start"),
	}
	now := time.Now()

	// Enter grace period
	tracker.Evaluate(false, now)

	// Advance past grace duration
	later := now.Add(8 * 24 * time.Hour)
	status := tracker.Evaluate(false, later)
	if status != StatusExpired {
		t.Errorf("expected StatusExpired, got %v", status)
	}
}

func TestEvaluate_RecoversFromGracePeriod(t *testing.T) {
	dir := t.TempDir()
	tracker := &Tracker{
		GraceDuration: 7 * 24 * time.Hour,
		MarkerPath:    filepath.Join(dir, ".grace_start"),
	}
	now := time.Now()

	// Enter grace period
	tracker.Evaluate(false, now)

	// Recover with valid license
	status := tracker.Evaluate(true, now.Add(1*time.Hour))
	if status != StatusValid {
		t.Errorf("expected StatusValid after recovery, got %v", status)
	}

	// Marker file should be removed
	if _, err := os.Stat(tracker.MarkerPath); !os.IsNotExist(err) {
		t.Error("marker file should be removed after recovery")
	}
}

func TestEvaluate_RestartPreservesGracePeriod(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()

	// Simulate first session
	tracker1 := &Tracker{
		GraceDuration: 7 * 24 * time.Hour,
		MarkerPath:    filepath.Join(dir, ".grace_start"),
	}
	tracker1.Evaluate(false, now)

	// Simulate restart (new tracker, same marker)
	tracker2 := &Tracker{
		GraceDuration: 7 * 24 * time.Hour,
		MarkerPath:    filepath.Join(dir, ".grace_start"),
	}
	status := tracker2.Evaluate(false, now.Add(1*time.Hour))
	if status != StatusGracePeriod {
		t.Errorf("expected StatusGracePeriod after restart, got %v", status)
	}
}

func TestEvaluate_CorruptMarker(t *testing.T) {
	dir := t.TempDir()
	markerPath := filepath.Join(dir, ".grace_start")
	os.WriteFile(markerPath, []byte("not-a-timestamp"), 0644)

	tracker := &Tracker{
		GraceDuration: 7 * 24 * time.Hour,
		MarkerPath:    markerPath,
	}
	status := tracker.Evaluate(false, time.Now())
	// Corrupt marker: conservative — treat as first day of grace period
	if status != StatusGracePeriod {
		t.Errorf("expected StatusGracePeriod for corrupt marker, got %v", status)
	}
}
