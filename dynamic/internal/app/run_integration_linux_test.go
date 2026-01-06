//go:build linux

package app

import (
	"testing"
	"time"

	"github.com/yetanotherparticipant/PipeSec/dynamic/internal/dynscan"
)

func TestRunModeDetectsProcessEnvironmentSecrets(t *testing.T) {
	findings := runMode(
		"integration",
		"bash",
		[]string{"-lc", "export GH_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz1234567890ABCD; (sleep 2) & wait"},
		3*time.Second,
		dynscan.DefaultSecretPatterns(),
		"CRITICAL",
		false,
		"",
		"",
	)

	found := false
	for _, finding := range findings {
		if finding.Category == "Secret in Process Environment" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected Secret in Process Environment finding, got %#v", findings)
	}
}

func TestRunModeStopsProcessOnThreshold(t *testing.T) {
	start := time.Now()
	findings := runMode(
		"proactive",
		"bash",
		[]string{"-lc", "echo AKIAIOSFODNN7EXAMPLE; sleep 8; echo never"},
		15*time.Second,
		dynscan.DefaultSecretPatterns(),
		"CRITICAL",
		false,
		"",
		"",
	)
	elapsed := time.Since(start)

	if elapsed >= 5*time.Second {
		t.Fatalf("expected proactive stop before sleep finishes; elapsed=%s findings=%#v", elapsed, findings)
	}

	foundSecret := false
	for _, finding := range findings {
		if finding.Category == "Secret in Logs" {
			foundSecret = true
		}
		if finding.Category == "Command Exit" {
			t.Fatalf("did not expect Command Exit finding on proactive stop: %#v", findings)
		}
	}
	if !foundSecret {
		t.Fatalf("expected Secret in Logs finding, got %#v", findings)
	}
}
