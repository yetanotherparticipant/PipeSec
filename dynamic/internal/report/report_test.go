package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/yetanotherparticipant/PipeSec/dynamic/internal/dynscan"
)

func TestExitCode(t *testing.T) {
	findings := []dynscan.Finding{
		{Severity: dynscan.SeverityMedium},
		{Severity: dynscan.SeverityHigh},
	}

	if got := ExitCode(findings, "CRITICAL"); got != 0 {
		t.Fatalf("expected 0, got %d", got)
	}
	if got := ExitCode(findings, "HIGH"); got != 1 {
		t.Fatalf("expected 1, got %d", got)
	}
}

func TestRenderJSON(t *testing.T) {
	findings := []dynscan.Finding{
		{
			Severity:    dynscan.SeverityCritical,
			Category:    "Secret in Logs",
			Description: "d",
			Location:    "l",
		},
	}
	out := Render(findings, "json")
	var payload map[string]any
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if payload["count"].(float64) != 1 {
		t.Fatalf("expected count=1, got %v", payload["count"])
	}
}

func TestRenderConsole(t *testing.T) {
	out := Render(nil, "console")
	if !strings.Contains(out, "No vulnerabilities") {
		t.Fatalf("unexpected output: %s", out)
	}
}
