//go:build linux

package app

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/yetanotherparticipant/PipeSec/dynamic/internal/dynscan"
)

type jsonReport struct {
	Findings []dynscan.Finding `json:"findings"`
	Count    int               `json:"count"`
}

func TestRunScanModeLogFileDetectsSecrets(t *testing.T) {
	root := projectRoot(t)
	logPath := filepath.Join(root, "samples", "build.log")
	patternsPath := filepath.Join(root, "data", "secret_patterns.json")

	args := []string{
		"-mode", "scan",
		"-format", "json",
		"-source", "build.log",
		"-log", logPath,
		"-patterns", patternsPath,
	}
	payload, code := executeCLI(t, args)

	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if payload.Count != 4 {
		t.Fatalf("expected 4 findings, got %d (%#v)", payload.Count, payload.Findings)
	}
	for _, finding := range payload.Findings {
		if finding.Category != "Secret in Logs" {
			t.Fatalf("unexpected category: %s", finding.Category)
		}
	}
}

func TestRunModeStopsProcessOnThresholdViaCLI(t *testing.T) {
	root := projectRoot(t)
	patternsPath := filepath.Join(root, "data", "secret_patterns.json")

	args := []string{
		"-mode", "run",
		"-format", "json",
		"-source", "proactive",
		"-patterns", patternsPath,
		"-fail-on", "CRITICAL",
		"--",
		"bash",
		"-lc",
		"echo AKIAIOSFODNN7EXAMPLE; sleep 8; echo never",
	}

	start := time.Now()
	payload, code := executeCLI(t, args)
	elapsed := time.Since(start)

	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if elapsed >= 5*time.Second {
		t.Fatalf("expected proactive stop before sleep finishes; elapsed=%s findings=%#v", elapsed, payload.Findings)
	}

	foundSecret := false
	for _, finding := range payload.Findings {
		if finding.Category == "Secret in Logs" {
			foundSecret = true
		}
		if finding.Category == "Command Exit" {
			t.Fatalf("did not expect Command Exit finding after proactive stop: %#v", payload.Findings)
		}
	}
	if !foundSecret {
		t.Fatalf("expected Secret in Logs finding, got %#v", payload.Findings)
	}
}

func TestRunModeAllowListLowersEgressSeverityViaCLI(t *testing.T) {
	root := projectRoot(t)
	patternsPath := filepath.Join(root, "data", "secret_patterns.json")

	args := []string{
		"-mode", "run",
		"-format", "json",
		"-source", "allowlist",
		"-patterns", patternsPath,
		"-allow-list", "1.1.1.1",
		"--",
		"bash",
		"-lc",
		"curl -s --max-time 4 http://1.1.1.1 >/dev/null 2>&1 || true",
	}
	payload, code := executeCLI(t, args)

	finding := firstNetworkFinding(payload.Findings)
	if finding == nil {
		t.Skipf("no observable external egress in this environment; findings=%#v", payload.Findings)
	}
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (%#v)", code, payload.Findings)
	}
	if finding.Severity != dynscan.SeverityLow {
		t.Fatalf("expected LOW severity for allow-list, got %s", finding.Severity)
	}
}

func TestRunModeDenyListRaisesEgressSeverityViaCLI(t *testing.T) {
	root := projectRoot(t)
	patternsPath := filepath.Join(root, "data", "secret_patterns.json")

	args := []string{
		"-mode", "run",
		"-format", "json",
		"-source", "denylist",
		"-patterns", patternsPath,
		"-deny-list", "1.1.1.1",
		"--",
		"bash",
		"-lc",
		"curl -s --max-time 4 http://1.1.1.1 >/dev/null 2>&1 || true",
	}
	payload, code := executeCLI(t, args)

	finding := firstNetworkFinding(payload.Findings)
	if finding == nil {
		t.Skipf("no observable external egress in this environment; findings=%#v", payload.Findings)
	}
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d (%#v)", code, payload.Findings)
	}
	if finding.Severity != dynscan.SeverityCritical {
		t.Fatalf("expected CRITICAL severity for deny-list, got %s", finding.Severity)
	}
}

func TestRunModeFailOnEgressForcesCriticalViaCLI(t *testing.T) {
	root := projectRoot(t)
	patternsPath := filepath.Join(root, "data", "secret_patterns.json")

	args := []string{
		"-mode", "run",
		"-format", "json",
		"-source", "fail-on-egress",
		"-patterns", patternsPath,
		"-fail-on-egress",
		"--",
		"bash",
		"-lc",
		"curl -s --max-time 4 http://1.1.1.1 >/dev/null 2>&1 || true",
	}
	payload, code := executeCLI(t, args)

	finding := firstNetworkFinding(payload.Findings)
	if finding == nil {
		t.Skipf("no observable external egress in this environment; findings=%#v", payload.Findings)
	}
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d (%#v)", code, payload.Findings)
	}
	if finding.Severity != dynscan.SeverityCritical {
		t.Fatalf("expected CRITICAL severity with --fail-on-egress, got %s", finding.Severity)
	}
}

func executeCLI(t *testing.T, args []string) (jsonReport, int) {
	t.Helper()
	t.Setenv("TELEGRAM_BOT_TOKEN", "")
	t.Setenv("TELEGRAM_CHAT_ID", "")
	t.Setenv("PIPESEC_WEBHOOK_URL", "")
	t.Setenv("PIPESEC_WEBHOOK_HEADERS", "")

	fullArgs := append([]string{"pipesec-dynamic"}, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(args, fullArgs, &stdout, &stderr)

	var payload jsonReport
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &payload); err != nil {
		t.Fatalf("failed to parse JSON report: %v\nstdout=%q\nstderr=%q", err, stdout.String(), stderr.String())
	}
	return payload, code
}

func projectRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to resolve caller path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../../.."))
}

func firstNetworkFinding(findings []dynscan.Finding) *dynscan.Finding {
	var best *dynscan.Finding
	for i := range findings {
		if !strings.HasPrefix(findings[i].Category, "Network Egress") {
			continue
		}
		if best == nil || severityLevel(findings[i].Severity) > severityLevel(best.Severity) {
			best = &findings[i]
		}
	}
	return best
}
