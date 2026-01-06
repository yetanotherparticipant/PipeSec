package dynscan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadProcMonitorPolicyFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	content := `{
  "version": 1,
  "dangerous_fd_patterns": ["/var/run/docker\\.sock$"],
  "secret_fd_patterns": ["(?i)\\.aws/credentials$"]
}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	p, err := LoadProcMonitorPolicyFromFile(path)
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	if len(p.DangerousFDPatterns) != 1 || len(p.SecretFDPatterns) != 1 {
		t.Fatalf("unexpected policy: %#v", p)
	}
}

func TestSetProcMonitorPolicyAndMatch(t *testing.T) {
	SetProcMonitorPolicy(ProcMonitorPolicy{
		DangerousFDPatterns: []string{"/var/run/docker\\.sock$"},
		SecretFDPatterns:    []string{"(?i)\\.aws/credentials$"},
	})

	if category, ok := matchFDTargetByPolicy("/var/run/docker.sock"); !ok || category != "Dangerous Open File Descriptor" {
		t.Fatalf("expected dangerous fd match, got category=%q ok=%v", category, ok)
	}
	if category, ok := matchFDTargetByPolicy("/home/runner/.aws/credentials"); !ok || category != "Runtime Secret File Access" {
		t.Fatalf("expected secret fd match, got category=%q ok=%v", category, ok)
	}
}
