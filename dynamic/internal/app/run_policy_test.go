package app

import (
	"testing"

	"github.com/yetanotherparticipant/PipeSec/dynamic/internal/dynscan"
)

func TestClassifyEgressSeverityAllowListWithProtocolPrefix(t *testing.T) {
	sev := classifyEgressSeverity("tcp:1.1.1.1:443", false, "1.1.1.1", "")
	if sev != dynscan.SeverityLow {
		t.Fatalf("expected LOW severity, got %s", sev)
	}
}

func TestClassifyEgressSeverityDenyListWithProtocolPrefix(t *testing.T) {
	sev := classifyEgressSeverity("tcp:1.1.1.1:443", false, "", "1.1.1.1")
	if sev != dynscan.SeverityCritical {
		t.Fatalf("expected CRITICAL severity, got %s", sev)
	}
}

func TestClassifyEgressSeverityFailOnEgressOverridesAllowList(t *testing.T) {
	sev := classifyEgressSeverity("tcp:1.1.1.1:443", true, "1.1.1.1", "")
	if sev != dynscan.SeverityCritical {
		t.Fatalf("expected CRITICAL severity, got %s", sev)
	}
}
