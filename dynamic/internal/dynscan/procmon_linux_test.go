//go:build linux

package dynscan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiscoverChildrenRecursively(t *testing.T) {
	root := t.TempDir()
	withProcRoot(t, root)

	writeProcFile(t, root, 100, "task/100/children", "101 102")
	writeProcFile(t, root, 101, "task/101/children", "103")
	writeProcFile(t, root, 102, "task/102/children", "")
	writeProcFile(t, root, 103, "task/103/children", "")

	children := DiscoverChildren(100)
	got := intsToString(children)
	if got != "101,102,103" {
		t.Fatalf("unexpected children: %s", got)
	}
}

func TestReadEnvironDetectsSecret(t *testing.T) {
	root := t.TempDir()
	withProcRoot(t, root)
	writeProcFile(
		t,
		root,
		200,
		"environ",
		"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\x00FOO=bar\x00",
	)

	env, findings := ReadEnviron(200, DefaultSecretPatterns())
	if env["FOO"] != "bar" {
		t.Fatalf("expected env FOO=bar, got %#v", env)
	}
	if len(findings) == 0 || findings[0].Category != "Secret in Process Environment" {
		t.Fatalf("unexpected findings: %#v", findings)
	}
}

func TestParseMapsFlagsSuspiciousSharedObject(t *testing.T) {
	root := t.TempDir()
	withProcRoot(t, root)
	maps := strings.Join([]string{
		"7f0000-7f1000 r--p 00000000 00:00 0 /usr/lib/libc.so.6",
		"7f2000-7f3000 r-xp 00000000 00:00 0 /tmp/libevil.so",
	}, "\n")
	writeProcFile(t, root, 210, "maps", maps)

	_, findings := ParseMaps(210)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d (%#v)", len(findings), findings)
	}
	if findings[0].Severity != SeverityHigh {
		t.Fatalf("expected HIGH severity, got %s", findings[0].Severity)
	}
}

func TestParseMapsIgnoresLdSoCache(t *testing.T) {
	root := t.TempDir()
	withProcRoot(t, root)
	maps := strings.Join([]string{
		"7f1000-7f2000 r--p 00000000 00:00 0 /etc/ld.so.cache",
		"7f3000-7f4000 r--p 00000000 00:00 0 [vvar]",
	}, "\n")
	writeProcFile(t, root, 211, "maps", maps)

	_, findings := ParseMaps(211)
	if len(findings) != 0 {
		t.Fatalf("expected no findings for ld.so.cache, got %#v", findings)
	}
}

func TestReadCapabilitiesDetectsDangerousCaps(t *testing.T) {
	root := t.TempDir()
	withProcRoot(t, root)
	status := strings.Join([]string{
		"Name:\ttest",
		"CapInh:\t0000000000000000",
		"CapPrm:\t0000000000200000",
		"CapEff:\t0000000000200000",
		"CapBnd:\t0000000000000000",
		"CapAmb:\t0000000000000000",
	}, "\n")
	writeProcFile(t, root, 220, "status", status)

	_, findings := ReadCapabilities(220)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Category != "Dangerous Process Capabilities" {
		t.Fatalf("unexpected category: %s", findings[0].Category)
	}
}

func TestReadCapabilitiesIgnoresBoundingSetOnly(t *testing.T) {
	root := t.TempDir()
	withProcRoot(t, root)
	status := strings.Join([]string{
		"Name:\ttest",
		"CapInh:\t0000000000000000",
		"CapPrm:\t0000000000000000",
		"CapEff:\t0000000000000000",
		"CapBnd:\t000001ffffffffff",
		"CapAmb:\t0000000000000000",
	}, "\n")
	writeProcFile(t, root, 221, "status", status)

	_, findings := ReadCapabilities(221)
	if len(findings) != 0 {
		t.Fatalf("expected no findings when only CapBnd is set, got %#v", findings)
	}
}

func TestCollectProcInfoAndPolicyDrivenFD(t *testing.T) {
	root := t.TempDir()
	withProcRoot(t, root)
	SetProcMonitorPolicy(ProcMonitorPolicy{
		DangerousFDPatterns: []string{"/var/run/docker\\.sock$"},
	})

	pid := 230
	writeProcFile(t, root, pid, "cmdline", "bash\x00-lc\x00echo\x00")
	writeProcFile(
		t,
		root,
		pid,
		"environ",
		"AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\x00",
	)
	writeProcFile(
		t,
		root,
		pid,
		"maps",
		"7f2000-7f3000 r-xp 00000000 00:00 0 /tmp/libevil.so\n",
	)
	writeProcFile(
		t,
		root,
		pid,
		"status",
		"CapInh:\t0000000000000000\nCapPrm:\t0000000000200000\nCapEff:\t0000000000200000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\n",
	)
	writeProcFile(t, root, pid, "task/230/children", "")
	writeProcFile(t, root, pid, "limits", "Limit                     Soft Limit           Hard Limit           Units\nMax core file size        unlimited            unlimited            bytes\n")
	writeProcFile(t, root, pid, "coredump_filter", "00000033\n")
	writeProcFile(t, root, pid, "syscall", "0 0 0 0 0 0 0\n")

	makeProcSymlink(t, root, pid, "fd/3", "/var/run/docker.sock")
	makeProcSymlink(t, root, pid, "exe", "/tmp/evil-binary")
	makeProcSymlink(t, root, pid, "cwd", "/tmp/build")
	makeProcSymlink(t, root, pid, "root", "/")
	makeProcSymlink(t, root, pid, "ns/mnt", "mnt:[4026531840]")
	makeProcSymlink(t, root, pid, "ns/net", "net:[4026531840]")
	makeProcSymlink(t, root, pid, "ns/pid", "pid:[4026531836]")
	makeProcSymlink(t, root, pid, "ns/user", "user:[4026531837]")

	info, findings := CollectProcInfo(pid, DefaultSecretPatterns())
	if info == nil {
		t.Fatal("expected proc info")
	}
	if info.PID != pid {
		t.Fatalf("unexpected pid: %d", info.PID)
	}
	if len(info.OpenFDs) == 0 {
		t.Fatalf("expected open fds")
	}
	categories := map[string]bool{}
	for _, finding := range findings {
		categories[finding.Category] = true
	}
	expected := []string{
		"Secret in Process Environment",
		"Suspicious Shared Object",
		"Dangerous Process Capabilities",
		"Dangerous Open File Descriptor",
		"Suspicious Executable Path",
		"Suspicious Working Directory",
		"Core Dump Exposure",
	}
	for _, category := range expected {
		if !categories[category] {
			t.Fatalf("expected finding category %q, got %#v", category, categories)
		}
	}
}

func TestNamespaceDiffFindings(t *testing.T) {
	root := &ProcInfo{
		PID: 1,
		Namespaces: map[string]string{
			"mnt": "mnt:[1]",
			"net": "net:[1]",
		},
	}
	child := &ProcInfo{
		PID: 2,
		Namespaces: map[string]string{
			"mnt": "mnt:[2]",
			"net": "net:[1]",
		},
	}
	findings := NamespaceDiffFindings(root, child)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
}

func TestIsSuspiciousChildCommand(t *testing.T) {
	if !IsSuspiciousChildCommand([]string{"curl", "https://example.com"}) {
		t.Fatalf("expected suspicious command")
	}
	if IsSuspiciousChildCommand([]string{"python", "build.py"}) {
		t.Fatalf("expected non-suspicious command")
	}
}

func withProcRoot(t *testing.T, root string) {
	t.Helper()
	old := procFSRoot
	procFSRoot = root
	t.Cleanup(func() {
		procFSRoot = old
	})
}

func writeProcFile(t *testing.T, root string, pid int, rel string, content string) {
	t.Helper()
	path := filepath.Join(root, itoa(pid), rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func makeProcSymlink(t *testing.T, root string, pid int, rel string, target string) {
	t.Helper()
	path := filepath.Join(root, itoa(pid), rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir symlink dir %s: %v", path, err)
	}
	_ = os.Remove(path)
	if err := os.Symlink(target, path); err != nil {
		t.Fatalf("symlink %s -> %s: %v", path, target, err)
	}
}

func intsToString(v []int) string {
	if len(v) == 0 {
		return ""
	}
	out := make([]string, 0, len(v))
	for _, x := range v {
		out = append(out, itoa(x))
	}
	return strings.Join(out, ",")
}
