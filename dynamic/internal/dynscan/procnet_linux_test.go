//go:build linux

package dynscan

import "testing"

func TestParseProcNetAddrLoopbackLittleEndian(t *testing.T) {
	got, ok := parseProcNetAddr("0100007F:BC7C")
	if !ok {
		t.Fatalf("expected ok")
	}
	if got != "127.0.0.1:48252" {
		t.Fatalf("unexpected endpoint: %s", got)
	}
}

func TestParseProcNetAddrLoopbackBigEndianLike(t *testing.T) {
	got, ok := parseProcNetAddr("7F000001:BC7C")
	if !ok {
		t.Fatalf("expected ok")
	}
	// Even if kernel format differs, we must avoid false positive local egress.
	if got != "127.0.0.1:48252" {
		t.Fatalf("unexpected endpoint: %s", got)
	}
}

func TestParseProcNetAddrIPv4LittleEndianPreference(t *testing.T) {
	got, ok := parseProcNetAddr("0101A8C0:01BB")
	if !ok {
		t.Fatalf("expected ok")
	}
	if got != "192.168.1.1:443" {
		t.Fatalf("unexpected endpoint: %s", got)
	}
}

func TestParseProcNetAddrInvalid(t *testing.T) {
	if _, ok := parseProcNetAddr("not-an-address"); ok {
		t.Fatalf("expected parse failure")
	}
}
