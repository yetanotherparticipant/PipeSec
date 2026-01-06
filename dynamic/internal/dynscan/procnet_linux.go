//go:build linux

package dynscan

import (
	"bufio"
	"encoding/hex"
	"net"
	"os"
	"strconv"
	"strings"
)

func LinuxRemoteEndpoints() map[string]struct{} {
	out := map[string]struct{}{}
	readProcNet("/proc/net/tcp", out)
	readProcNet("/proc/net/tcp6", out)
	readProcNet("/proc/net/udp", out)
	readProcNet("/proc/net/udp6", out)
	return out
}

func readProcNet(path string, out map[string]struct{}) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	first := true
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		if first {
			first = false
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		remote := fields[2]
		ipPort, ok := parseProcNetAddr(remote)
		if !ok {
			continue
		}
		if strings.HasSuffix(ipPort, ":0") ||
			strings.HasPrefix(ipPort, "0.0.0.0:") ||
			strings.HasPrefix(ipPort, "127.0.0.1:") ||
			strings.HasPrefix(ipPort, "[::]:") ||
			strings.HasPrefix(ipPort, "[::1]:") {
			continue
		}
		out[ipPort] = struct{}{}
	}
}

func parseProcNetAddr(v string) (string, bool) {
	parts := strings.Split(v, ":")
	if len(parts) != 2 {
		return "", false
	}
	ipHex, portHex := parts[0], parts[1]
	portU16, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return "", false
	}
	port := int(portU16)

	// IPv4 is 8 hex chars in little-endian; IPv6 is 32 hex chars.
	switch len(ipHex) {
	case 8:
		b, err := hex.DecodeString(ipHex)
		if err != nil || len(b) != 4 {
			return "", false
		}
		ipLE := net.IP{b[3], b[2], b[1], b[0]}
		ipBE := net.IP{b[0], b[1], b[2], b[3]}
		ip := chooseProcNetIP(ipLE, ipBE)
		return ip.String() + ":" + itoa(port), true
	case 32:
		b, err := hex.DecodeString(ipHex)
		if err != nil || len(b) != 16 {
			return "", false
		}
		// /proc/net/tcp6 often uses little-endian 32-bit words; on some systems it may
		// appear in big-endian/network order. Prefer native endianness, fallback if needed.
		ipLE := make(net.IP, 16)
		copy(ipLE, b)
		for i := 0; i < 16; i += 4 {
			ipLE[i+0], ipLE[i+1], ipLE[i+2], ipLE[i+3] = ipLE[i+3], ipLE[i+2], ipLE[i+1], ipLE[i+0]
		}
		ipBE := net.IP(b)
		ip := chooseProcNetIP(ipLE, ipBE)
		return "[" + ip.String() + "]:" + itoa(port), true
	default:
		return "", false
	}
}

func chooseProcNetIP(ipLE, ipBE net.IP) net.IP {
	if ipLE == nil {
		return ipBE
	}
	if ipBE == nil {
		return ipLE
	}

	// If one candidate decodes to loopback/unspecified and the other does not,
	// prefer the special-case address to avoid false egress findings caused by
	// byte-order ambiguity (e.g. 1.0.0.127 vs 127.0.0.1).
	leSpecial := procNetIPIsSpecial(ipLE)
	beSpecial := procNetIPIsSpecial(ipBE)
	if leSpecial != beSpecial {
		if leSpecial {
			return ipLE
		}
		return ipBE
	}

	// /proc/net/* is normally exported in little-endian representation.
	// Prefer little-endian decoding when both candidates are equally plausible.
	return ipLE
}

func procNetIPIsSpecial(ip net.IP) bool {
	if ip == nil {
		return true
	}
	return ip.IsUnspecified() || ip.IsLoopback()
}
