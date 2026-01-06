//go:build linux

package dynscan

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var procFSRoot = "/proc"

var suspiciousChildCmdRe = regexp.MustCompile(`(?i)\b(curl|wget|nc|ncat|socat)\b`)
var sharedObjectPathRe = regexp.MustCompile(`(?i)(^|/)[^/\s]+\.so(?:\.[0-9]+(?:\.[0-9]+)*)?(?:\s+\(deleted\))?$`)

func CollectProcInfo(pid int, patterns []SecretPattern) (*ProcInfo, []Finding) {
	info := &ProcInfo{
		PID:        pid,
		Environ:    map[string]string{},
		Namespaces: map[string]string{},
		Limits:     map[string]string{},
		Cgroup:     []string{},
		Mounts:     []ProcMount{},
	}
	findings := make([]Finding, 0, 8)

	info.Cmdline = ReadCmdline(pid)

	environ, envFindings := ReadEnviron(pid, patterns)
	if environ != nil {
		info.Environ = environ
	}
	findings = append(findings, envFindings...)

	maps, mapsFindings := ParseMaps(pid)
	info.Maps = maps
	findings = append(findings, mapsFindings...)

	caps, capsFindings := ReadCapabilities(pid)
	info.Capabilities = caps
	findings = append(findings, capsFindings...)

	status, statusFindings := ReadStatusSecurity(pid)
	info.Status = status
	findings = append(findings, statusFindings...)

	info.Tasks = readTaskIDs(pid)
	info.Children = DiscoverChildren(pid)

	openFDs, fdFindings := readOpenFDs(pid)
	info.OpenFDs = openFDs
	findings = append(findings, fdFindings...)

	info.Cgroup = readCgroup(pid)

	mounts, mountFindings := readMounts(pid, info.Cgroup)
	info.Mounts = mounts
	findings = append(findings, mountFindings...)

	exePath, cwd, root, pathFindings := readExeCwdRoot(pid)
	info.ExePath = exePath
	info.CWD = cwd
	info.Root = root
	findings = append(findings, pathFindings...)

	namespaces := readNamespaces(pid)
	if namespaces != nil {
		info.Namespaces = namespaces
	}

	limits, coreEnabled := readLimits(pid)
	if limits != nil {
		info.Limits = limits
	}

	info.CoreDumpFilter = readCoreDumpFilter(pid)
	if coreEnabled && info.CoreDumpFilter != "" && info.CoreDumpFilter != "00000000" {
		findings = append(findings, Finding{
			Severity:       SeverityMedium,
			Category:       "Core Dump Exposure",
			Description:    "Core dumps are enabled for the process and may include sensitive memory.",
			Location:       procPath(pid, "limits"),
			Recommendation: "Disable core dumps for CI jobs handling secrets, or tighten coredump_filter and dump collection policies.",
			Evidence:       "coredump_filter=" + info.CoreDumpFilter,
		})
	}

	info.Syscall = readSyscall(pid)

	return info, findings
}

func DiscoverChildren(pid int) []int {
	if pid <= 0 {
		return nil
	}

	visited := map[int]struct{}{pid: {}}
	children := map[int]struct{}{}
	queue := []int{pid}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]

		tasks := readTaskIDs(cur)
		for _, tid := range tasks {
			for _, child := range readChildrenFile(cur, tid) {
				if child <= 0 {
					continue
				}
				children[child] = struct{}{}
				if _, ok := visited[child]; ok {
					continue
				}
				visited[child] = struct{}{}
				queue = append(queue, child)
			}
		}
	}

	out := make([]int, 0, len(children))
	for child := range children {
		out = append(out, child)
	}
	sort.Ints(out)
	return out
}

func ReadCmdline(pid int) []string {
	b, err := os.ReadFile(procPath(pid, "cmdline"))
	if err != nil || len(b) == 0 {
		return nil
	}
	return splitNulSeparated(b)
}

func ReadEnviron(pid int, patterns []SecretPattern) (map[string]string, []Finding) {
	b, err := os.ReadFile(procPath(pid, "environ"))
	if err != nil || len(b) == 0 {
		return map[string]string{}, nil
	}

	env := map[string]string{}
	findings := make([]Finding, 0)
	seen := map[string]struct{}{}

	for _, entry := range splitNulSeparated(b) {
		k, v, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		env[k] = v

		for _, pattern := range patterns {
			candidates := []string{v}
			// Patterns like "Generic Secret" are key-value oriented and can match only on full entry.
			if entry != v {
				candidates = append(candidates, entry)
			}
			for _, candidate := range candidates {
				matches := pattern.Re.FindAllString(candidate, -1)
				for _, m := range matches {
					key := pattern.Name + "|" + k + "|" + m
					if _, ok := seen[key]; ok {
						continue
					}
					seen[key] = struct{}{}
					findings = append(findings, Finding{
						Severity:       SeverityLow,
						Category:       "Secret in Process Environment",
						Description:    fmt.Sprintf("Detected secret in process environment variable '%s' (type: %s).", k, pattern.Name),
						Location:       procPath(pid, "environ"),
						Recommendation: "Avoid passing secrets via plaintext environment variables to subprocesses. Rotate the secret and use short-lived credentials.",
						Evidence:       truncateEvidence(m),
					})
				}
			}
		}
	}

	return env, findings
}

func ParseMaps(pid int) ([]MappedRegion, []Finding) {
	f, err := os.Open(procPath(pid, "maps"))
	if err != nil {
		return nil, nil
	}
	defer f.Close()

	regions := make([]MappedRegion, 0)
	findings := make([]Finding, 0)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		addrStart, addrEnd := splitAddrRange(fields[0])
		pathname := ""
		if len(fields) > 5 {
			pathname = strings.Join(fields[5:], " ")
		}

		regions = append(regions, MappedRegion{
			AddrStart: addrStart,
			AddrEnd:   addrEnd,
			Perms:     fields[1],
			Offset:    fields[2],
			Dev:       fields[3],
			Inode:     fields[4],
			Pathname:  pathname,
		})

		sev, suspicious := classifySharedObject(pathname)
		if !suspicious {
			continue
		}
		findings = append(findings, Finding{
			Severity:       sev,
			Category:       "Suspicious Shared Object",
			Description:    "Detected a shared object loaded from a suspicious location.",
			Location:       procPath(pid, "maps"),
			Recommendation: "Load shared libraries only from trusted system paths and avoid runtime loading from writable locations.",
			Evidence:       truncateEvidence(pathname),
		})
	}

	return regions, findings
}

func ReadCapabilities(pid int) (ProcCaps, []Finding) {
	fields := readStatusFields(pid)
	if len(fields) == 0 {
		return ProcCaps{}, nil
	}

	caps := ProcCaps{
		CapInh: fields["CapInh"],
		CapPrm: fields["CapPrm"],
		CapEff: fields["CapEff"],
		CapBnd: fields["CapBnd"],
		CapAmb: fields["CapAmb"],
	}

	dangerous := map[int]string{
		1:  "CAP_DAC_OVERRIDE",
		12: "CAP_NET_ADMIN",
		13: "CAP_NET_RAW",
		16: "CAP_SYS_MODULE",
		19: "CAP_SYS_PTRACE",
		21: "CAP_SYS_ADMIN",
	}

	exposed := make([]string, 0)
	for bit, name := range dangerous {
		// CapBnd only sets the upper bound; it does not mean the process currently
		// has effective/permitted privileges.
		if hasCapBit(caps.CapEff, bit) || hasCapBit(caps.CapPrm, bit) || hasCapBit(caps.CapAmb, bit) {
			exposed = append(exposed, name)
		}
	}
	sort.Strings(exposed)

	if len(exposed) == 0 {
		return caps, nil
	}

	return caps, []Finding{{
		Severity:       SeverityHigh,
		Category:       "Dangerous Process Capabilities",
		Description:    "Process has dangerous Linux capabilities that may allow privilege escalation or host tampering.",
		Location:       procPath(pid, "status"),
		Recommendation: "Drop unnecessary capabilities (least privilege) and use stricter container/job runtime profiles.",
		Evidence:       strings.Join(exposed, ", "),
	}}
}

func ReadStatusSecurity(pid int) (ProcStatus, []Finding) {
	fields := readStatusFields(pid)
	if len(fields) == 0 {
		return ProcStatus{}, nil
	}

	status := ProcStatus{
		NoNewPrivs: atoiDefault(fields["NoNewPrivs"], -1),
		Seccomp:    atoiDefault(fields["Seccomp"], -1),
		TracerPID:  atoiDefault(fields["TracerPid"], 0),
		Threads:    atoiDefault(fields["Threads"], 0),
	}

	findings := make([]Finding, 0, 4)
	statusPath := procPath(pid, "status")

	if status.NoNewPrivs == 0 {
		findings = append(findings, Finding{
			Severity:       SeverityLow,
			Category:       "Sandbox Hardening",
			Description:    "NoNewPrivs is disabled for the process.",
			Location:       statusPath,
			Recommendation: "Enable NoNewPrivs for untrusted workloads to reduce privilege-escalation surface.",
			Evidence:       "NoNewPrivs=0",
		})
	}

	if status.Seccomp == 0 {
		findings = append(findings, Finding{
			Severity:       SeverityLow,
			Category:       "Sandbox Hardening",
			Description:    "Process is running without seccomp filtering.",
			Location:       statusPath,
			Recommendation: "Run CI workloads with seccomp enabled (prefer mode 2 with a restrictive profile).",
			Evidence:       "Seccomp=0",
		})
	}

	if status.TracerPID > 0 {
		findings = append(findings, Finding{
			Severity:       SeverityMedium,
			Category:       "Suspicious Debug Attach",
			Description:    "Process is being traced by another process (ptrace).",
			Location:       statusPath,
			Recommendation: "Investigate unexpected debuggers/tracers and block ptrace for CI workloads unless explicitly required.",
			Evidence:       "TracerPid=" + itoa(status.TracerPID),
		})
	}

	if status.Threads > 256 {
		findings = append(findings, Finding{
			Severity:       SeverityMedium,
			Category:       "Anomalous Threading",
			Description:    "Process has an unusually high number of threads.",
			Location:       statusPath,
			Recommendation: "Investigate excessive thread creation and enforce resource limits for CI jobs.",
			Evidence:       "Threads=" + itoa(status.Threads),
		})
	}

	return status, findings
}

func IsSuspiciousChildCommand(cmdline []string) bool {
	if len(cmdline) == 0 {
		return false
	}
	return suspiciousChildCmdRe.MatchString(strings.Join(cmdline, " "))
}

func NamespaceDiffFindings(rootInfo, childInfo *ProcInfo) []Finding {
	if rootInfo == nil || childInfo == nil || rootInfo.PID == childInfo.PID {
		return nil
	}
	if len(rootInfo.Namespaces) == 0 || len(childInfo.Namespaces) == 0 {
		return nil
	}

	keys := []string{"mnt", "net", "pid", "user"}
	diff := make([]string, 0, len(keys))
	for _, key := range keys {
		rootNS := rootInfo.Namespaces[key]
		childNS := childInfo.Namespaces[key]
		if rootNS == "" || childNS == "" || rootNS == childNS {
			continue
		}
		diff = append(diff, key+":"+rootNS+"->"+childNS)
	}
	if len(diff) == 0 {
		return nil
	}

	sort.Strings(diff)
	return []Finding{{
		Severity:       SeverityMedium,
		Category:       "Suspicious Namespace Context",
		Description:    fmt.Sprintf("Child process namespace context differs from monitored root process %d.", rootInfo.PID),
		Location:       procPath(childInfo.PID, "ns"),
		Recommendation: "Verify whether namespace switching is expected for this workload and ensure isolation boundaries are intentional.",
		Evidence:       strings.Join(diff, "; "),
	}}
}

func readTaskIDs(pid int) []int {
	entries, err := os.ReadDir(procPath(pid, "task"))
	if err != nil {
		return nil
	}

	out := make([]int, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		tid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		out = append(out, tid)
	}
	sort.Ints(out)
	return out
}

func readChildrenFile(pid, tid int) []int {
	b, err := os.ReadFile(procPath(pid, "task", itoa(tid), "children"))
	if err != nil {
		return nil
	}

	fields := strings.Fields(string(b))
	out := make([]int, 0, len(fields))
	for _, field := range fields {
		child, err := strconv.Atoi(field)
		if err != nil {
			continue
		}
		out = append(out, child)
	}
	return out
}

func readOpenFDs(pid int) ([]OpenFD, []Finding) {
	entries, err := os.ReadDir(procPath(pid, "fd"))
	if err != nil {
		return nil, nil
	}

	out := make([]OpenFD, 0, len(entries))
	findings := make([]Finding, 0)
	fdBySocketInode := map[string][]int{}
	for _, entry := range entries {
		fd := entry.Name()
		if _, err := strconv.Atoi(fd); err != nil {
			continue
		}

		target, err := os.Readlink(procPath(pid, "fd", fd))
		if err != nil {
			continue
		}

		openFD := OpenFD{
			FD:     fd,
			Target: target,
		}
		if inode := parseSocketInodeFromTarget(target); inode != "" {
			openFD.Inode = inode
		} else if inode := readFDInfoInode(pid, fd); inode != "" {
			openFD.Inode = inode
		}
		out = append(out, openFD)
		if openFD.Inode != "" {
			fdBySocketInode[openFD.Inode] = append(fdBySocketInode[openFD.Inode], len(out)-1)
		}

		if strings.HasPrefix(target, "memfd:") {
			findings = append(findings, Finding{
				Severity:       SeverityHigh,
				Category:       "Dangerous Open File Descriptor",
				Description:    "Process has an anonymous in-memory file descriptor (memfd) open.",
				Location:       procPath(pid, "fd", fd),
				Recommendation: "Review whether executable or untrusted payloads are loaded via memfd and restrict such behavior in CI jobs.",
				Evidence:       truncateEvidence(target),
			})
			continue
		}

		category, matched := matchFDTargetByPolicy(target)
		if !matched {
			continue
		}
		findings = append(findings, Finding{
			Severity:       SeverityHigh,
			Category:       category,
			Description:    "Process opened a file descriptor matching a high-risk policy pattern.",
			Location:       procPath(pid, "fd", fd),
			Recommendation: "Avoid exposing sensitive host sockets/files to CI jobs and use isolated runtime credentials.",
			Evidence:       truncateEvidence(target),
		})
	}

	for inode, endpoint := range readProcNetEndpointsByInode(pid) {
		indices := fdBySocketInode[inode]
		for _, idx := range indices {
			out[idx].Endpoint = endpoint.Endpoint
			out[idx].Proto = endpoint.Protocol
			findings = append(findings, Finding{
				Severity:       SeverityMedium,
				Category:       "Network Egress (Process FD)",
				Description:    "Process socket file descriptor is associated with a non-local remote endpoint.",
				Location:       procPath(pid, "fd", out[idx].FD),
				Recommendation: "Verify whether this per-process outbound connection is expected and restrict runtime egress when possible.",
				Evidence:       endpoint.Protocol + ":" + endpoint.Endpoint,
			})
		}
	}

	return out, findings
}

type procNetEndpoint struct {
	Protocol string
	Endpoint string
}

func parseSocketInodeFromTarget(target string) string {
	if !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
		return ""
	}
	return strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
}

func readFDInfoInode(pid int, fd string) string {
	f, err := os.Open(procPath(pid, "fdinfo", fd))
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "ino:") {
			continue
		}
		return strings.TrimSpace(strings.TrimPrefix(line, "ino:"))
	}
	return ""
}

func readProcNetEndpointsByInode(pid int) map[string]procNetEndpoint {
	out := map[string]procNetEndpoint{}
	readProcNetInodeTable(procPath(pid, "net", "tcp"), "tcp", out)
	readProcNetInodeTable(procPath(pid, "net", "tcp6"), "tcp6", out)
	readProcNetInodeTable(procPath(pid, "net", "udp"), "udp", out)
	readProcNetInodeTable(procPath(pid, "net", "udp6"), "udp6", out)
	return out
}

func readProcNetInodeTable(path, protocol string, out map[string]procNetEndpoint) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	first := true
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if first {
			first = false
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		remote := fields[2]
		inode := fields[9]
		endpoint, ok := parseProcNetAddr(remote)
		if !ok || endpoint == "" {
			continue
		}
		if isIgnoredRemoteEndpoint(endpoint) {
			continue
		}
		if _, exists := out[inode]; exists {
			continue
		}
		out[inode] = procNetEndpoint{
			Protocol: protocol,
			Endpoint: endpoint,
		}
	}
}

func isIgnoredRemoteEndpoint(endpoint string) bool {
	return strings.HasSuffix(endpoint, ":0") ||
		strings.HasPrefix(endpoint, "0.0.0.0:") ||
		strings.HasPrefix(endpoint, "127.0.0.1:") ||
		strings.HasPrefix(endpoint, "[::]:") ||
		strings.HasPrefix(endpoint, "[::1]:")
}

func readExeCwdRoot(pid int) (exePath, cwd, root string, findings []Finding) {
	exePath, _ = os.Readlink(procPath(pid, "exe"))
	cwd, _ = os.Readlink(procPath(pid, "cwd"))
	root, _ = os.Readlink(procPath(pid, "root"))
	findings = make([]Finding, 0)

	if isSuspiciousExecPath(exePath) {
		findings = append(findings, Finding{
			Severity:       SeverityMedium,
			Category:       "Suspicious Executable Path",
			Description:    "Process executable points to a suspicious location.",
			Location:       procPath(pid, "exe"),
			Recommendation: "Execute binaries only from trusted immutable paths and avoid running binaries from writable directories.",
			Evidence:       truncateEvidence(exePath),
		})
	}

	if isWritableTransientPath(cwd) {
		findings = append(findings, Finding{
			Severity:       SeverityMedium,
			Category:       "Suspicious Working Directory",
			Description:    "Process working directory is in a writable transient location.",
			Location:       procPath(pid, "cwd"),
			Recommendation: "Avoid executing sensitive steps from /tmp-like writable directories in CI.",
			Evidence:       truncateEvidence(cwd),
		})
	}

	return exePath, cwd, root, findings
}

func readNamespaces(pid int) map[string]string {
	entries, err := os.ReadDir(procPath(pid, "ns"))
	if err != nil {
		return nil
	}

	out := make(map[string]string, len(entries))
	for _, entry := range entries {
		target, err := os.Readlink(procPath(pid, "ns", entry.Name()))
		if err != nil {
			continue
		}
		out[entry.Name()] = target
	}
	return out
}

func readCgroup(pid int) []string {
	b, err := os.ReadFile(procPath(pid, "cgroup"))
	if err != nil {
		return nil
	}

	out := make([]string, 0, 4)
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		out = append(out, line)
	}
	return out
}

func readMounts(pid int, cgroup []string) ([]ProcMount, []Finding) {
	mounts := readMountInfo(pid)
	if len(mounts) == 0 {
		mounts = readMountsFallback(pid)
	}
	return mounts, detectMountBreakoutFindings(pid, mounts, cgroup)
}

func readMountInfo(pid int) []ProcMount {
	f, err := os.Open(procPath(pid, "mountinfo"))
	if err != nil {
		return nil
	}
	defer f.Close()

	out := make([]ProcMount, 0, 16)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}

		sep := -1
		for i := 6; i < len(fields); i++ {
			if fields[i] == "-" {
				sep = i
				break
			}
		}
		if sep == -1 || sep+2 >= len(fields) {
			continue
		}

		out = append(out, ProcMount{
			Root:       decodeMountField(fields[3]),
			MountPoint: decodeMountField(fields[4]),
			FSType:     fields[sep+1],
			Source:     decodeMountField(fields[sep+2]),
		})
	}
	return out
}

func readMountsFallback(pid int) []ProcMount {
	f, err := os.Open(procPath(pid, "mounts"))
	if err != nil {
		return nil
	}
	defer f.Close()

	out := make([]ProcMount, 0, 16)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		out = append(out, ProcMount{
			Source:     decodeMountField(fields[0]),
			MountPoint: decodeMountField(fields[1]),
			FSType:     fields[2],
		})
	}
	return out
}

func detectMountBreakoutFindings(pid int, mounts []ProcMount, cgroup []string) []Finding {
	if len(mounts) == 0 {
		return nil
	}

	findings := make([]Finding, 0, 4)
	seen := map[string]struct{}{}
	inContainer := isContainerizedCgroup(cgroup)

	addFinding := func(sev Severity, desc, evidence string) {
		key := string(sev) + "|" + desc + "|" + evidence
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		findings = append(findings, Finding{
			Severity:       sev,
			Category:       "Container Breakout Risk",
			Description:    desc,
			Location:       procPath(pid, "mountinfo"),
			Recommendation: "Avoid mounting host control sockets/root into CI jobs and run with isolated, non-privileged runtime settings.",
			Evidence:       truncateEvidence(evidence),
		})
	}

	for _, mount := range mounts {
		source := strings.ToLower(mount.Source)
		point := strings.ToLower(mount.MountPoint)
		fsType := strings.ToLower(mount.FSType)
		evidence := mount.Source + " -> " + mount.MountPoint + " (" + mount.FSType + ")"

		if source == "/var/run/docker.sock" || point == "/var/run/docker.sock" ||
			source == "/run/docker.sock" || point == "/run/docker.sock" {
			addFinding(
				SeverityHigh,
				"Process mount namespace exposes Docker daemon socket, enabling potential host/container breakout.",
				evidence,
			)
			continue
		}

		if mount.Source == "/" && mount.MountPoint != "/" && mount.MountPoint != "" {
			sev := SeverityMedium
			if inContainer {
				sev = SeverityHigh
			}
			addFinding(
				sev,
				"Potential host root bind mount detected in process mount namespace.",
				evidence,
			)
			continue
		}

		if strings.HasPrefix(source, "/proc/1/root") || strings.HasPrefix(source, "/host") {
			addFinding(
				SeverityHigh,
				"Mount source appears to expose host filesystem paths inside the process namespace.",
				evidence,
			)
			continue
		}

		if inContainer && fsType == "nsfs" && strings.HasPrefix(point, "/var/run/docker/netns/") {
			addFinding(
				SeverityMedium,
				"Container process can access host network namespace mountpoints.",
				evidence,
			)
		}
	}

	return findings
}

func isContainerizedCgroup(cgroup []string) bool {
	for _, line := range cgroup {
		l := strings.ToLower(line)
		if strings.Contains(l, "docker") ||
			strings.Contains(l, "kubepods") ||
			strings.Contains(l, "containerd") ||
			strings.Contains(l, "podman") ||
			strings.Contains(l, "crio") ||
			strings.Contains(l, "libpod") ||
			strings.Contains(l, "lxc") {
			return true
		}
	}
	return false
}

func readStatusFields(pid int) map[string]string {
	f, err := os.Open(procPath(pid, "status"))
	if err != nil {
		return nil
	}
	defer f.Close()

	out := map[string]string{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out
}

func atoiDefault(v string, fallback int) int {
	parsed, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return fallback
	}
	return parsed
}

func decodeMountField(v string) string {
	// mountinfo/mounts escape spaces and some characters as octal sequences.
	return strings.NewReplacer(
		`\\040`, " ",
		`\\011`, "\t",
		`\\012`, "\n",
		`\\134`, `\`,
	).Replace(v)
}

func readLimits(pid int) (map[string]string, bool) {
	f, err := os.Open(procPath(pid, "limits"))
	if err != nil {
		return nil, false
	}
	defer f.Close()

	limits := map[string]string{}
	coreEnabled := false

	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if lineNo == 1 || line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		name := strings.Join(fields[:len(fields)-3], " ")
		soft := fields[len(fields)-3]
		hard := fields[len(fields)-2]
		units := fields[len(fields)-1]
		limits[name] = soft + "/" + hard + " " + units

		if name == "Max core file size" && soft != "0" {
			coreEnabled = true
		}
	}

	return limits, coreEnabled
}

func readCoreDumpFilter(pid int) string {
	b, err := os.ReadFile(procPath(pid, "coredump_filter"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func readSyscall(pid int) string {
	b, err := os.ReadFile(procPath(pid, "syscall"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func splitNulSeparated(b []byte) []string {
	parts := strings.Split(string(b), "\x00")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}

func splitAddrRange(v string) (string, string) {
	parts := strings.SplitN(v, "-", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return parts[0], parts[1]
}

func classifySharedObject(pathname string) (Severity, bool) {
	lower := strings.ToLower(pathname)
	if lower == "" {
		return "", false
	}

	if strings.HasSuffix(lower, "ld.so.cache") {
		return "", false
	}

	// Ignore non-.so entries to avoid false positives like /etc/ld.so.cache.
	if !sharedObjectPathRe.MatchString(strings.TrimSpace(pathname)) && !strings.Contains(lower, "memfd:") {
		return "", false
	}

	if strings.Contains(lower, "memfd:") || strings.Contains(lower, "(deleted)") {
		return SeverityHigh, true
	}
	if strings.HasPrefix(lower, "/tmp/") || strings.HasPrefix(lower, "/dev/shm/") || strings.HasPrefix(lower, "/var/tmp/") {
		return SeverityHigh, true
	}
	if strings.HasPrefix(lower, "/lib/") || strings.HasPrefix(lower, "/usr/lib/") || strings.HasPrefix(lower, "/usr/local/lib/") {
		return "", false
	}
	return SeverityMedium, true
}

func hasCapBit(hexValue string, bit int) bool {
	if hexValue == "" || bit < 0 || bit > 63 {
		return false
	}
	v, err := strconv.ParseUint(strings.TrimSpace(hexValue), 16, 64)
	if err != nil {
		return false
	}
	return (v & (uint64(1) << bit)) != 0
}

func isSuspiciousExecPath(path string) bool {
	if path == "" {
		return false
	}
	if strings.Contains(strings.ToLower(path), "(deleted)") {
		return true
	}
	return isWritableTransientPath(path)
}

func isWritableTransientPath(path string) bool {
	lower := strings.ToLower(filepath.Clean(path))
	return strings.HasPrefix(lower, "/tmp/") ||
		strings.HasPrefix(lower, "/dev/shm/") ||
		strings.HasPrefix(lower, "/var/tmp/")
}

func procPath(pid int, elems ...string) string {
	parts := []string{procFSRoot, itoa(pid)}
	parts = append(parts, elems...)
	return filepath.Join(parts...)
}

func truncateEvidence(v string) string {
	if len(v) <= maxEvidenceLength {
		return v
	}
	return v[:maxEvidenceLength] + "..."
}
