//go:build !linux

package dynscan

func CollectProcInfo(pid int, patterns []SecretPattern) (*ProcInfo, []Finding) {
	return nil, nil
}

func DiscoverChildren(pid int) []int {
	return nil
}

func ReadCmdline(pid int) []string {
	return nil
}

func ReadEnviron(pid int, patterns []SecretPattern) (map[string]string, []Finding) {
	return nil, nil
}

func ParseMaps(pid int) ([]MappedRegion, []Finding) {
	return nil, nil
}

func ReadCapabilities(pid int) (ProcCaps, []Finding) {
	return ProcCaps{}, nil
}

func ReadStatusSecurity(pid int) (ProcStatus, []Finding) {
	return ProcStatus{}, nil
}

func IsSuspiciousChildCommand(cmdline []string) bool {
	return false
}

func NamespaceDiffFindings(rootInfo, childInfo *ProcInfo) []Finding {
	return nil
}
