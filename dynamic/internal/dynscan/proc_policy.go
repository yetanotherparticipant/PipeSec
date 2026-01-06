package dynscan

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sync"
)

type ProcMonitorPolicy struct {
	Version             int      `json:"version"`
	DangerousFDPatterns []string `json:"dangerous_fd_patterns"`
	SecretFDPatterns    []string `json:"secret_fd_patterns"`
}

type compiledProcMonitorPolicy struct {
	dangerousFDPatterns []*regexp.Regexp
	secretFDPatterns    []*regexp.Regexp
}

var (
	procPolicyMu sync.RWMutex
	procPolicy   compiledProcMonitorPolicy
)

func SetProcMonitorPolicy(policy ProcMonitorPolicy) {
	procPolicyMu.Lock()
	defer procPolicyMu.Unlock()
	procPolicy = compileProcMonitorPolicy(policy)
}

func matchFDTargetByPolicy(target string) (category string, matched bool) {
	p := getCompiledProcMonitorPolicy()
	for _, re := range p.dangerousFDPatterns {
		if re.MatchString(target) {
			return "Dangerous Open File Descriptor", true
		}
	}
	for _, re := range p.secretFDPatterns {
		if re.MatchString(target) {
			return "Runtime Secret File Access", true
		}
	}
	return "", false
}

func getCompiledProcMonitorPolicy() compiledProcMonitorPolicy {
	procPolicyMu.RLock()
	defer procPolicyMu.RUnlock()
	return procPolicy
}

func compileProcMonitorPolicy(policy ProcMonitorPolicy) compiledProcMonitorPolicy {
	return compiledProcMonitorPolicy{
		dangerousFDPatterns: compileRegexList(policy.DangerousFDPatterns),
		secretFDPatterns:    compileRegexList(policy.SecretFDPatterns),
	}
}

func compileRegexList(in []string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(in))
	for _, pattern := range in {
		if pattern == "" {
			continue
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		out = append(out, re)
	}
	return out
}

func LoadProcMonitorPolicyFromFile(path string) (ProcMonitorPolicy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return ProcMonitorPolicy{}, err
	}

	var p ProcMonitorPolicy
	if err := json.Unmarshal(b, &p); err != nil {
		return ProcMonitorPolicy{}, err
	}
	if len(p.DangerousFDPatterns) == 0 && len(p.SecretFDPatterns) == 0 {
		return ProcMonitorPolicy{}, errors.New("policy has no fd patterns")
	}
	return p, nil
}

func LoadProcMonitorPolicyAuto() (ProcMonitorPolicy, string, error) {
	for _, candidate := range candidateProcPolicyFiles() {
		if candidate == "" {
			continue
		}
		if _, err := os.Stat(candidate); err != nil {
			continue
		}
		policy, err := LoadProcMonitorPolicyFromFile(candidate)
		if err != nil {
			continue
		}
		return policy, candidate, nil
	}
	return ProcMonitorPolicy{}, "", errors.New("proc monitor policy not found")
}

func candidateProcPolicyFiles() []string {
	out := []string{
		filepath.Join("data", "proc_monitor_policy.json"),
		filepath.Join("..", "data", "proc_monitor_policy.json"),
	}

	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		out = append(
			out,
			filepath.Join(exeDir, "data", "proc_monitor_policy.json"),
			filepath.Join(exeDir, "..", "data", "proc_monitor_policy.json"),
		)
	}

	return out
}
