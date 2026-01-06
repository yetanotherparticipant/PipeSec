package app

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yetanotherparticipant/PipeSec/dynamic/internal/dynscan"
	"github.com/yetanotherparticipant/PipeSec/dynamic/internal/notify"
	"github.com/yetanotherparticipant/PipeSec/dynamic/internal/report"
)

const egressCheckInterval = 200 * time.Millisecond
const heavyProcCheckInterval = time.Second

func Run() int {
	return run(os.Args[1:], os.Args, os.Stdout, os.Stderr)
}

func run(args []string, fullArgs []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("pipesec-dynamic", flag.ContinueOnError)
	fs.SetOutput(stderr)

	mode := fs.String("mode", "scan", "scan|run")
	format := fs.String("format", "console", "console|json")
	source := fs.String("source", "stdin", "source label for findings")
	logFile := fs.String("log", "", "path to log file (optional; default stdin)")
	timeout := fs.Duration("timeout", 0, "timeout for run mode (0 = none)")
	patternsPath := fs.String("patterns", "", "path to secret_patterns.json (optional)")
	procPolicyPath := fs.String("proc-policy", "", "path to proc monitor policy json (optional)")
	failOn := fs.String("fail-on", "CRITICAL", "return exit 1 if severity >= LEVEL (LOW|MEDIUM|HIGH|CRITICAL)")
	failOnEgress := fs.Bool("fail-on-egress", false, "treat any egress as CRITICAL")
	allowList := fs.String("allow-list", "", "comma-separated list of allowed IPs (LOW severity)")
	denyList := fs.String("deny-list", "", "comma-separated list of denied IPs (CRITICAL severity)")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}

	patterns := dynscan.DefaultSecretPatterns()
	if *patternsPath != "" {
		if loaded, err := dynscan.LoadSecretPatternsFromFile(*patternsPath); err == nil {
			patterns = loaded
		} else {
			fmt.Fprintln(stderr, "warning: failed to load patterns:", err)
		}
	} else if loaded, _, err := dynscan.LoadSecretPatternsAuto(); err == nil {
		patterns = loaded
	}

	if *procPolicyPath != "" {
		if policy, err := dynscan.LoadProcMonitorPolicyFromFile(*procPolicyPath); err == nil {
			dynscan.SetProcMonitorPolicy(policy)
		} else {
			fmt.Fprintln(stderr, "warning: failed to load proc policy:", err)
		}
	} else if policy, _, err := dynscan.LoadProcMonitorPolicyAuto(); err == nil {
		dynscan.SetProcMonitorPolicy(policy)
	}

	var findings []dynscan.Finding
	switch *mode {
	case "scan":
		findings = scanMode(*logFile, *source, patterns)
	case "run":
		if fs.NArg() == 0 {
			fmt.Fprintln(stderr, "pipesec-dynamic -mode run -- <command> [args...]")
			return 2
		}
		cmdName := fs.Arg(0)
		cmdArgs := fs.Args()[1:]
		findings = runMode(
			*source,
			cmdName,
			cmdArgs,
			*timeout,
			patterns,
			*failOn,
			*failOnEgress,
			*allowList,
			*denyList,
		)
	default:
		fmt.Fprintln(stderr, "unknown -mode:", *mode)
		return 2
	}

	code := report.ExitCode(findings, *failOn)
	fmt.Fprintln(stdout, report.Render(findings, *format))
	if code != 0 {
		summary := fmt.Sprintf(
			"PipeSec Dynamic Scan\nFound %d issues.\nCommand line: `%s`",
			len(findings),
			strings.Join(fullArgs, " "),
		)
		for _, channel := range notify.ChannelsFromEnv() {
			channel.Send(summary, findings)
		}
	}
	return code
}

func scanMode(logFile, source string, patterns []dynscan.SecretPattern) []dynscan.Finding {
	var r io.Reader = os.Stdin
	if logFile != "" {
		f, err := os.Open(logFile)
		if err != nil {
			return findingsWithIOError(logFile, err)
		}
		defer f.Close()
		r = f
	}
	return dynscan.ScanLogStream(r, source, patterns)
}

func runMode(
	source string,
	cmdName string,
	cmdArgs []string,
	timeout time.Duration,
	patterns []dynscan.SecretPattern,
	failOn string,
	failOnEgress bool,
	allowList string,
	denyList string,
) []dynscan.Finding {
	ctx, cancel := commandContext(timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, cmdName, cmdArgs...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return findingsWithExecError(cmdName, err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return findingsWithExecError(cmdName, err)
	}

	if err := cmd.Start(); err != nil {
		return findingsWithExecError(cmdName, err)
	}

	var (
		findings         []dynscan.Finding
		findingsMu       sync.Mutex
		cancelOnce       sync.Once
		proactiveStopped atomic.Bool
	)

	recordFinding := func(f dynscan.Finding) {
		f = applyEgressPolicy(f, failOnEgress, allowList, denyList)
		findingsMu.Lock()
		findings = append(findings, f)
		findingsMu.Unlock()
		if !shouldStopProactively(f.Severity, failOn) {
			return
		}
		cancelOnce.Do(func() {
			proactiveStopped.Store(true)
			cancel()
		})
	}

	before := dynscan.LinuxRemoteEndpoints()
	observed := map[string]struct{}{}
	var observedMu sync.Mutex

	emitEgressFindings := func(snapshot map[string]struct{}) {
		for ep := range snapshot {
			if _, ok := before[ep]; ok {
				continue
			}

			observedMu.Lock()
			if _, seen := observed[ep]; seen {
				observedMu.Unlock()
				continue
			}
			observed[ep] = struct{}{}
			observedMu.Unlock()

			sev := classifyEgressSeverity(ep, failOnEgress, allowList, denyList)
			recordFinding(dynscan.Finding{
				Severity:       sev,
				Category:       "Network Egress (Observed)",
				Description:    "A new outbound network connection was detected while the command was running.",
				Location:       source,
				Recommendation: "Validate whether network access is necessary; for CI, prefer restricting egress and/or enforcing a fixed allowlist of domains.",
				Evidence:       ep,
			})
		}
	}

	stopEgress := make(chan struct{})
	egressDone := make(chan struct{})
	go func() {
		defer close(egressDone)
		t := time.NewTicker(egressCheckInterval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				emitEgressFindings(dynscan.LinuxRemoteEndpoints())
			case <-stopEgress:
				return
			}
		}
	}()

	stopProc := make(chan struct{})
	procFindings := monitorProcessTree(cmd, patterns, stopProc)
	var procWG sync.WaitGroup
	procWG.Add(1)
	go func() {
		defer procWG.Done()
		for f := range procFindings {
			recordFinding(f)
		}
	}()

	var scanWG sync.WaitGroup
	scanWG.Add(2)
	go func() {
		defer scanWG.Done()
		streamScanLog(stdout, source+":stdout", patterns, recordFinding)
	}()
	go func() {
		defer scanWG.Done()
		streamScanLog(stderr, source+":stderr", patterns, recordFinding)
	}()

	waitErr := cmd.Wait()
	close(stopEgress)
	<-egressDone
	emitEgressFindings(dynscan.LinuxRemoteEndpoints())
	close(stopProc)
	scanWG.Wait()
	procWG.Wait()

	if waitErr != nil && !proactiveStopped.Load() {
		findingsMu.Lock()
		findings = append(findings, dynscan.Finding{
			Severity:       dynscan.SeverityLow,
			Category:       "Command Exit",
			Description:    "The command exited with an error.",
			Location:       cmdName,
			Recommendation: "Check the command execution logs.",
			Evidence:       waitErr.Error(),
		})
		findingsMu.Unlock()
	}

	findingsMu.Lock()
	defer findingsMu.Unlock()
	return findings
}

func checkIP(endpoint, list string) bool {
	ip := endpointIP(endpoint)
	if ip == "" {
		return false
	}
	candidates := strings.Split(list, ",")
	for _, c := range candidates {
		if strings.TrimSpace(c) == ip {
			return true
		}
	}
	return false
}

func classifyEgressSeverity(endpoint string, failOnEgress bool, allowList string, denyList string) dynscan.Severity {
	endpoint = normalizeEgressEndpoint(endpoint)
	if failOnEgress {
		return dynscan.SeverityCritical
	}
	if allowList != "" {
		if checkIP(endpoint, allowList) {
			return dynscan.SeverityLow
		}
		return dynscan.SeverityCritical
	}
	if denyList != "" && checkIP(endpoint, denyList) {
		return dynscan.SeverityCritical
	}
	return dynscan.SeverityMedium
}

func applyEgressPolicy(f dynscan.Finding, failOnEgress bool, allowList string, denyList string) dynscan.Finding {
	if !strings.HasPrefix(f.Category, "Network Egress") {
		return f
	}
	endpoint := normalizeEgressEndpoint(f.Evidence)
	if endpoint == "" {
		if failOnEgress {
			f.Severity = dynscan.SeverityCritical
		}
		return f
	}
	f.Severity = classifyEgressSeverity(endpoint, failOnEgress, allowList, denyList)
	return f
}

func normalizeEgressEndpoint(evidence string) string {
	endpoint := strings.TrimSpace(evidence)
	if endpoint == "" {
		return endpoint
	}

	if proto, rest, ok := strings.Cut(endpoint, ":"); ok {
		switch strings.ToLower(strings.TrimSpace(proto)) {
		case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6":
			endpoint = strings.TrimSpace(rest)
		}
	}
	return endpoint
}

func endpointIP(endpoint string) string {
	endpoint = normalizeEgressEndpoint(endpoint)
	if endpoint == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(endpoint); err == nil {
		return strings.Trim(host, "[]")
	}
	parts := strings.Split(endpoint, ":")
	if len(parts) == 0 {
		return ""
	}
	return strings.Trim(parts[0], "[]")
}

func shouldStopProactively(severity dynscan.Severity, failOn string) bool {
	threshold := parseFailOnThreshold(failOn)
	return severityLevel(severity) >= threshold
}

func parseFailOnThreshold(failOn string) int {
	switch strings.ToUpper(strings.TrimSpace(failOn)) {
	case "", "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 5
	}
}

func severityLevel(severity dynscan.Severity) int {
	switch severity {
	case dynscan.SeverityLow:
		return 1
	case dynscan.SeverityMedium:
		return 2
	case dynscan.SeverityHigh:
		return 3
	case dynscan.SeverityCritical:
		return 4
	default:
		return 0
	}
}

func streamScanLog(r io.Reader, source string, patterns []dynscan.SecretPattern, emit func(dynscan.Finding)) {
	const maxEvidenceLength = 20

	scanner := bufio.NewScanner(r)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		for _, p := range patterns {
			matches := p.Re.FindAllString(line, -1)
			for _, m := range matches {
				evidence := m
				if len(evidence) > maxEvidenceLength {
					evidence = evidence[:maxEvidenceLength] + "..."
				}
				emit(dynscan.Finding{
					Severity:       dynscan.SeverityCritical,
					Category:       "Secret in Logs",
					Description:    "Detected secret of type '" + p.Name + "' in the log stream.",
					Location:       source + ":line " + strconvItoa(lineNo),
					Recommendation: "A secret was written to logs: rotate the secret immediately and remove its output to stdout/stderr.",
					Evidence:       evidence,
				})
			}
		}
	}
}

func findingsWithIOError(path string, err error) []dynscan.Finding {
	return []dynscan.Finding{{
		Severity:       dynscan.SeverityLow,
		Category:       "IO Error",
		Description:    "Failed to open the log file.",
		Location:       path,
		Recommendation: "Verify the path and access permissions.",
		Evidence:       err.Error(),
	}}
}

func findingsWithExecError(cmd string, err error) []dynscan.Finding {
	return []dynscan.Finding{{
		Severity:       dynscan.SeverityLow,
		Category:       "Exec Error",
		Description:    "Failed to start the command.",
		Location:       cmd,
		Recommendation: "Verify the command name and environment.",
		Evidence:       err.Error(),
	}}
}

func commandContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return context.WithCancel(context.Background())
	}
	return context.WithTimeout(context.Background(), timeout)
}

func monitorProcessTree(cmd *exec.Cmd, patterns []dynscan.SecretPattern, stop <-chan struct{}) <-chan dynscan.Finding {
	out := make(chan dynscan.Finding, 128)

	go func() {
		defer close(out)

		seen := map[string]struct{}{}
		emit := func(f dynscan.Finding) {
			key := findingDedupKey(f)
			if _, ok := seen[key]; ok {
				return
			}
			seen[key] = struct{}{}
			select {
			case out <- f:
			default:
			}
		}

		runFastSweep := func() {
			if cmd.Process == nil {
				return
			}
			rootPID := cmd.Process.Pid
			if rootPID <= 0 {
				return
			}
			pids := append([]int{rootPID}, dynscan.DiscoverChildren(rootPID)...)
			for _, pid := range pids {
				_, envFindings := dynscan.ReadEnviron(pid, patterns)
				for _, finding := range envFindings {
					emit(finding)
				}

				_, mapFindings := dynscan.ParseMaps(pid)
				for _, finding := range mapFindings {
					emit(finding)
				}

				_, capFindings := dynscan.ReadCapabilities(pid)
				for _, finding := range capFindings {
					emit(finding)
				}

				cmdline := dynscan.ReadCmdline(pid)
				if pid != rootPID && dynscan.IsSuspiciousChildCommand(cmdline) {
					emit(dynscan.Finding{
						Severity:       dynscan.SeverityMedium,
						Category:       "Suspicious Child Process",
						Description:    "Detected a suspicious networking utility in a child process command line.",
						Location:       "/proc/" + strconvItoa(pid) + "/cmdline",
						Recommendation: "Review why this child process was spawned and restrict unexpected networking tools in CI jobs.",
						Evidence:       strings.Join(cmdline, " "),
					})
				}
			}
		}

		runHeavySweep := func() {
			if cmd.Process == nil {
				return
			}
			rootPID := cmd.Process.Pid
			if rootPID <= 0 {
				return
			}

			children := dynscan.DiscoverChildren(rootPID)
			sort.Ints(children)
			pids := append([]int{rootPID}, children...)

			var rootInfo *dynscan.ProcInfo
			infoByPID := make(map[int]*dynscan.ProcInfo, len(pids))

			for _, pid := range pids {
				info, findings := dynscan.CollectProcInfo(pid, patterns)
				if info != nil {
					infoByPID[pid] = info
					if pid == rootPID {
						rootInfo = info
					}
				}
				for _, finding := range findings {
					emit(finding)
				}
			}

			if rootInfo == nil {
				return
			}
			for _, pid := range children {
				child := infoByPID[pid]
				for _, finding := range dynscan.NamespaceDiffFindings(rootInfo, child) {
					emit(finding)
				}
			}
		}

		fastTicker := time.NewTicker(egressCheckInterval)
		defer fastTicker.Stop()
		heavyTicker := time.NewTicker(heavyProcCheckInterval)
		defer heavyTicker.Stop()

		runFastSweep()
		runHeavySweep()

		for {
			select {
			case <-fastTicker.C:
				runFastSweep()
			case <-heavyTicker.C:
				runHeavySweep()
			case <-stop:
				runFastSweep()
				runHeavySweep()
				return
			}
		}
	}()

	return out
}

func findingDedupKey(f dynscan.Finding) string {
	return string(f.Severity) + "|" + f.Category + "|" + f.Location + "|" + f.Evidence + "|" + f.Description
}

func strconvItoa(v int) string {
	return fmt.Sprintf("%d", v)
}
