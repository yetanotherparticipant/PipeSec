package report

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yetanotherparticipant/PipeSec/dynamic/internal/dynscan"
)

func ExitCode(findings []dynscan.Finding, failOn string) int {
	if failOn == "" {
		for _, f := range findings {
			if f.Severity == dynscan.SeverityCritical {
				return 1
			}
		}
		return 0
	}

	levels := map[dynscan.Severity]int{
		dynscan.SeverityLow:      1,
		dynscan.SeverityMedium:   2,
		dynscan.SeverityHigh:     3,
		dynscan.SeverityCritical: 4,
	}

	threshold, ok := map[string]int{
		"LOW":      1,
		"MEDIUM":   2,
		"HIGH":     3,
		"CRITICAL": 4,
	}[strings.ToUpper(failOn)]
	if !ok {
		return 0
	}

	maxSev := 0
	for _, f := range findings {
		if lvl, ok := levels[f.Severity]; ok && lvl > maxSev {
			maxSev = lvl
		}
	}

	if maxSev >= threshold {
		return 1
	}
	return 0
}

func Render(findings []dynscan.Finding, format string) string {
	if format == "json" {
		b, _ := json.MarshalIndent(map[string]any{
			"findings": findings,
			"count":    len(findings),
		}, "", "  ")
		return string(b)
	}

	if len(findings) == 0 {
		return "No vulnerabilities found!"
	}

	lines := make([]string, 0, len(findings)*6+8)
	lines = append(lines, "")
	lines = append(lines, strings.Repeat("=", 80))
	lines = append(lines, "PipeSec Dynamic - Report")
	lines = append(lines, strings.Repeat("=", 80))
	lines = append(lines, "")
	lines = append(lines, fmt.Sprintf("Total issues found: %d", len(findings)))

	for i, f := range findings {
		lines = append(lines, "")
		lines = append(lines, fmt.Sprintf("#%d [%s] %s", i+1, f.Severity, f.Category))
		lines = append(lines, "   Location: "+f.Location)
		lines = append(lines, "   Description: "+f.Description)
		if f.Evidence != "" {
			lines = append(lines, "   Evidence: "+f.Evidence)
		}
		lines = append(lines, "   Recommendation: "+f.Recommendation)
	}

	lines = append(lines, "")
	lines = append(lines, strings.Repeat("=", 80))
	return strings.Join(lines, "\n")
}
