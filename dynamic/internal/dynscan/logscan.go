package dynscan

import (
	"bufio"
	"io"
)

const maxEvidenceLength = 20

func ScanLogStream(r io.Reader, source string, patterns []SecretPattern) []Finding {
	var findings []Finding

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
				findings = append(findings, Finding{
					Severity:       SeverityCritical,
					Category:       "Secret in Logs",
					Description:    "Detected secret of type '" + p.Name + "' in the log stream.",
					Location:       source + ":line " + itoa(lineNo),
					Recommendation: "A secret was written to logs: rotate the secret immediately and remove its output to stdout/stderr.",
					Evidence:       evidence,
				})
			}
		}
	}

	return findings
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [32]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
