package signal

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Finding is the scanner-independent message sent through the application's channel.
type Finding struct {
	Source   string `json:"source"`
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Path     string `json:"path"`
	Line     string `json:"line"`
}

// Decode reads one complete scanner JSON report and emits its findings.
// The caller owns and closes out; callers may also send Finding values directly.
func Decode(format string, in io.Reader, out chan<- Finding) error {
	switch strings.ToLower(format) {
	case "semgrep":
		var report struct {
			Results []struct {
				CheckID string `json:"check_id"`
				Path    string `json:"path"`
				Start   struct {
					Line int `json:"line"`
				} `json:"start"`
				Extra struct {
					Message  string `json:"message"`
					Severity string `json:"severity"`
				} `json:"extra"`
			} `json:"results"`
		}
		if err := json.NewDecoder(in).Decode(&report); err != nil {
			return fmt.Errorf("decode semgrep: %w", err)
		}
		for _, r := range report.Results {
			out <- Finding{Source: "semgrep", RuleID: r.CheckID, Severity: normalizeSemgrep(r.Extra.Severity), Message: r.Extra.Message, Path: r.Path, Line: fmt.Sprint(r.Start.Line)}
		}
	case "gosec":
		var report struct {
			Issues []struct {
				RuleID       string            `json:"rule_id"`
				Severity     string            `json:"severity"`
				Details      string            `json:"details"`
				File         string            `json:"file"`
				Line         string            `json:"line"`
				NoSec        bool              `json:"nosec"`
				Suppressions []json.RawMessage `json:"suppressions"`
			} `json:"Issues"`
		}
		if err := json.NewDecoder(in).Decode(&report); err != nil {
			return fmt.Errorf("decode gosec: %w", err)
		}
		for _, r := range report.Issues {
			if r.NoSec || len(r.Suppressions) > 0 {
				continue
			}
			out <- Finding{Source: "gosec", RuleID: r.RuleID, Severity: strings.ToUpper(r.Severity), Message: r.Details, Path: r.File, Line: r.Line}
		}
	default:
		return fmt.Errorf("unsupported scanner %q (use semgrep or gosec)", format)
	}
	return nil
}

func normalizeSemgrep(severity string) string {
	switch strings.ToUpper(severity) {
	case "ERROR":
		return "HIGH"
	case "WARNING":
		return "MEDIUM"
	case "INFO":
		return "LOW"
	default:
		return strings.ToUpper(severity)
	}
}

func AtLeast(actual, minimum string) bool {
	rank := map[string]int{"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
	return rank[strings.ToUpper(actual)] >= rank[strings.ToUpper(minimum)] && rank[strings.ToUpper(actual)] > 0
}
