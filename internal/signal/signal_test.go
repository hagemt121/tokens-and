package signal

import (
	"strings"
	"testing"
)

func TestDecodeSemgrep(t *testing.T) {
	in := `{"results":[{"check_id":"rule.one","path":"main.go","start":{"line":12},"extra":{"message":"unsafe call","severity":"ERROR"}}]}`
	ch := make(chan Finding, 1)
	if err := Decode("semgrep", strings.NewReader(in), ch); err != nil {
		t.Fatal(err)
	}
	f := <-ch
	if f.Source != "semgrep" || f.Severity != "HIGH" || f.RuleID != "rule.one" || f.Path != "main.go" || f.Line != "12" {
		t.Fatalf("unexpected finding: %+v", f)
	}
}

func TestDecodeGosecSkipsSuppressed(t *testing.T) {
	in := `{"Issues":[{"rule_id":"G101","severity":"HIGH","details":"secret","file":"main.go","line":"8"},{"rule_id":"G102","severity":"LOW","nosec":true},{"rule_id":"G103","severity":"MEDIUM","suppressions":[{"kind":"comment"}]}]}`
	ch := make(chan Finding, 3)
	if err := Decode("gosec", strings.NewReader(in), ch); err != nil {
		t.Fatal(err)
	}
	if len(ch) != 1 {
		t.Fatalf("got %d findings, want 1", len(ch))
	}
	f := <-ch
	if f.RuleID != "G101" || f.Line != "8" {
		t.Fatalf("unexpected finding: %+v", f)
	}
}

func TestAtLeast(t *testing.T) {
	if !AtLeast("CRITICAL", "HIGH") || AtLeast("MEDIUM", "HIGH") || AtLeast("UNKNOWN", "LOW") {
		t.Fatal("severity ordering incorrect")
	}
}
