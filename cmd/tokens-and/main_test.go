package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/hagemt121/tokens-and/internal/semgrepcli"
)

func TestScanUsesSemgrepCLI(t *testing.T) {
	dir := t.TempDir()
	cli := filepath.Join(dir, "custom-semgrep")
	script := "#!/bin/sh\n" +
		"[ \"$1\" = scan ] && [ \"$2\" = --config ] && [ \"$3\" = p/test ] && [ \"$4\" = --json ] && [ \"$5\" = . ] || exit 2\n" +
		"printf '%s' '{\"results\":[{\"check_id\":\"test\",\"path\":\"main.go\",\"start\":{\"line\":1},\"extra\":{\"message\":\"test finding\",\"severity\":\"ERROR\"}}]}'\n"
	if err := os.WriteFile(cli, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SEMGREP_CLI", cli)
	if got, err := semgrepcli.Resolve(); err != nil || got != cli {
		t.Fatalf("got %q, %v; want %q", got, err, cli)
	}
	if err := run(context.Background(), "semgrep", "-", "HIGH", "log", true, "p/test", ".", ""); err != nil {
		t.Fatal(err)
	}
}

func TestSemgrepCLIRejectsInvalidOverride(t *testing.T) {
	t.Setenv("SEMGREP_CLI", filepath.Join(t.TempDir(), "missing"))
	if _, err := semgrepcli.Resolve(); err == nil {
		t.Fatal("expected invalid SEMGREP_CLI to fail")
	}
}
