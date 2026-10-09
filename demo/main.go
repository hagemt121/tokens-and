package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"

	"github.com/hagemt121/tokens-and/internal/semgrepcli"
	"github.com/hagemt121/tokens-and/internal/signal"
)

func main() {
	if err := run(context.Background()); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context) error {
	output, err := semgrepcli.Scan(ctx, "p/security-audit", ".")
	if err != nil {
		return err
	}
	findings := make(chan signal.Finding)
	decodeErrors := make(chan error, 1)
	go func() {
		defer close(findings)
		decodeErrors <- signal.Decode("semgrep", bytes.NewReader(output), findings)
	}()
	count := 0
	for finding := range findings {
		count++
		fmt.Fprintf(os.Stdout, "%s %s %s:%s: %s\n", finding.Severity, finding.RuleID, finding.Path, finding.Line, finding.Message)
	}
	if err := <-decodeErrors; err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "Semgrep: %d findings\n", count)
	return nil
}
