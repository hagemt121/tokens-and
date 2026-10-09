package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/hagemt121/tokens-and/internal/semgrepcli"
	"github.com/hagemt121/tokens-and/internal/services"
	"github.com/hagemt121/tokens-and/internal/signal"
	"github.com/hagemt121/tokens-and/internal/slack"
	"github.com/hagemt121/tokens-and/internal/spotify"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "lookup-user" {
		if err := lookupUser(context.Background(), os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "spotify-login" {
		if len(os.Args) != 2 {
			log.Fatal("spotify-login takes no arguments")
		}
		config, err := spotify.AuthConfigFromEnv()
		if err != nil {
			log.Fatal(err)
		}
		if err := config.Login(context.Background(), os.Stdout); err != nil {
			log.Fatal(err)
		}
		return
	}
	scanner := flag.String("scanner", "semgrep", "report format: semgrep or gosec")
	report := flag.String("report", "-", "JSON report path, or - for stdin")
	scan := flag.Bool("scan", false, "run Semgrep and read its JSON output instead of a report")
	semgrepConfig := flag.String("semgrep-config", "p/security-audit", "Semgrep ruleset for -scan")
	target := flag.String("target", ".", "scan target for -scan")
	minimum := flag.String("min-severity", "HIGH", "minimum severity: LOW, MEDIUM, HIGH, or CRITICAL")
	action := flag.String("action", "log", "action: log or pause")
	daemonURL := flag.String("daemon-url", "", "also publish matching findings to a signal daemon")
	flag.Parse()
	if err := run(context.Background(), *scanner, *report, *minimum, *action, *scan, *semgrepConfig, *target, *daemonURL); err != nil {
		log.Fatal(err)
	}
}

func lookupUser(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("lookup-user", flag.ContinueOnError)
	workspace := flags.String("workspace", "", "Slack workspace ID (for example T123)")
	email := flags.String("email", "", "email address to look up")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected lookup-user argument %q", flags.Arg(0))
	}
	client := slack.Client{Token: os.Getenv("SLACK_BOT_TOKEN")}
	id, err := client.LookupUser(ctx, *workspace, *email)
	if err != nil {
		return err
	}
	fmt.Println(id)
	return nil
}

func run(ctx context.Context, scanner, report, minimum, action string, scan bool, semgrepConfig, target, daemonURL string) error {
	if !signal.AtLeast(minimum, "LOW") {
		return fmt.Errorf("invalid min-severity %q", minimum)
	}
	if action != "log" && action != "pause" {
		return fmt.Errorf("invalid action %q", action)
	}
	var input io.Reader = os.Stdin
	if scan {
		if scanner != "semgrep" || report != "-" {
			return fmt.Errorf("-scan requires -scanner semgrep and no -report file")
		}
		output, err := semgrepcli.Scan(ctx, semgrepConfig, target)
		if err != nil {
			return err
		}
		input = bytes.NewReader(output)
	} else if report != "-" {
		file, err := os.Open(report)
		if err != nil {
			return err
		}
		defer file.Close()
		input = file
	}
	findings := make(chan signal.Finding)
	decodeErrors := make(chan error, 1)
	go func() {
		defer close(findings)
		decodeErrors <- signal.Decode(scanner, input, findings)
	}()
	var client spotify.Client
	busClient := services.Client{URL: daemonURL, Token: os.Getenv("SIGNAL_API_TOKEN")}
	var actionErr error
	pauseAttempted := false
	for finding := range findings {
		if !signal.AtLeast(finding.Severity, minimum) {
			continue
		}
		log.Printf("%s %s %s %s:%s: %s", finding.Source, finding.Severity, finding.RuleID, finding.Path, finding.Line, finding.Message)
		if daemonURL != "" {
			if err := busClient.Publish(ctx, finding); err != nil {
				actionErr = errors.Join(actionErr, err)
			}
		}
		if action == "pause" && !pauseAttempted {
			pauseAttempted = true
			var err error
			client, err = spotify.NewClientFromEnv(ctx)
			if err == nil {
				err = client.Pause(ctx)
			}
			actionErr = errors.Join(actionErr, err)
		}
	}
	if err := <-decodeErrors; err != nil {
		return err
	}
	return actionErr
}
