package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	ossignal "os/signal"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"

	"github.com/hagemt121/tokens-and/internal/services"
	"github.com/hagemt121/tokens-and/internal/signal"
	"github.com/hagemt121/tokens-and/internal/slack"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8787", "HTTP listen address")
	minimum := flag.String("min-severity", "HIGH", "minimum severity sent to Slack")
	flag.Parse()
	if !signal.AtLeast(*minimum, "LOW") {
		log.Fatal("invalid min-severity")
	}
	if os.Getenv("SIGNAL_API_TOKEN") == "" {
		log.Fatal("SIGNAL_API_TOKEN is required")
	}
	if os.Getenv("SLACK_BOT_TOKEN") == "" || (os.Getenv("SLACK_ADMIN_USER_ID") == "" && os.Getenv("SLACK_CHANNEL_ID") == "") {
		log.Fatal("SLACK_BOT_TOKEN and SLACK_ADMIN_USER_ID or SLACK_CHANNEL_ID are required")
	}
	ctx, stop := ossignal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	group, groupCtx := errgroup.WithContext(ctx)
	bus := services.NewBus(128)
	slackClient := slack.Client{Token: os.Getenv("SLACK_BOT_TOKEN"), AdminUserID: os.Getenv("SLACK_ADMIN_USER_ID"), ChannelID: os.Getenv("SLACK_CHANNEL_ID")}
	limiter := rate.NewLimiter(rate.Every(time.Second), 1)
	group.Go(func() error {
		for {
			select {
			case <-groupCtx.Done():
				return nil
			case finding := <-bus.Signals():
				if !signal.AtLeast(finding.Severity, *minimum) {
					continue
				}
				if err := limiter.Wait(groupCtx); err != nil {
					return nil
				}
				if err := slackClient.Send(groupCtx, finding); err != nil {
					log.Printf("Slack delivery failed: %v", err)
				}
			}
		}
	})
	server := &http.Server{Addr: *listen, Handler: bus.Handler(os.Getenv("SIGNAL_API_TOKEN")), ReadHeaderTimeout: 5 * time.Second}
	group.Go(func() error {
		<-groupCtx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	})
	log.Printf("signal daemon listening on %s", *listen)
	group.Go(func() error {
		err := server.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	})
	if err := group.Wait(); err != nil {
		log.Fatal(err)
	}
}
