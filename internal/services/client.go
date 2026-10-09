package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/hagemt121/tokens-and/internal/signal"
)

// Client publishes findings to a daemon's /signals endpoint.
type Client struct {
	URL   string
	Token string
	HTTP  *http.Client
}

func (c Client) Publish(ctx context.Context, finding signal.Finding) error {
	if c.Token == "" {
		return fmt.Errorf("SIGNAL_API_TOKEN is required")
	}
	data, err := json.Marshal(finding)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.URL, "/")+"/signals", bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("signal daemon: HTTP %d", resp.StatusCode)
	}
	return nil
}
