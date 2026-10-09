// Package slack sends security findings to the tool administrator.
package slack

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hagemt121/tokens-and/internal/signal"
)

type Client struct {
	Token       string
	AdminUserID string
	ChannelID   string // When set, sends to this channel instead of opening an admin DM.
	HTTP        *http.Client
	BaseURL     string // Defaults to Slack's Web API; useful for tests.
}

func (c Client) Send(ctx context.Context, finding signal.Finding) error {
	if c.Token == "" || (c.AdminUserID == "" && c.ChannelID == "") {
		return fmt.Errorf("SLACK_BOT_TOKEN and a Slack destination are required")
	}
	channel := c.ChannelID
	if channel == "" {
		var opened struct {
			Channel struct {
				ID string `json:"id"`
			} `json:"channel"`
		}
		if err := c.call(ctx, "conversations.open", map[string]string{"users": c.AdminUserID}, &opened); err != nil {
			return err
		}
		channel = opened.Channel.ID
		if channel == "" {
			return fmt.Errorf("slack conversations.open returned no channel ID")
		}
	}
	message := fmt.Sprintf("Security finding: %s %s (%s)\n%s:%s\n%s", finding.Severity, finding.RuleID, finding.Source, finding.Path, finding.Line, finding.Message)
	message = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(message)
	if len(message) > 3500 {
		message = message[:3500]
	}
	return c.call(ctx, "chat.postMessage", map[string]string{"channel": channel, "text": message}, nil)
}

// LookupUser verifies that the token belongs to workspaceID, then resolves email.
func (c Client) LookupUser(ctx context.Context, workspaceID, email string) (string, error) {
	if c.Token == "" {
		return "", fmt.Errorf("SLACK_BOT_TOKEN is required")
	}
	if workspaceID == "" || email == "" {
		return "", fmt.Errorf("workspace ID and email are required")
	}
	var auth struct {
		TeamID string `json:"team_id"`
	}
	if err := c.call(ctx, "auth.test", map[string]string{}, &auth); err != nil {
		return "", err
	}
	if auth.TeamID != workspaceID {
		return "", fmt.Errorf("token belongs to workspace %q, not %q", auth.TeamID, workspaceID)
	}
	var found struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	if err := c.get(ctx, "users.lookupByEmail?email="+url.QueryEscape(email), &found); err != nil {
		return "", err
	}
	if found.User.ID == "" {
		return "", fmt.Errorf("Slack returned no user ID for %q", email)
	}
	return found.User.ID, nil
}

func (c Client) call(ctx context.Context, method string, payload any, result any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return c.request(ctx, http.MethodPost, method, bytes.NewReader(data), result)
}

func (c Client) get(ctx context.Context, method string, result any) error {
	return c.request(ctx, http.MethodGet, method, nil, result)
}

func (c Client) request(ctx context.Context, verb, method string, body io.Reader, result any) error {
	base := c.BaseURL
	if base == "" {
		base = "https://slack.com/api"
	}
	req, err := http.NewRequestWithContext(ctx, verb, strings.TrimRight(base, "/")+"/"+method, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	if verb == http.MethodPost {
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	}
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("slack %s: %w", method, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack %s: HTTP %d", method, resp.StatusCode)
	}
	var envelope struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(responseBody, &envelope); err != nil {
		return fmt.Errorf("slack %s: %w", method, err)
	}
	if !envelope.OK {
		return fmt.Errorf("slack %s: %s", method, envelope.Error)
	}
	if result != nil {
		if err := json.Unmarshal(responseBody, result); err != nil {
			return err
		}
	}
	return nil
}
