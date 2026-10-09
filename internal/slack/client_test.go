package slack

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hagemt121/tokens-and/internal/signal"
)

func TestSendToAdminDM(t *testing.T) {
	var posted struct {
		Channel string `json:"channel"`
		Text    string `json:"text"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("missing bot token")
		}
		switch r.URL.Path {
		case "/conversations.open":
			var request struct {
				Users string `json:"users"`
			}
			_ = json.NewDecoder(r.Body).Decode(&request)
			if request.Users != "U123" {
				t.Errorf("got users %q", request.Users)
			}
			_, _ = w.Write([]byte(`{"ok":true,"channel":{"id":"D456"}}`))
		case "/chat.postMessage":
			_ = json.NewDecoder(r.Body).Decode(&posted)
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	client := Client{Token: "test-token", AdminUserID: "U123", BaseURL: server.URL}
	if err := client.Send(context.Background(), signal.Finding{Source: "semgrep", RuleID: "R1", Severity: "HIGH", Path: "a.go", Line: "3", Message: "bad <@U999>"}); err != nil {
		t.Fatal(err)
	}
	if posted.Channel != "D456" || !strings.Contains(posted.Text, "&lt;@U999&gt;") {
		t.Fatalf("unexpected post: %+v", posted)
	}
}

func TestLookupUserChecksWorkspace(t *testing.T) {
	lookups := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth.test":
			_, _ = w.Write([]byte(`{"ok":true,"team_id":"T123"}`))
		case "/users.lookupByEmail":
			lookups++
			if r.URL.Query().Get("email") != "admin+test@example.com" {
				t.Errorf("wrong email: %s", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`{"ok":true,"user":{"id":"U123"}}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	client := Client{Token: "test-token", BaseURL: server.URL}
	if _, err := client.LookupUser(context.Background(), "T999", "admin+test@example.com"); err == nil {
		t.Fatal("expected workspace mismatch")
	}
	id, err := client.LookupUser(context.Background(), "T123", "admin+test@example.com")
	if err != nil || id != "U123" || lookups != 1 {
		t.Fatalf("got %q, %v, lookups=%d", id, err, lookups)
	}
}

func TestSendToChannelID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat.postMessage" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		var posted struct {
			Channel string `json:"channel"`
		}
		_ = json.NewDecoder(r.Body).Decode(&posted)
		if posted.Channel != "C123" {
			t.Errorf("got channel %q", posted.Channel)
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()
	client := Client{Token: "test-token", AdminUserID: "U123", ChannelID: "C123", BaseURL: server.URL}
	if err := client.Send(context.Background(), signal.Finding{RuleID: "R1"}); err != nil {
		t.Fatal(err)
	}
}

func TestSlackAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":false,"error":"missing_scope"}`))
	}))
	defer server.Close()
	client := Client{Token: "test-token", BaseURL: server.URL}
	if _, err := client.LookupUser(context.Background(), "T123", "admin@example.com"); err == nil || !strings.Contains(err.Error(), "missing_scope") {
		t.Fatalf("got %v", err)
	}
}
