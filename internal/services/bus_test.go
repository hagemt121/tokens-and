package services

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hagemt121/tokens-and/internal/signal"
)

func TestHTTPPublishesToSharedChannel(t *testing.T) {
	bus := NewBus(1)
	server := httptest.NewServer(bus.Handler("secret"))
	defer server.Close()
	client := Client{URL: server.URL, Token: "secret"}
	want := signal.Finding{Source: "gosec", RuleID: "G101", Severity: "HIGH"}
	if err := client.Publish(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-bus.Signals():
		if got != want {
			t.Fatalf("got %+v; want %+v", got, want)
		}
	case <-time.After(time.Second):
		t.Fatal("finding did not reach channel")
	}
}

func TestHTTPRejectsUnauthenticatedAndInvalidFindings(t *testing.T) {
	bus := NewBus(1)
	server := httptest.NewServer(bus.Handler("secret"))
	defer server.Close()
	for _, tc := range []struct {
		token, body string
		status      int
	}{
		{"wrong", `{"source":"gosec","rule_id":"G101","severity":"HIGH"}`, http.StatusUnauthorized},
		{"secret", `{"source":"gosec","rule_id":"G101","severity":"UNKNOWN"}`, http.StatusBadRequest},
	} {
		req, err := http.NewRequest(http.MethodPost, server.URL+"/signals", bytes.NewBufferString(tc.body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+tc.token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != tc.status {
			t.Fatalf("got HTTP %d, want %d", resp.StatusCode, tc.status)
		}
	}
}
