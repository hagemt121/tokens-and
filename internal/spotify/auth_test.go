package spotify

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestLoginUsesPKCEAndSavesToken(t *testing.T) {
	var challenge string
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" || r.FormValue("grant_type") != "authorization_code" || r.FormValue("client_id") != "client-id" || r.FormValue("code") != "auth-code" {
			t.Errorf("unexpected token request: %s %s", r.URL.Path, r.Form.Encode())
		}
		if oauth2.S256ChallengeFromVerifier(r.FormValue("code_verifier")) != challenge {
			t.Error("PKCE verifier did not match challenge")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"access","token_type":"Bearer","expires_in":3600,"refresh_token":"refresh"}`)
	}))
	defer tokenServer.Close()
	path := filepath.Join(t.TempDir(), "spotify.json")
	config := AuthConfig{ClientID: "client-id", RedirectURI: "http://127.0.0.1:0/callback", TokenFile: path, Endpoint: oauth2.Endpoint{AuthURL: tokenServer.URL + "/authorize", TokenURL: tokenServer.URL + "/token"}}
	reader, writer := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- config.Login(context.Background(), writer); writer.Close() }()
	scanner := bufio.NewScanner(reader)
	if !scanner.Scan() || !scanner.Scan() {
		t.Fatalf("missing auth URL: %v", scanner.Err())
	}
	authURL, err := url.Parse(scanner.Text())
	if err != nil {
		t.Fatal(err)
	}
	challenge = authURL.Query().Get("code_challenge")
	redirect := authURL.Query().Get("redirect_uri")
	if challenge == "" || !strings.HasPrefix(redirect, "http://127.0.0.1:") {
		t.Fatalf("invalid authorization URL: %s", authURL)
	}
	callback, err := url.Parse(redirect)
	if err != nil {
		t.Fatal(err)
	}
	query := callback.Query()
	query.Set("state", authURL.Query().Get("state"))
	query.Set("code", "auth-code")
	callback.RawQuery = query.Encode()
	resp, err := http.Get(callback.String())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("callback HTTP %d", resp.StatusCode)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	token, err := loadToken(path)
	if err != nil || token.RefreshToken != "refresh" {
		t.Fatalf("saved token: %+v, %v", token, err)
	}
	info, err := os.Stat(path)
	if err != nil { t.Fatal(err) }
	if info.Mode().Perm() != 0600 {
		t.Fatalf("token file permissions: %v", info.Mode().Perm())
	}
}

func TestTokenSourceRefreshPersistsRotatedToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("grant_type") != "refresh_token" || r.FormValue("refresh_token") != "old-refresh" || r.FormValue("client_id") != "client-id" {
			t.Errorf("unexpected refresh request: %s", r.Form.Encode())
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"new-access","token_type":"Bearer","expires_in":3600,"refresh_token":"new-refresh"}`)
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "spotify.json")
	initial := &oauth2.Token{AccessToken: "expired", RefreshToken: "old-refresh", Expiry: time.Now().Add(-time.Hour)}
	if err := saveToken(path, initial); err != nil {
		t.Fatal(err)
	}
	a := AuthConfig{ClientID: "client-id", TokenFile: path, Endpoint: oauth2.Endpoint{TokenURL: server.URL}}
	config := a.oauthConfig()
	source := &savingTokenSource{source: config.TokenSource(context.Background(), initial), file: path, last: initial}
	token, err := source.Token()
	if err != nil {
		t.Fatal(err)
	}
	if token.AccessToken != "new-access" {
		t.Fatalf("got token %q", token.AccessToken)
	}
	saved, err := loadToken(path)
	if err != nil || saved.RefreshToken != "new-refresh" {
		t.Fatalf("saved token: %+v, %v", saved, err)
	}
}
