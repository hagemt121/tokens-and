package spotify

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

const defaultRedirectURI = "http://127.0.0.1:8888/callback"

type AuthConfig struct {
	ClientID    string
	RedirectURI string
	TokenFile   string
	Endpoint    oauth2.Endpoint // Defaults to Spotify; may be replaced in tests.
}

func AuthConfigFromEnv() (AuthConfig, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return AuthConfig{}, err
	}
	file := os.Getenv("SPOTIFY_TOKEN_FILE")
	if file == "" {
		file = filepath.Join(configDir, "tokens-and", "spotify.json")
	}
	redirect := os.Getenv("SPOTIFY_REDIRECT_URI")
	if redirect == "" {
		redirect = defaultRedirectURI
	}
	return AuthConfig{ClientID: os.Getenv("SPOTIFY_CLIENT_ID"), RedirectURI: redirect, TokenFile: file}, nil
}

func (a AuthConfig) oauthConfig() oauth2.Config {
	endpoint := a.Endpoint
	if endpoint.AuthURL == "" {
		endpoint.AuthURL = "https://accounts.spotify.com/authorize"
	}
	if endpoint.TokenURL == "" {
		endpoint.TokenURL = "https://accounts.spotify.com/api/token"
	}
	endpoint.AuthStyle = oauth2.AuthStyleInParams // PKCE refresh requires client_id in the form body.
	return oauth2.Config{ClientID: a.ClientID, RedirectURL: a.RedirectURI, Scopes: []string{"user-modify-playback-state"}, Endpoint: endpoint}
}

// Login completes a local authorization-code-with-PKCE flow and saves the token.
// The caller opens the printed URL in a browser.
func (a AuthConfig) Login(ctx context.Context, output io.Writer) error {
	if a.ClientID == "" {
		return fmt.Errorf("SPOTIFY_CLIENT_ID is required")
	}
	u, err := url.Parse(a.RedirectURI)
	if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.Path == "" {
		return fmt.Errorf("SPOTIFY_REDIRECT_URI must be http://127.0.0.1:PORT/path")
	}
	listener, err := net.Listen("tcp", u.Host)
	if err != nil {
		return err
	}
	defer listener.Close()
	u.Host = listener.Addr().String()
	a.RedirectURI = u.String()
	config := a.oauthConfig()
	verifier := oauth2.GenerateVerifier()
	stateBytes := make([]byte, 32)
	if _, err := rand.Read(stateBytes); err != nil {
		return err
	}
	state := base64.RawURLEncoding.EncodeToString(stateBytes)
	result := make(chan error, 1)
	mux := http.NewServeMux()
	mux.HandleFunc(u.Path, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Query().Get("state") != state {
			http.Error(w, "invalid state", http.StatusBadRequest)
			return
		}
		if problem := r.URL.Query().Get("error"); problem != "" {
			http.Error(w, problem, http.StatusBadRequest)
			select {
			case result <- fmt.Errorf("spotify authorization: %s", problem):
			default:
			}
			return
		}
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "missing code", http.StatusBadRequest)
			return
		}
		token, err := config.Exchange(ctx, code, oauth2.VerifierOption(verifier))
		if err == nil {
			err = saveToken(a.TokenFile, token)
		}
		if err != nil {
			http.Error(w, "authorization failed; see terminal", http.StatusBadRequest)
		} else {
			_, _ = io.WriteString(w, "Spotify connected. You can close this tab.")
		}
		select {
		case result <- err:
		default:
		}
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = server.Serve(listener) }()
	if _, err := fmt.Fprintf(output, "Open this URL to authorize Spotify:\n%s\n", config.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))); err != nil {
		return err
	}
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// NewClientFromEnv uses a stored refreshable token, or a legacy static access token.
func NewClientFromEnv(ctx context.Context) (Client, error) {
	if token := os.Getenv("SPOTIFY_ACCESS_TOKEN"); token != "" {
		return Client{Token: token}, nil
	}
	a, err := AuthConfigFromEnv()
	if err != nil {
		return Client{}, err
	}
	if a.ClientID == "" {
		return Client{}, fmt.Errorf("SPOTIFY_CLIENT_ID is required; run spotify-login first")
	}
	initial, err := loadToken(a.TokenFile)
	if err != nil {
		return Client{}, fmt.Errorf("load Spotify token: %w; run spotify-login", err)
	}
	if initial.RefreshToken == "" {
		return Client{}, fmt.Errorf("Spotify token has no refresh token; run spotify-login")
	}
	config := a.oauthConfig()
	return Client{Source: &savingTokenSource{source: config.TokenSource(ctx, initial), file: a.TokenFile, last: initial}}, nil
}

type savingTokenSource struct {
	mu     sync.Mutex
	source oauth2.TokenSource
	file   string
	last   *oauth2.Token
}

func (s *savingTokenSource) Token() (*oauth2.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	token, err := s.source.Token()
	if err != nil {
		return nil, err
	}
	if token.AccessToken != s.last.AccessToken || token.RefreshToken != s.last.RefreshToken || !token.Expiry.Equal(s.last.Expiry) {
		if err := saveToken(s.file, token); err != nil {
			return nil, err
		}
		s.last = token
	}
	return token, nil
}

func loadToken(path string) (*oauth2.Token, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var token oauth2.Token
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, err
	}
	return &token, nil
}

func saveToken(path string, token *oauth2.Token) error {
	if path == "" {
		return fmt.Errorf("Spotify token file path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.Marshal(token)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".spotify-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return err
	}
	return nil
}

var _ oauth2.TokenSource = (*savingTokenSource)(nil)
