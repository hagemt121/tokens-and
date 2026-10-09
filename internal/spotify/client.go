package spotify

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/oauth2"
)

// Client controls playback with a user OAuth access token carrying
// user-modify-playback-state. The caller supplies and refreshes that token.
type Client struct {
	HTTP   *http.Client
	Token  string
	Source oauth2.TokenSource
}

func (c Client) Pause(ctx context.Context) error {
	accessToken := c.Token
	if c.Source != nil {
		token, err := c.Source.Token()
		if err != nil {
			return fmt.Errorf("spotify token: %w", err)
		}
		accessToken = token.AccessToken
	}
	if accessToken == "" {
		return fmt.Errorf("Spotify access token is empty")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, "https://api.spotify.com/v1/me/player/pause", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("spotify pause: %s: %s", resp.Status, body)
	}
	return nil
}
