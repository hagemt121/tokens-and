package spotify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

type rewriteTransport struct{ target *httptest.Server }

func (r rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = "http"
	req.URL.Host = r.target.Listener.Addr().String()
	return http.DefaultTransport.RoundTrip(req)
}

func TestPause(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/v1/me/player/pause" || r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("unexpected request: %s %s %s", r.Method, r.URL.Path, r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	c := Client{Token: "test-token", HTTP: &http.Client{Transport: rewriteTransport{target: srv}}}
	if err := c.Pause(context.Background()); err != nil {
		t.Fatal(err)
	}
}
