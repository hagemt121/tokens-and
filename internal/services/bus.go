// Package services connects process-local finding channels with an HTTP daemon endpoint.
package services

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/hagemt121/tokens-and/internal/signal"
)

type Bus struct{ signals chan signal.Finding }

func NewBus(buffer int) *Bus {
	if buffer < 0 {
		buffer = 0
	}
	return &Bus{signals: make(chan signal.Finding, buffer)}
}

func (b *Bus) Signals() <-chan signal.Finding { return b.signals }

func (b *Bus) Publish(ctx context.Context, finding signal.Finding) error {
	select {
	case b.signals <- finding:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Handler receives one JSON Finding per POST /signals and sends it to the bus.
func (b *Bus) Handler(token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/signals" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		authorization := r.Header.Get("Authorization")
		provided := strings.TrimPrefix(authorization, "Bearer ")
		if token == "" || authorization == provided || subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var finding signal.Finding
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&finding); err != nil {
			http.Error(w, "invalid finding JSON", http.StatusBadRequest)
			return
		}
		var extra any
		if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
			http.Error(w, "expected one finding", http.StatusBadRequest)
			return
		}
		if finding.Source == "" || finding.RuleID == "" || !signal.AtLeast(finding.Severity, "LOW") {
			http.Error(w, "source, rule ID, and valid severity required", http.StatusBadRequest)
			return
		}
		if err := b.Publish(r.Context(), finding); err != nil {
			http.Error(w, fmt.Sprint(err), http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	})
}
