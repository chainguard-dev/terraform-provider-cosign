package tlog

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/sigstore/rekor/pkg/generated/client/entries"
)

func TestIsRetryableRekorError(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"conflict", &entries.CreateLogEntryConflict{}, false},
		{"badrequest", &entries.CreateLogEntryBadRequest{}, false},
		{"default-4xx", entries.NewCreateLogEntryDefault(http.StatusForbidden), false},
		{"default-5xx", entries.NewCreateLogEntryDefault(http.StatusBadGateway), false},
		{"http2-stream-error", fmt.Errorf("stream error: stream ID 15; INTERNAL_ERROR; received from peer"), true},
		{"wrapped-conflict", fmt.Errorf("outer: %w", &entries.CreateLogEntryConflict{}), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isRetryableRekorError(tc.err); got != tc.want {
				t.Errorf("isRetryableRekorError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestCreateLogEntryWithRetry_RetriesTransient(t *testing.T) {
	defer shrinkRetryBackoff(t)()

	var attempts int
	transient := errors.New("stream error: stream ID 1; INTERNAL_ERROR; received from peer")

	got, err := createLogEntryWithRetry(t.Context(), func() (*entries.CreateLogEntryCreated, error) {
		attempts++
		if attempts < 3 {
			return nil, transient
		}
		return &entries.CreateLogEntryCreated{}, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil response")
	}
	if attempts != 3 {
		t.Errorf("attempts = %d, want 3", attempts)
	}
}

func TestCreateLogEntryWithRetry_StopsOnConflict(t *testing.T) {
	defer shrinkRetryBackoff(t)()

	var attempts int
	_, err := createLogEntryWithRetry(t.Context(), func() (*entries.CreateLogEntryCreated, error) {
		attempts++
		return nil, &entries.CreateLogEntryConflict{}
	})
	if _, ok := errors.AsType[*entries.CreateLogEntryConflict](err); !ok {
		t.Fatalf("err = %v, want CreateLogEntryConflict", err)
	}
	if attempts != 1 {
		t.Errorf("attempts = %d, want 1 (conflict should not retry)", attempts)
	}
}

func TestCreateLogEntryWithRetry_ExhaustsAttempts(t *testing.T) {
	defer shrinkRetryBackoff(t)()

	var attempts int
	transient := errors.New("stream error: INTERNAL_ERROR")
	_, err := createLogEntryWithRetry(t.Context(), func() (*entries.CreateLogEntryCreated, error) {
		attempts++
		return nil, transient
	})
	if !errors.Is(err, transient) {
		t.Fatalf("err = %v, want %v", err, transient)
	}
	if attempts != createLogEntryMaxAttempts {
		t.Errorf("attempts = %d, want %d", attempts, createLogEntryMaxAttempts)
	}
}

func TestCreateLogEntryWithRetry_AbortsOnContextCancel(t *testing.T) {
	prev := createLogEntryInitialBackoff
	createLogEntryInitialBackoff = time.Hour
	defer func() { createLogEntryInitialBackoff = prev }()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var attempts int
	_, err := createLogEntryWithRetry(ctx, func() (*entries.CreateLogEntryCreated, error) {
		attempts++
		cancel()
		return nil, errors.New("stream error")
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if attempts != 1 {
		t.Errorf("attempts = %d, want 1 (should abort before second attempt)", attempts)
	}
}

func shrinkRetryBackoff(t *testing.T) func() {
	t.Helper()
	prev := createLogEntryInitialBackoff
	createLogEntryInitialBackoff = time.Millisecond
	return func() { createLogEntryInitialBackoff = prev }
}
