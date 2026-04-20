package provider

import (
	"encoding/base64"
	"testing"
	"time"
)

func TestTokenExpiry(t *testing.T) {
	const futureExp int64 = 2000000000 // 2033-05-18

	validJWT := "header." + base64.RawURLEncoding.EncodeToString([]byte(`{"exp":2000000000}`)) + ".sig"
	noExpJWT := "header." + base64.RawURLEncoding.EncodeToString([]byte(`{}`)) + ".sig"
	badJSONJWT := "header." + base64.RawURLEncoding.EncodeToString([]byte(`not-json`)) + ".sig"

	tests := []struct {
		name      string
		token     string
		wantExact time.Time // zero => expect ~time.Now()
	}{
		{
			name:      "valid jwt with exp",
			token:     validJWT,
			wantExact: time.Unix(futureExp, 0).Add(-oidcExpiryBuffer),
		},
		{
			name:  "not three parts",
			token: "invalid",
		},
		{
			name:  "bad base64 payload",
			token: "header.!!!bad-base64!!!.sig",
		},
		{
			name:  "invalid json payload",
			token: badJSONJWT,
		},
		{
			name:  "missing exp claim",
			token: noExpJWT,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			before := time.Now()
			got := tokenExpiry(tc.token)
			after := time.Now()

			if !tc.wantExact.IsZero() {
				if !got.Equal(tc.wantExact) {
					t.Errorf("tokenExpiry = %v, want %v", got, tc.wantExact)
				}
				return
			}

			// Error paths: got should be between before and after.
			if got.Before(before) || got.After(after) {
				t.Errorf("tokenExpiry = %v, want within [%v, %v]", got, before, after)
			}
		})
	}
}
