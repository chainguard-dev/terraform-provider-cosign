package secant

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	prototrustroot "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"google.golang.org/protobuf/encoding/protojson"
)

type staticOIDC string

func (staticOIDC) Enabled(context.Context) bool                      { return true }
func (s staticOIDC) Provide(context.Context, string) (string, error) { return string(s), nil }

// TestSignContentUsesTransportAndContext signs with a BundleSigner made with
// WithTransport against stand-in Fulcio, TSA and Rekor v2 servers, and checks
// that every request went through that transport and carried the caller's
// context.
func TestSignContentUsesTransportAndContext(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	hits := map[string]int{}
	hit := func(name string) {
		mu.Lock()
		defer mu.Unlock()
		hits[name]++
	}

	fulcioSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit("fulcio")
		leaf, _, err := vs.GenerateLeafCert("signer@example.com", "https://issuer.example.com")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}))
		_ = json.NewEncoder(w).Encode(map[string]any{
			"signedCertificateEmbeddedSct": map[string]any{"chain": map[string]any{"certificates": []string{certPEM}}},
		})
	}))
	defer fulcioSrv.Close()

	tsaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit("tsa")
		body, _ := io.ReadAll(r.Body)
		resp, err := vs.TimestampResponse(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(resp)
	}))
	defer tsaSrv.Close()

	rekorSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit("rekor")
		if r.URL.Path != "/api/v2/log/entries" {
			http.NotFound(w, r)
			return
		}
		b, _ := protojson.Marshal(&protorekor.TransparencyLogEntry{LogIndex: 1})
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(b)
	}))
	defer rekorSrv.Close()

	start := time.Now().Add(-time.Hour)
	svc := func(url string, v uint32) []root.Service {
		return []root.Service{{URL: url, MajorAPIVersion: v, ValidityPeriodStart: start}}
	}
	anyOne := root.ServiceConfiguration{Selector: prototrustroot.ServiceSelector_ANY}
	sc, err := root.NewSigningConfig(root.SigningConfigMediaType02,
		svc(fulcioSrv.URL, 1), nil,
		svc(rekorSrv.URL, 2), anyOne,
		svc(tsaSrv.URL, 1), anyOne)
	if err != nil {
		t.Fatal(err)
	}

	transport := &recordingTransport{}
	enc := base64.RawURLEncoding.EncodeToString
	token := enc([]byte(`{"alg":"none"}`)) + "." + enc([]byte(`{"sub":"signer","iss":"https://issuer.example.com"}`)) + ".sig"
	bs, err := NewBundleSigner(staticOIDC(token), WithSigningConfig(sc), WithTrustedMaterial(vs), WithTransport(transport))
	if err != nil {
		t.Fatal(err)
	}
	// With no trusted material, sign.Bundle skips verifying the stand-in
	// services' responses.
	bs.trustedMaterial = nil

	ctx := context.WithValue(context.Background(), ctxKey{}, "caller")
	content := &sign.DSSEData{Data: []byte(`{}`), PayloadType: "application/vnd.in-toto+json"}
	// The first sign gets a Fulcio certificate; the second reuses it.
	for range 2 {
		if _, err := bs.SignContent(ctx, content); err != nil {
			t.Fatalf("SignContent: %v", err)
		}
	}

	if want := map[string]int{"fulcio": 1, "tsa": 2, "rekor": 2}; !maps.Equal(hits, want) {
		t.Errorf("requests = %v, want %v", hits, want)
	}
	hosts := map[string]string{
		strings.TrimPrefix(fulcioSrv.URL, "http://"): "fulcio",
		strings.TrimPrefix(tsaSrv.URL, "http://"):    "tsa",
		strings.TrimPrefix(rekorSrv.URL, "http://"):  "rekor",
	}
	seen := map[string]int{}
	for _, r := range transport.recorded() {
		name, ok := hosts[r.host]
		if !ok {
			t.Errorf("request to unexpected host %q", r.host)
			continue
		}
		seen[name]++
		if r.value != "caller" {
			t.Errorf("%s request carried context value %v, want %q", name, r.value, "caller")
		}
	}
	if !maps.Equal(seen, hits) {
		t.Errorf("requests through the transport = %v, want all of them %v", seen, hits)
	}
}

type ctxKey struct{}

type recordedRequest struct {
	host  string
	value any
}

// recordingTransport records the host of each request and the ctxKey value
// on its context, then sends it with http.DefaultTransport.
type recordingTransport struct {
	mu   sync.Mutex
	reqs []recordedRequest
}

func (rt *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.mu.Lock()
	rt.reqs = append(rt.reqs, recordedRequest{host: req.URL.Host, value: req.Context().Value(ctxKey{})})
	rt.mu.Unlock()
	return http.DefaultTransport.RoundTrip(req)
}

func (rt *recordingTransport) recorded() []recordedRequest {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return slices.Clone(rt.reqs)
}
