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
	"strings"
	"sync"
	"testing"
	"time"

	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	prototrustroot "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"google.golang.org/protobuf/encoding/protojson"
)

type staticOIDC string

func (staticOIDC) Enabled(context.Context) bool                      { return true }
func (s staticOIDC) Provide(context.Context, string) (string, error) { return string(s), nil }

// TestSignContentTracesUnderCaller signs through a tracing transport against
// stand-in Fulcio, TSA and Rekor v2 servers, and checks that every request
// went through that transport and recorded its span under the caller's span.
func TestSignContentTracesUnderCaller(t *testing.T) {
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

	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	transport := otelhttp.NewTransport(http.DefaultTransport, otelhttp.WithTracerProvider(tp))

	keypair, err := sign.NewEphemeralKeypair(nil)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	token := enc([]byte(`{"alg":"none"}`)) + "." + enc([]byte(`{"sub":"signer","iss":"https://issuer.example.com"}`)) + ".sig"
	// Constructed directly so the trusted material stays nil: sign.Bundle
	// then skips verifying the stand-in services' responses.
	bs := &BundleSigner{oidc: staticOIDC(token), signingConfig: sc, keypair: keypair, transport: transport}

	ctx, parent := tp.Tracer("test").Start(context.Background(), "sign")
	content := &sign.DSSEData{Data: []byte(`{}`), PayloadType: "application/vnd.in-toto+json"}
	// The first sign gets a Fulcio certificate; the second reuses it.
	for range 2 {
		if _, err := bs.SignContent(ctx, content); err != nil {
			t.Fatalf("SignContent: %v", err)
		}
	}
	parent.End()

	if want := map[string]int{"fulcio": 1, "tsa": 2, "rekor": 2}; !maps.Equal(hits, want) {
		t.Errorf("requests = %v, want %v", hits, want)
	}
	hosts := map[string]string{
		strings.TrimPrefix(fulcioSrv.URL, "http://"): "fulcio",
		strings.TrimPrefix(tsaSrv.URL, "http://"):    "tsa",
		strings.TrimPrefix(rekorSrv.URL, "http://"):  "rekor",
	}
	spans := map[string]int{}
	for _, s := range rec.Ended() {
		if s.Name() == "sign" {
			continue
		}
		var host string
		for _, kv := range s.Attributes() {
			if kv.Key == "server.address" || kv.Key == "net.peer.name" {
				host = kv.Value.AsString()
			}
			if kv.Key == "server.port" {
				host += ":" + kv.Value.String()
			}
		}
		name, ok := hosts[host]
		if !ok {
			t.Errorf("span %q for unexpected host %q", s.Name(), host)
			continue
		}
		spans[name]++
		if s.Parent().SpanID() != parent.SpanContext().SpanID() || s.SpanContext().TraceID() != parent.SpanContext().TraceID() {
			t.Errorf("%s span %q: parent %s in trace %s, want parent %s in trace %s", name, s.Name(),
				s.Parent().SpanID(), s.SpanContext().TraceID(), parent.SpanContext().SpanID(), parent.SpanContext().TraceID())
		}
	}
	if !maps.Equal(spans, hits) {
		t.Errorf("client spans = %v, want one per request %v", spans, hits)
	}
}
