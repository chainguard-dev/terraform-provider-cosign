package secant

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chainguard-dev/terraform-provider-cosign/pkg/private/secant/types"
	"github.com/go-openapi/runtime"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v3/pkg/oci"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sigstore/cosign/v3/pkg/oci/static"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore/pkg/signature"
	sigopts "github.com/sigstore/sigstore/pkg/signature/options"
	sigPayload "github.com/sigstore/sigstore/pkg/signature/payload"
)

func TestSignDigest(t *testing.T) {
	ctx := context.Background()

	// An in-memory registry that can be flipped to read-only, to prove that
	// re-signing writes nothing.
	reg := registry.New()
	var readonly atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if readonly.Load() && r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "registry is read-only", http.StatusMethodNotAllowed)
			return
		}
		reg.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	repo, err := name.NewRepository(strings.TrimPrefix(srv.URL, "http://") + "/test-repo")
	if err != nil {
		t.Fatal(err)
	}

	// This digest is never pushed: fetching it would fail, so SignDigest
	// succeeding proves it never touches the subject manifest.
	digest := repo.Digest("sha256:" + strings.Repeat("a", 64))

	signer := newTestCosigner(t)
	fakeEntries := &fakeRekorEntries{}
	rekorClient := &client.Rekor{Entries: fakeEntries}

	if err := SignDigest(ctx, SkipSame, nil, signer, rekorClient, digest, nil); err != nil {
		t.Fatalf("SignDigest() = %v", err)
	}

	payloads := signaturePayloads(t, digest)
	if len(payloads) != 1 {
		t.Fatalf("got %d signatures, want 1", len(payloads))
	}
	// The stored payload should be a simple signing payload for our digest.
	var sci sigPayload.SimpleContainerImage
	if err := json.Unmarshal(payloads[0], &sci); err != nil {
		t.Fatalf("unmarshaling payload: %v", err)
	}
	if got := sci.Critical.Image.DockerManifestDigest; got != digest.DigestStr() {
		t.Errorf("payload signs digest %q, want %q", got, digest.DigestStr())
	}
	if fakeEntries.uploadCount != 1 {
		t.Errorf("got %d rekor uploads, want 1", fakeEntries.uploadCount)
	}

	// Signing the same digest again with SKIPSAME should match the existing
	// signature and skip both the rekor upload and the signature write, so it
	// succeeds even against a read-only registry.
	readonly.Store(true)
	if err := SignDigest(ctx, SkipSame, nil, signer, rekorClient, digest, nil); err != nil {
		t.Fatalf("SignDigest() again = %v", err)
	}
	if fakeEntries.uploadCount != 1 {
		t.Errorf("got %d rekor uploads after re-sign, want 1", fakeEntries.uploadCount)
	}
	if got := len(signaturePayloads(t, digest)); got != 1 {
		t.Errorf("got %d signatures after re-sign, want 1", got)
	}
}

func TestSign(t *testing.T) {
	ctx := context.Background()
	repo := setupTestRepo(t)

	idx, err := random.Index(1024, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.WriteIndex(repo.Tag("latest"), idx); err != nil {
		t.Fatal(err)
	}

	im, err := idx.IndexManifest()
	if err != nil {
		t.Fatal(err)
	}
	h, err := idx.Digest()
	if err != nil {
		t.Fatal(err)
	}
	digests := []name.Digest{repo.Digest(h.String())}
	for _, m := range im.Manifests {
		digests = append(digests, repo.Digest(m.Digest.String()))
	}

	signer := newTestCosigner(t)
	fakeEntries := &fakeRekorEntries{}
	rekorClient := &client.Rekor{Entries: fakeEntries}

	if err := Sign(ctx, SkipSame, nil, signer, rekorClient, digests[:1], nil); err != nil {
		t.Fatalf("Sign() = %v", err)
	}

	// The walk signs the index and each of its children.
	for _, d := range digests {
		if got := len(signaturePayloads(t, d)); got != 1 {
			t.Errorf("got %d signatures for %s, want 1", got, d)
		}
	}
	if fakeEntries.uploadCount != len(digests) {
		t.Errorf("got %d rekor uploads, want %d", fakeEntries.uploadCount, len(digests))
	}
}

// signaturePayloads fetches the .sig tag for digest and returns the payload of
// each signature layer.
func signaturePayloads(t *testing.T, digest name.Digest) [][]byte {
	t.Helper()

	tag, err := ociremote.SignatureTag(digest)
	if err != nil {
		t.Fatal(err)
	}
	sigs, err := ociremote.Signatures(tag)
	if err != nil {
		t.Fatalf("fetching %s: %v", tag, err)
	}
	ss, err := sigs.Get()
	if err != nil {
		t.Fatal(err)
	}
	payloads := make([][]byte, 0, len(ss))
	for _, s := range ss {
		p, err := s.Payload()
		if err != nil {
			t.Fatal(err)
		}
		payloads = append(payloads, p)
	}
	return payloads
}

// testCosigner is a keyless signer using a self-signed certificate, just
// enough to drive signing in tests.
type testCosigner struct {
	signature.SignerVerifier
	cert []byte
}

func newTestCosigner(t *testing.T) *testCosigner {
	t.Helper()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := signature.LoadECDSASignerVerifier(privKey, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    now,
		NotAfter:     now.Add(10 * time.Minute),
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatal(err)
	}
	return &testCosigner{
		SignerVerifier: inner,
		cert:           pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}),
	}
}

// Cosign implements types.Cosigner.
func (s *testCosigner) Cosign(ctx context.Context, payload io.Reader) (oci.Signature, error) {
	payloadBytes, err := io.ReadAll(payload)
	if err != nil {
		return nil, err
	}
	signed, err := s.SignMessage(bytes.NewReader(payloadBytes), sigopts.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	return static.NewSignature(payloadBytes, base64.StdEncoding.EncodeToString(signed), static.WithCertChain(s.cert, s.cert))
}

var _ types.CosignerVerifier = (*testCosigner)(nil)

// fakeRekorEntries implements entries.ClientService, recording uploads.
type fakeRekorEntries struct {
	uploadCount int
}

func (f *fakeRekorEntries) CreateLogEntry(params *entries.CreateLogEntryParams, opts ...entries.ClientOption) (*entries.CreateLogEntryCreated, error) {
	f.uploadCount++
	entryBytes, err := json.Marshal(params.ProposedEntry)
	if err != nil {
		return nil, err
	}
	var li int64 = 1
	it := time.Now().Unix()
	lid := "logId"
	return &entries.CreateLogEntryCreated{
		Payload: map[string]models.LogEntryAnon{
			"result": {
				Body:           base64.StdEncoding.EncodeToString(entryBytes),
				Verification:   &models.LogEntryAnonVerification{},
				IntegratedTime: &it,
				LogIndex:       &li,
				LogID:          &lid,
			},
		},
	}, nil
}

func (f *fakeRekorEntries) GetLogEntryByIndex(params *entries.GetLogEntryByIndexParams, opts ...entries.ClientOption) (*entries.GetLogEntryByIndexOK, error) {
	return nil, errors.New("unimplemented")
}

func (f *fakeRekorEntries) GetLogEntryByUUID(params *entries.GetLogEntryByUUIDParams, opts ...entries.ClientOption) (*entries.GetLogEntryByUUIDOK, error) {
	return nil, errors.New("unimplemented")
}

func (f *fakeRekorEntries) SearchLogQuery(params *entries.SearchLogQueryParams, opts ...entries.ClientOption) (*entries.SearchLogQueryOK, error) {
	return nil, errors.New("unimplemented")
}

func (f *fakeRekorEntries) SetTransport(transport runtime.ClientTransport) {}

var _ entries.ClientService = (*fakeRekorEntries)(nil)
