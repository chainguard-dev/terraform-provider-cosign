package fulcio

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/sign"
)

type identity struct{ issuer, subject string }

var (
	orgA = identity{issuer: "https://issuer.enforce.dev", subject: "org-a/identity"}
	orgB = identity{issuer: "https://issuer.enforce.dev", subject: "org-b/identity"}
)

// testJWT returns an unsigned JWT carrying id's issuer and subject.
func testJWT(t *testing.T, id identity) string {
	t.Helper()
	claims, err := json.Marshal(map[string]string{"iss": id.issuer, "sub": id.subject})
	if err != nil {
		t.Fatalf("marshaling claims: %v", err)
	}
	return "e30." + base64.RawURLEncoding.EncodeToString(claims) + ".sig"
}

// fakeFulcio issues self-signed certs whose CommonName records the identity
// of the requesting token, and counts fetches per identity.
type fakeFulcio struct {
	t *testing.T

	mu       sync.Mutex
	fetches  map[identity]int
	validity map[identity]time.Duration // default 10m
	gate     map[identity]chan struct{} // fetches for these block until closed
	started  map[identity]chan struct{} // closed when a gated fetch starts
	fail     map[identity]error
}

func newFakeFulcio(t *testing.T) *fakeFulcio {
	return &fakeFulcio{
		t:        t,
		fetches:  map[identity]int{},
		validity: map[identity]time.Duration{},
		gate:     map[identity]chan struct{}{},
		started:  map[identity]chan struct{}{},
		fail:     map[identity]error{},
	}
}

func (f *fakeFulcio) fetchCount(id identity) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fetches[id]
}

func (f *fakeFulcio) GetCertificate(_ context.Context, _ sign.Keypair, opts *sign.CertificateProviderOptions) ([]byte, error) {
	k, err := tokenIdentity(opts.IDToken)
	if err != nil {
		return nil, err
	}
	id := identity{issuer: k.issuer, subject: k.subject}

	f.mu.Lock()
	f.fetches[id]++
	gate, started := f.gate[id], f.started[id]
	validity, ok := f.validity[id]
	if !ok {
		validity = 10 * time.Minute
	}
	failErr := f.fail[id]
	f.mu.Unlock()

	if gate != nil {
		close(started)
		<-gate
	}
	if failErr != nil {
		return nil, failErr
	}
	return identityCertDER(f.t, id, validity), nil
}

// identityCertDER returns a self-signed cert naming id in its CommonName.
func identityCertDER(t *testing.T, id identity, validity time.Duration) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Errorf("generating key: %v", err)
		return nil
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: id.issuer + "|" + id.subject},
		NotBefore:    now.Add(-1 * time.Hour),
		NotAfter:     now.Add(validity),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Errorf("creating certificate: %v", err)
	}
	return der
}

func newKeypair(t *testing.T) sign.Keypair {
	t.Helper()
	kp, err := sign.NewEphemeralKeypair(nil)
	if err != nil {
		t.Fatalf("generating keypair: %v", err)
	}
	return kp
}

// certFor gets a cert for kp as id and fails the test unless it is id's.
func certFor(t *testing.T, c *CachingCertProvider, kp sign.Keypair, id identity) error {
	der, err := c.GetCertificate(context.Background(), kp, &sign.CertificateProviderOptions{IDToken: testJWT(t, id)})
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	if got, want := cert.Subject.CommonName, id.issuer+"|"+id.subject; got != want {
		t.Errorf("requested a cert for %q, got one for %q", want, got)
	}
	return nil
}

func TestCachingCertProviderInterleavedIdentities(t *testing.T) {
	f := newFakeFulcio(t)
	c := NewCachingCertProvider(f)
	kp := newKeypair(t)

	for _, id := range []identity{orgA, orgB, orgA, orgB, orgA} {
		if err := certFor(t, c, kp, id); err != nil {
			t.Fatalf("getting cert for %v: %v", id, err)
		}
	}

	// Each identity fetches once, then reuses its own cached cert.
	for _, id := range []identity{orgA, orgB} {
		if got := f.fetchCount(id); got != 1 {
			t.Errorf("Fulcio fetches for %v = %d, want 1", id, got)
		}
	}
}

func TestCachingCertProviderKeysByPublicKey(t *testing.T) {
	f := newFakeFulcio(t)
	c := NewCachingCertProvider(f)

	if err := certFor(t, c, newKeypair(t), orgA); err != nil {
		t.Fatalf("getting cert with first keypair: %v", err)
	}
	if err := certFor(t, c, newKeypair(t), orgA); err != nil {
		t.Fatalf("getting cert with second keypair: %v", err)
	}
	// A cert binds one public key, so another keypair needs its own.
	if got := f.fetchCount(orgA); got != 2 {
		t.Errorf("Fulcio fetches = %d, want 2", got)
	}
}

// TestCachingCertProviderConcurrentRefreshPerIdentity holds org A's Fulcio
// fetch open while concurrent requests for A wait on it and requests for B
// proceed.
func TestCachingCertProviderConcurrentRefreshPerIdentity(t *testing.T) {
	f := newFakeFulcio(t)
	gate, started := make(chan struct{}), make(chan struct{})
	f.gate[orgA], f.started[orgA] = gate, started
	c := NewCachingCertProvider(f)
	kp := newKeypair(t)

	const n = 8
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for range n {
		wg.Go(func() { errs <- certFor(t, c, kp, orgA) })
	}
	<-started

	// B is not blocked by A's in-flight fetch, concurrently or in sequence.
	bDone := make(chan error, 1)
	go func() {
		var bwg sync.WaitGroup
		berrs := make(chan error, n)
		for range n {
			bwg.Go(func() { berrs <- certFor(t, c, kp, orgB) })
		}
		bwg.Wait()
		close(berrs)
		for err := range berrs {
			if err != nil {
				bDone <- err
				return
			}
		}
		bDone <- certFor(t, c, kp, orgB)
	}()
	select {
	case err := <-bDone:
		if err != nil {
			t.Fatalf("getting cert for B: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("requests for B blocked on A's fetch")
	}

	close(gate)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("getting cert for A: %v", err)
		}
	}

	// Concurrent requests for an identity coalesce onto one fetch.
	for _, id := range []identity{orgA, orgB} {
		if got := f.fetchCount(id); got != 1 {
			t.Errorf("Fulcio fetches for %v = %d, want 1", id, got)
		}
	}
}

func TestCachingCertProviderRetriesFailedFetch(t *testing.T) {
	f := newFakeFulcio(t)
	f.fail[orgA] = errors.New("fulcio unavailable")
	c := NewCachingCertProvider(f)
	kp := newKeypair(t)

	if err := certFor(t, c, kp, orgA); err == nil {
		t.Fatal("expected the Fulcio error")
	}
	if err := certFor(t, c, kp, orgB); err != nil {
		t.Fatalf("getting cert for B: %v", err)
	}

	f.mu.Lock()
	delete(f.fail, orgA)
	f.mu.Unlock()
	if err := certFor(t, c, kp, orgA); err != nil {
		t.Fatalf("getting cert for A after recovery: %v", err)
	}
	if got := f.fetchCount(orgA); got != 2 {
		t.Errorf("Fulcio fetches for A = %d, want 2", got)
	}
}

func TestCachingCertProviderRefreshesNearExpiry(t *testing.T) {
	f := newFakeFulcio(t)
	// Within the 30s refresh buffer, so A's cert is stale as soon as it's cached.
	f.validity[orgA] = 10 * time.Second
	c := NewCachingCertProvider(f)
	kp := newKeypair(t)

	for range 2 {
		if err := certFor(t, c, kp, orgA); err != nil {
			t.Fatalf("getting cert for A: %v", err)
		}
	}
	if got := f.fetchCount(orgA); got != 2 {
		t.Errorf("Fulcio fetches for A = %d, want 2", got)
	}
}

func TestCachingCertProviderPrunesExpiredIdentities(t *testing.T) {
	f := newFakeFulcio(t)
	f.validity[orgA] = 10 * time.Second
	c := NewCachingCertProvider(f)
	kp := newKeypair(t)

	if err := certFor(t, c, kp, orgA); err != nil {
		t.Fatalf("getting cert for A: %v", err)
	}
	if err := certFor(t, c, kp, orgB); err != nil {
		t.Fatalf("getting cert for B: %v", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	var got []string
	for k := range c.certs {
		got = append(got, k.subject)
	}
	if len(got) != 1 || got[0] != orgB.subject {
		t.Errorf("cached subjects = %v, want only %q", got, orgB.subject)
	}
}

func TestCachingCertProviderRequiresIDToken(t *testing.T) {
	c := NewCachingCertProvider(newFakeFulcio(t))
	kp := newKeypair(t)
	for _, opts := range []*sign.CertificateProviderOptions{nil, {}} {
		if _, err := c.GetCertificate(context.Background(), kp, opts); err == nil {
			t.Errorf("GetCertificate(%v): expected an error", opts)
		}
	}
}

func TestTokenIdentity(t *testing.T) {
	got, err := tokenIdentity(testJWT(t, orgA))
	if err != nil {
		t.Fatalf("tokenIdentity: %v", err)
	}
	if got.issuer != orgA.issuer || got.subject != orgA.subject {
		t.Errorf("tokenIdentity = %+v, want %+v", got, orgA)
	}

	for name, token := range map[string]string{
		"not a JWT":   "opaque-token",
		"bad payload": "e30.!!!.sig",
		"no sub":      testJWT(t, identity{issuer: orgA.issuer}),
		"no iss":      testJWT(t, identity{subject: orgA.subject}),
	} {
		if _, err := tokenIdentity(token); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
