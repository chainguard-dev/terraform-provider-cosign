package fulcio

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
)

var _ sign.CertificateProvider = (*CachingCertProvider)(nil)

// NewCertProvider returns a sigstore-go Fulcio client for the Fulcio instance
// selected from sc, configured as cosign configures it for bundle signing.
func NewCertProvider(sc *root.SigningConfig) (sign.CertificateProvider, error) {
	if len(sc.FulcioCertificateAuthorityURLs()) == 0 {
		return nil, errors.New("no fulcio URLs provided in signing config")
	}
	svc, err := root.SelectService(sc.FulcioCertificateAuthorityURLs(), sign.FulcioAPIVersions, time.Now())
	if err != nil {
		return nil, fmt.Errorf("selecting fulcio service: %w", err)
	}
	return sign.NewFulcio(&sign.FulcioOptions{
		BaseURL: svc.URL,
		Timeout: 30 * time.Second,
		Retries: 1,
	}), nil
}

// CachingCertProvider is a sign.CertificateProvider that caches the
// certificates of an inner provider (normally Fulcio) until they near expiry.
//
// Certificates are cached per identity (the issuer and subject of the ID
// token in the request) and per public key, so one CachingCertProvider is safe
// to use for callers that sign as many identities, and to share across
// keypairs. Concurrent requests for one identity and key coalesce onto a
// single fetch, without blocking requests for others.
//
// The identity is read from the token without verifying it, and a cache hit
// returns a certificate without Fulcio seeing the token. CachingCertProvider
// therefore trusts its caller to pass tokens from a trusted, in-process OIDC
// provider, as BundleSigner does; don't pass it tokens from untrusted callers.
type CachingCertProvider struct {
	inner sign.CertificateProvider

	mu    sync.Mutex // guards certs and every entry in it
	certs map[certKey]*certEntry
}

// certKey identifies a cached certificate: the issuer and subject of the ID
// token it was requested with, and the public key it binds.
type certKey struct {
	issuer, subject, publicKey string
}

type certEntry struct {
	der      []byte    // Cached DER-encoded certificate
	notAfter time.Time // Zero until the first fetch succeeds

	// refreshing is non-nil while one caller fetches a new cert for this
	// key, and is closed when that fetch finishes.
	refreshing chan struct{}
}

// NewCachingCertProvider returns a CachingCertProvider over inner.
func NewCachingCertProvider(inner sign.CertificateProvider) *CachingCertProvider {
	return &CachingCertProvider{inner: inner, certs: map[certKey]*certEntry{}}
}

// needsRefresh reports whether the cached cert is missing or nearing expiry
// (within 30 seconds, matching SignerVerifier).
func (e *certEntry) needsRefresh() bool {
	return e.der == nil || time.Now().Add(30*time.Second).After(e.notAfter)
}

// GetCertificate returns a certificate for keypair, issued to the identity of
// opts.IDToken, from the cache when it has one that isn't nearing expiry.
func (c *CachingCertProvider) GetCertificate(ctx context.Context, keypair sign.Keypair, opts *sign.CertificateProviderOptions) ([]byte, error) {
	if opts == nil || opts.IDToken == "" {
		return nil, errors.New("fetching certificate requires IDToken to be set")
	}
	key, err := tokenIdentity(opts.IDToken)
	if err != nil {
		return nil, err
	}
	if key.publicKey, err = keypair.GetPublicKeyPem(); err != nil {
		return nil, fmt.Errorf("getting public key: %w", err)
	}

	// The first caller to see a stale cert fetches a new one while the
	// others wait on its refreshing channel. c.mu is never held across the
	// fetch, so one identity's refresh doesn't block requests for others.
	c.mu.Lock()
	for {
		// Look the entry up on every pass: a failed refresh leaves an empty
		// entry that another caller may prune while this one waits.
		e := c.entryLocked(key)
		if !e.needsRefresh() {
			der := e.der
			c.mu.Unlock()
			return der, nil
		}

		if e.refreshing == nil {
			done := make(chan struct{})
			e.refreshing = done
			c.mu.Unlock()

			der, notAfter, err := c.fetch(ctx, keypair, opts)

			c.mu.Lock()
			if err == nil {
				e.der, e.notAfter = der, notAfter
			}
			e.refreshing = nil
			close(done)
			c.mu.Unlock()
			return der, err
		}

		refreshing := e.refreshing
		c.mu.Unlock()
		select {
		case <-refreshing:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		c.mu.Lock()
	}
}

// fetch gets a new certificate from the inner provider and parses its expiry.
func (c *CachingCertProvider) fetch(ctx context.Context, keypair sign.Keypair, opts *sign.CertificateProviderOptions) ([]byte, time.Time, error) {
	der, err := c.inner.GetCertificate(ctx, keypair, opts)
	if err != nil {
		return nil, time.Time{}, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("parsing certificate: %w", err)
	}
	return der, cert.NotAfter, nil
}

// entryLocked returns the cache entry for key, creating it if needed, after
// pruning entries whose certs have expired so the cache doesn't grow without
// bound across identities. Entries with a refresh in flight are kept.
// Must be called with c.mu held.
func (c *CachingCertProvider) entryLocked(key certKey) *certEntry {
	for k, e := range c.certs {
		if e.refreshing == nil && e.needsRefresh() {
			delete(c.certs, k)
		}
	}
	e, ok := c.certs[key]
	if !ok {
		e = &certEntry{}
		c.certs[key] = e
	}
	return e
}

// tokenIdentity returns a certKey holding the issuer and subject of a JWT,
// read without verifying it. Fulcio verifies the token; this only picks the
// cache entry, the same way mono's legacy apkauth signer keys its certs.
func tokenIdentity(idToken string) (certKey, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return certKey{}, errors.New("ID token is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return certKey{}, fmt.Errorf("decoding ID token payload: %w", err)
	}
	var claims struct {
		Issuer  string `json:"iss"`
		Subject string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return certKey{}, fmt.Errorf("parsing ID token claims: %w", err)
	}
	if claims.Issuer == "" || claims.Subject == "" {
		return certKey{}, errors.New("ID token is missing iss or sub")
	}
	return certKey{issuer: claims.Issuer, subject: claims.Subject}, nil
}
