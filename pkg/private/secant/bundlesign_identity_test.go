package secant

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
	"strings"
	"testing"
	"time"

	"github.com/chainguard-dev/terraform-provider-cosign/pkg/private/secant/fulcio"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"google.golang.org/protobuf/encoding/protojson"
)

type subjectCtxKey struct{}

// subjectOIDCProvider returns a token for the subject scoped on the context,
// the way apkauth picks an org scope from the request context.
type subjectOIDCProvider struct{}

func (subjectOIDCProvider) Enabled(context.Context) bool { return true }

func (subjectOIDCProvider) Provide(ctx context.Context, _ string) (string, error) {
	sub, ok := ctx.Value(subjectCtxKey{}).(string)
	if !ok {
		return "", errors.New("no subject on context")
	}
	claims, err := json.Marshal(map[string]string{"iss": "https://issuer.enforce.dev", "sub": sub})
	if err != nil {
		return "", err
	}
	return "e30." + base64.RawURLEncoding.EncodeToString(claims) + ".sig", nil
}

// subjectFulcio issues self-signed certs naming the token's subject.
type subjectFulcio struct{ fetches int }

func (f *subjectFulcio) GetCertificate(_ context.Context, _ sign.Keypair, opts *sign.CertificateProviderOptions) ([]byte, error) {
	f.fetches++
	var claims struct {
		Subject string `json:"sub"`
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(opts.IDToken, ".")[1])
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: claims.Subject},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(10 * time.Minute),
	}
	return x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
}

// TestBundleSignerSignsAsCallerIdentity signs offline through the real
// cbundle.SignData (no transparency log or TSA in the signing config) and
// checks that each bundle carries a cert for the identity on its context.
func TestBundleSignerSignsAsCallerIdentity(t *testing.T) {
	sc, err := root.NewSigningConfig(root.SigningConfigMediaType02, nil, nil, nil, root.ServiceConfiguration{}, nil, root.ServiceConfiguration{})
	if err != nil {
		t.Fatalf("NewSigningConfig: %v", err)
	}
	keypair, err := sign.NewEphemeralKeypair(nil)
	if err != nil {
		t.Fatalf("NewEphemeralKeypair: %v", err)
	}
	f := &subjectFulcio{}
	bs := &BundleSigner{
		oidc:          subjectOIDCProvider{},
		signingConfig: sc,
		keypair:       keypair,
		certs:         fulcio.NewCachingCertProvider(f),
	}

	for _, sub := range []string{"org-a/identity", "org-b/identity", "org-a/identity", "org-b/identity"} {
		ctx := context.WithValue(context.Background(), subjectCtxKey{}, sub)
		bundleBytes, err := bs.SignContent(ctx, &sign.PlainData{Data: []byte("x")})
		if err != nil {
			t.Fatalf("SignContent as %s: %v", sub, err)
		}
		var bundle protobundle.Bundle
		if err := protojson.Unmarshal(bundleBytes, &bundle); err != nil {
			t.Fatalf("unmarshaling bundle: %v", err)
		}
		cert, err := x509.ParseCertificate(bundle.GetVerificationMaterial().GetCertificate().GetRawBytes())
		if err != nil {
			t.Fatalf("parsing bundle cert: %v", err)
		}
		if got := cert.Subject.CommonName; got != sub {
			t.Errorf("signed as %q with a cert for %q", sub, got)
		}
	}
	if f.fetches != 2 {
		t.Errorf("Fulcio fetches = %d, want 2 (one per identity)", f.fetches)
	}
}
