package secant

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"google.golang.org/protobuf/encoding/protojson"
)

// signData signs content into a serialized protobuf bundle with a certificate
// from bs.certs for idToken's identity. It builds the same timestamp authority
// and Rekor clients as cosign's bundle.SignData, which offers no way to set
// their transport and signs on context.Background, and signs with ctx through
// bs.transport.
func (bs *BundleSigner) signData(ctx context.Context, content sign.Content, idToken string) ([]byte, error) {
	now := time.Now()
	opts := sign.BundleOptions{
		Context:                    ctx,
		TrustedRoot:                bs.trustedMaterial,
		CertificateProvider:        bs.certs,
		CertificateProviderOptions: &sign.CertificateProviderOptions{IDToken: idToken},
	}

	if urls := bs.signingConfig.TimestampAuthorityURLs(); len(urls) != 0 {
		svcs, err := root.SelectServices(urls, bs.signingConfig.TimestampAuthorityURLsConfig(), sign.TimestampAuthorityAPIVersions, now)
		if err != nil {
			return nil, fmt.Errorf("selecting timestamp authorities: %w", err)
		}
		for _, svc := range svcs {
			opts.TimestampAuthorities = append(opts.TimestampAuthorities, sign.NewTimestampAuthority(&sign.TimestampAuthorityOptions{
				URL:       svc.URL,
				Timeout:   30 * time.Second,
				Retries:   1,
				Transport: bs.transport,
			}))
		}
	}

	var usingRekorV2 bool
	if urls := bs.signingConfig.RekorLogURLs(); len(urls) != 0 {
		svcs, err := root.SelectServices(urls, bs.signingConfig.RekorLogURLsConfig(), sign.RekorAPIVersions, now)
		if err != nil {
			return nil, fmt.Errorf("selecting rekor logs: %w", err)
		}
		for _, svc := range svcs {
			if svc.MajorAPIVersion == 2 {
				usingRekorV2 = true
			}
			opts.TransparencyLogs = append(opts.TransparencyLogs, sign.NewRekor(&sign.RekorOptions{
				BaseURL:   svc.URL,
				Timeout:   90 * time.Second,
				Retries:   1,
				Version:   svc.MajorAPIVersion,
				Transport: bs.transport,
			}))
		}
	}
	// Rekor v2 does not timestamp entries, so a short-lived Fulcio
	// certificate logged there needs a timestamp authority to verify.
	if usingRekorV2 && len(opts.TimestampAuthorities) == 0 {
		return nil, errors.New("a timestamp authority must be provided to request a short-lived certificate that will be logged to Rekor")
	}

	bundle, err := sign.Bundle(content, bs.keypair, opts)
	if err != nil {
		return nil, fmt.Errorf("error signing bundle: %w", err)
	}
	return protojson.Marshal(bundle)
}
