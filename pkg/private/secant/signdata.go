package secant

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"google.golang.org/protobuf/encoding/protojson"
)

// signData signs content into a serialized protobuf bundle, getting a Fulcio
// certificate with idToken or using certPEM. It builds the same Fulcio,
// timestamp authority and Rekor clients as cosign's bundle.SignData, which
// offers no way to set their transport and signs on context.Background, and
// signs with ctx through bs.transport.
func (bs *BundleSigner) signData(ctx context.Context, content sign.Content, idToken string, certPEM []byte) ([]byte, error) {
	now := time.Now()
	opts := sign.BundleOptions{
		Context:     ctx,
		TrustedRoot: bs.trustedMaterial,
	}

	switch {
	case idToken != "":
		svc, err := root.SelectService(bs.signingConfig.FulcioCertificateAuthorityURLs(), sign.FulcioAPIVersions, now)
		if err != nil {
			return nil, fmt.Errorf("selecting fulcio: %w", err)
		}
		opts.CertificateProvider = sign.NewFulcio(&sign.FulcioOptions{
			BaseURL:   svc.URL,
			Timeout:   30 * time.Second,
			Retries:   1,
			Transport: bs.transport,
		})
		opts.CertificateProviderOptions = &sign.CertificateProviderOptions{IDToken: idToken}
	case certPEM != nil:
		opts.CertificateProvider = pemCertProvider(certPEM)
	default:
		return nil, errors.New("signing needs an ID token or a certificate")
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
	if usingRekorV2 && len(opts.TimestampAuthorities) == 0 && idToken != "" {
		return nil, errors.New("a timestamp authority must be provided to request a short-lived certificate that will be logged to Rekor")
	}

	bundle, err := sign.Bundle(content, bs.keypair, opts)
	if err != nil {
		return nil, fmt.Errorf("error signing bundle: %w", err)
	}
	return protojson.Marshal(bundle)
}

// pemCertProvider provides a PEM-encoded certificate as DER.
type pemCertProvider []byte

func (p pemCertProvider) GetCertificate(context.Context, sign.Keypair, *sign.CertificateProviderOptions) ([]byte, error) {
	block, _ := pem.Decode(p)
	if block == nil {
		return nil, errors.New("could not decode cert")
	}
	return block.Bytes, nil
}
