package interactive

import (
	"context"
	"os"

	"github.com/sigstore/cosign/v2/pkg/providers"
	"github.com/sigstore/sigstore/pkg/oauth"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"golang.org/x/oauth2"
)

const (
	defaultIssuer = "https://oauth2.sigstore.dev/auth"
)

func init() {
	providers.Register("interactive", &provider{})
}

type provider struct {
}

func (p *provider) Enabled(ctx context.Context) bool {
	return os.Getenv("TF_COSIGN_LOCAL") != ""
}

func (p *provider) Provide(ctx context.Context, audience string) (string, error) {
	flow := &oauthflow.InteractiveIDTokenGetter{
		HTMLPage: oauth.InteractiveSuccessHTML,
		Input:    nil,
		Output:   nil,
	}
	if cid := os.Getenv("TF_COSIGN_CONNECTOR_ID"); cid != "" {
		flow.ExtraAuthURLParams = []oauth2.AuthCodeOption{oauthflow.ConnectorIDOpt(cid)}
	}

	iss := os.Getenv("TF_COSIGN_ISSUER")
	if iss == "" {
		iss = defaultIssuer
	}
	clientSecret := os.Getenv("TF_COSIGN_CLIENT_SECRET")
	redirectURL := os.Getenv("TF_COSIGN_REDIRECT_URL")

	tok, err := oauthflow.OIDConnect(iss, audience, clientSecret, redirectURL, flow)
	if err != nil {
		return "", err
	}
	return tok.RawString, nil
}
