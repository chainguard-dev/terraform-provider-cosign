// TODO: delete this file in favor of ociremote.WriteAttestationNewBundleFormat
// once the upstream cosign change adding a verbatim subject-descriptor option
// merges.

package secant

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
)

// referrerManifest augments v1.Manifest with the OCI 1.1 top-level artifactType
// field (which go-containerregistry's v1.Manifest does not model) and implements
// remote.Taggable so it can be PUT directly. It mirrors the unexported type of the
// same name in cosign's pkg/oci/remote so the serialized manifest is byte-identical.
type referrerManifest struct {
	v1.Manifest
	ArtifactType string `json:"artifactType,omitempty"`
}

func (r referrerManifest) RawManifest() ([]byte, error) {
	return json.Marshal(r)
}

func (r referrerManifest) MediaType() (types.MediaType, error) {
	return types.OCIManifestSchema1, nil
}

// writeBundleReferrer writes a v0.3 DSSE bundle for d as an OCI referrer. It
// reproduces cosign's ociremote.WriteAttestationNewBundleFormat / WriteReferrer
// manifest layout byte-for-byte so the result is discoverable and verifiable
// identically, with one deliberate difference: a non-nil subject is used verbatim
// as the referrer's subject descriptor, with no HEAD against the registry, so the
// subject manifest need not exist in d's repository (though the descriptor's
// digest must match d's). This supports the
// COSIGN_REPOSITORY-style pattern where attestations live in a repository separate
// from (and without) the subject image. A nil subject is resolved via HEAD exactly
// like cosign's WriteReferrer, and any failure (including 404) is an error.
//
// Everything is written to d.Repository, which the caller has already pointed at the
// desired (possibly override) repository.
func writeBundleReferrer(d name.Digest, bundleBytes []byte, predicateType string, subject *v1.Descriptor, ropt []remote.Option) error {
	bundleMediaType, err := sgbundle.MediaTypeString("0.3")
	if err != nil {
		return fmt.Errorf("generating bundle media type string: %w", err)
	}

	// Empty config layer, matching cosign's writeEmptyConfigLayer. Note the config
	// *blob* uses the image config media type while the config *descriptor* in the
	// manifest below uses the OCI empty media type, exactly as cosign does.
	configLayer := static.NewLayer([]byte("{}"), "application/vnd.oci.image.config.v1+json")
	configDesc, err := layerDescriptor(configLayer)
	if err != nil {
		return fmt.Errorf("describing config layer: %w", err)
	}
	if err := remote.WriteLayer(d.Repository, configLayer, ropt...); err != nil {
		return fmt.Errorf("uploading config layer: %w", err)
	}

	// The bundle itself is the sole layer.
	bundleLayer := static.NewLayer(bundleBytes, types.MediaType(bundleMediaType))
	bundleDesc, err := layerDescriptor(bundleLayer)
	if err != nil {
		return fmt.Errorf("describing bundle layer: %w", err)
	}
	if err := remote.WriteLayer(d.Repository, bundleLayer, ropt...); err != nil {
		return fmt.Errorf("uploading bundle layer: %w", err)
	}

	subject, err = subjectDescriptor(d, subject, ropt)
	if err != nil {
		return err
	}

	manifest := referrerManifest{
		Manifest: v1.Manifest{
			SchemaVersion: 2,
			MediaType:     types.OCIManifestSchema1,
			Config: v1.Descriptor{
				MediaType:    types.MediaType("application/vnd.oci.empty.v1+json"),
				ArtifactType: bundleMediaType,
				Digest:       configDesc.Digest,
				Size:         configDesc.Size,
			},
			Layers:  []v1.Descriptor{bundleDesc},
			Subject: subject,
			Annotations: map[string]string{
				"org.opencontainers.image.created": time.Now().UTC().Format(time.RFC3339),
				"dev.sigstore.bundle.content":      "dsse-envelope",
				ociremote.BundlePredicateType:      predicateType,
			},
		},
		ArtifactType: bundleMediaType,
	}

	manifestBytes, err := manifest.RawManifest()
	if err != nil {
		return fmt.Errorf("marshaling referrer manifest: %w", err)
	}
	manifestDigest, _, err := v1.SHA256(bytes.NewReader(manifestBytes))
	if err != nil {
		return fmt.Errorf("digesting referrer manifest: %w", err)
	}
	if err := remote.Put(d.Digest(manifestDigest.String()), manifest, ropt...); err != nil {
		return fmt.Errorf("uploading referrer manifest for %q: %w", d.String(), err)
	}
	return nil
}

// layerDescriptor builds an OCI descriptor for an already-constructed layer.
func layerDescriptor(layer v1.Layer) (v1.Descriptor, error) {
	mt, err := layer.MediaType()
	if err != nil {
		return v1.Descriptor{}, fmt.Errorf("layer media type: %w", err)
	}
	dig, err := layer.Digest()
	if err != nil {
		return v1.Descriptor{}, fmt.Errorf("layer digest: %w", err)
	}
	sz, err := layer.Size()
	if err != nil {
		return v1.Descriptor{}, fmt.Errorf("layer size: %w", err)
	}
	return v1.Descriptor{MediaType: mt, Digest: dig, Size: sz}, nil
}

// subjectDescriptor returns the OCI descriptor for d's subject. A non-nil subject
// is returned verbatim with no network call; the caller vouches for it, and a
// synthetic descriptor (digest-only, "size":0 — v1.Descriptor.Size has no
// omitempty) is fine because the read and verify paths never consult the subject's
// media type/size (the OCI Referrers listing keys on the subject digest, and
// sigstore-go verifies the subject digest, not the referrer's subject descriptor).
// A nil subject is resolved via HEAD, where any failure — including 404 — is an
// error, matching cosign's WriteReferrer.
func subjectDescriptor(d name.Digest, subject *v1.Descriptor, ropt []remote.Option) (*v1.Descriptor, error) {
	if subject != nil {
		// A descriptor for a different digest would be indexed by the registry
		// under that digest, leaving the referrer undiscoverable via d and
		// invisible to conflict resolution.
		if subject.Digest.String() != d.DigestStr() {
			return nil, fmt.Errorf("subject descriptor digest %q does not match %q", subject.Digest.String(), d.String())
		}
		return subject, nil
	}

	desc, err := remote.Head(d, ropt...)
	if err != nil {
		return nil, fmt.Errorf("resolving subject descriptor for %q: %w", d.String(), err)
	}
	return &v1.Descriptor{
		MediaType: desc.MediaType,
		Digest:    desc.Digest,
		Size:      desc.Size,
	}, nil
}
