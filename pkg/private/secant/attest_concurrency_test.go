package secant

import (
	"context"
	"fmt"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chainguard-dev/terraform-provider-cosign/pkg/private/secant/types"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/sigstore-go/pkg/sign"
)

// inFlightTracker counts concurrent calls, so a test can tell work that
// overlapped from work that ran one call at a time.
type inFlightTracker struct {
	mu          sync.Mutex
	inFlight    int
	maxInFlight int
	calls       int
}

func (c *inFlightTracker) enter() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.inFlight++
	c.calls++
	if c.inFlight > c.maxInFlight {
		c.maxInFlight = c.inFlight
	}
}

func (c *inFlightTracker) leave() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.inFlight--
}

func (c *inFlightTracker) snapshot() (calls, maxInFlight int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls, c.maxInFlight
}

// slowRekorEntries is fakeRekorEntries with a delay on every upload. It is
// safe for concurrent use, which fakeRekorEntries alone is not.
type slowRekorEntries struct {
	fakeRekorEntries
	delay   time.Duration
	tracker inFlightTracker
}

func (f *slowRekorEntries) CreateLogEntryContext(ctx context.Context, params *entries.CreateLogEntryParams, opts ...entries.ClientOption) (*entries.CreateLogEntryCreated, error) {
	f.tracker.enter()
	defer f.tracker.leave()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(f.delay):
	}
	// The embedded fake's counter is not guarded; serialize the handoff.
	f.tracker.mu.Lock()
	defer f.tracker.mu.Unlock()
	return f.fakeRekorEntries.CreateLogEntry(params, opts...)
}

// newStatementsForDigest builds one statement per predicate type for digest,
// each with a distinct payload so SKIPSAME cannot collapse them.
func newStatementsForDigest(t *testing.T, digest name.Digest, predicateTypes []string) []*types.Statement {
	t.Helper()
	statements := make([]*types.Statement, 0, len(predicateTypes))
	for i, pt := range predicateTypes {
		stmt, err := NewStatement(digest, strings.NewReader(fmt.Sprintf(`{"statement":%d}`, i)), pt)
		if err != nil {
			t.Fatalf("NewStatement(%q): %v", pt, err)
		}
		statements = append(statements, stmt)
	}
	return statements
}

// TestAttestUploadsStatementsConcurrentlyInOrder pins the behavior that makes
// a multi-statement attestation cost about one Rekor round trip: the uploads
// overlap, and the attestations are still attached in the order the
// statements were given.
func TestAttestUploadsStatementsConcurrentlyInOrder(t *testing.T) {
	ctx := context.Background()
	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)
	repo, err := name.NewRepository(strings.TrimPrefix(srv.URL, "http://") + "/test-repo")
	if err != nil {
		t.Fatal(err)
	}
	// Never pushed: Attest works purely by digest.
	digest := repo.Digest("sha256:" + strings.Repeat("b", 64))

	predicateTypes := []string{"spdx", "cyclonedx", "custom"}
	statements := newStatementsForDigest(t, digest, predicateTypes)

	fake := &slowRekorEntries{delay: 200 * time.Millisecond}
	rekorClient := &client.Rekor{Entries: fake}

	start := time.Now()
	if err := Attest(ctx, SkipSame, statements, newTestCosigner(t), rekorClient, nil); err != nil {
		t.Fatalf("Attest() = %v", err)
	}
	elapsed := time.Since(start)

	calls, maxInFlight := fake.tracker.snapshot()
	if calls != len(statements) {
		t.Errorf("got %d rekor uploads, want %d", calls, len(statements))
	}
	if maxInFlight < 2 {
		t.Errorf("rekor uploads never overlapped: max in flight %d, elapsed %v", maxInFlight, elapsed)
	}

	tag, err := ociremote.AttestationTag(digest)
	if err != nil {
		t.Fatal(err)
	}
	atts, err := ociremote.Signatures(tag)
	if err != nil {
		t.Fatalf("fetching %s: %v", tag, err)
	}
	sigs, err := atts.Get()
	if err != nil {
		t.Fatalf("getting attestations: %v", err)
	}
	got := make([]string, 0, len(sigs))
	for _, s := range sigs {
		ann, err := s.Annotations()
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, ann["predicateType"])
	}
	// Attestations are attached one at a time in statement order, and the
	// SKIPSAME replace op (replaceSignatures.Replace) puts each new attestation
	// ahead of the existing ones, so the stored order is the statement order
	// reversed. That is what the sequential implementation produced too; the
	// point here is that concurrent uploads must not change it.
	want := []string{
		"https://cosign.sigstore.dev/attestation/v1",
		"https://cyclonedx.org/bom",
		"https://spdx.dev/Document",
	}
	if !slices.Equal(got, want) {
		t.Errorf("attestation order = %v, want %v", got, want)
	}
}

// TestAttestEntityRejectsMismatchedSubjectsBeforeSigning keeps the subject
// check ahead of any signing, so a bad batch costs no Rekor uploads.
func TestAttestEntityRejectsMismatchedSubjectsBeforeSigning(t *testing.T) {
	ctx := context.Background()
	repo, err := name.NewRepository("example.com/test-repo")
	if err != nil {
		t.Fatal(err)
	}
	first := repo.Digest("sha256:" + strings.Repeat("d", 64))
	second := repo.Digest("sha256:" + strings.Repeat("e", 64))
	statements := append(newStatementsForDigest(t, first, []string{"spdx"}), newStatementsForDigest(t, second, []string{"cyclonedx"})...)

	fake := &slowRekorEntries{}
	rekorClient := &client.Rekor{Entries: fake}
	se := ociremote.SignedUnknown(first)
	if _, err := AttestEntity(ctx, se, SkipSame, statements, newTestCosigner(t), rekorClient); err == nil {
		t.Fatal("AttestEntity() succeeded with statements for two subjects")
	}
	if calls, _ := fake.tracker.snapshot(); calls != 0 {
		t.Errorf("got %d rekor uploads for a rejected batch, want 0", calls)
	}
}

// slowContentSigner is fakeContentSigner with a delay on every sign, safe for
// concurrent use.
type slowContentSigner struct {
	fakeContentSigner
	delay   time.Duration
	tracker inFlightTracker
}

func (f *slowContentSigner) SignContent(ctx context.Context, content sign.Content) ([]byte, error) {
	f.tracker.enter()
	defer f.tracker.leave()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(f.delay):
	}
	f.tracker.mu.Lock()
	defer f.tracker.mu.Unlock()
	return f.fakeContentSigner.SignContent(ctx, content)
}

// TestAttestBundleSignsPredicateTypesConcurrently mirrors the legacy test for
// the bundle path: statements of different predicate types are signed at the
// same time, and every one ends up as a referrer.
func TestAttestBundleSignsPredicateTypesConcurrently(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t, true)
	// Never pushed, as in apkoaas, so the statements carry the subject
	// descriptor verbatim.
	digest := repo.Digest("sha256:" + strings.Repeat("c", 64))
	h, err := v1.NewHash(digest.DigestStr())
	if err != nil {
		t.Fatal(err)
	}
	predicateTypes := []string{"spdx", "cyclonedx", "custom"}
	statements := newStatementsForDigest(t, digest, predicateTypes)
	for _, stmt := range statements {
		stmt.SubjectDescriptor = &v1.Descriptor{Digest: h}
	}

	signer := &slowContentSigner{fakeContentSigner: fakeContentSigner{t: t}, delay: 200 * time.Millisecond}
	start := time.Now()
	if err := attestBundle(ctx, SkipSame, statements, signer, nil); err != nil {
		t.Fatalf("attestBundle() = %v", err)
	}
	elapsed := time.Since(start)

	calls, maxInFlight := signer.tracker.snapshot()
	if calls != len(statements) {
		t.Errorf("got %d bundle signs, want %d", calls, len(statements))
	}
	if maxInFlight < 2 {
		t.Errorf("bundle signs never overlapped: max in flight %d, elapsed %v", maxInFlight, elapsed)
	}
	if got := len(referrerManifests(t, digest)); got != len(statements) {
		t.Errorf("got %d referrers, want %d", got, len(statements))
	}
}
