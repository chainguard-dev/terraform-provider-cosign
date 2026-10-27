package secant

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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
	"github.com/sigstore/cosign/v3/pkg/oci"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/signature"
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
	return f.CreateLogEntry(params, opts...)
}

// serialCosigner wraps testCosigner and records how many signing calls are in
// flight, so a test can check that AttestEntity never signs concurrently and
// so never requires a signer that is safe for concurrent use.
type serialCosigner struct {
	*testCosigner
	tracker inFlightTracker
}

func (c *serialCosigner) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	c.tracker.enter()
	defer c.tracker.leave()
	return c.testCosigner.SignMessage(message, opts...)
}

func (c *serialCosigner) Cosign(ctx context.Context, payload io.Reader) (oci.Signature, error) {
	c.tracker.enter()
	defer c.tracker.leave()
	return c.testCosigner.Cosign(ctx, payload)
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

// attestedPredicateTypes reads back the legacy attestations of digest and
// returns their predicate types in stored order.
func attestedPredicateTypes(t *testing.T, digest name.Digest) []string {
	t.Helper()
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
	return got
}

// TestAttestUploadsStatementsConcurrentlyInOrder pins the behavior that makes
// a multi-statement attestation cost about one Rekor round trip: the uploads
// overlap, signing stays sequential, and the attestations are still attached
// in the order the statements were given.
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

	signer := &serialCosigner{testCosigner: newTestCosigner(t)}
	fake := &slowRekorEntries{delay: 200 * time.Millisecond}
	rekorClient := &client.Rekor{Entries: fake}

	start := time.Now()
	if err := Attest(ctx, SkipSame, statements, signer, rekorClient, nil); err != nil {
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
	// Only the uploads fan out. The signer interface makes no promise about
	// concurrent use, so signing must stay one call at a time.
	if _, signMax := signer.tracker.snapshot(); signMax != 1 {
		t.Errorf("signer was called concurrently: max in flight %d, want 1", signMax)
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
	if got := attestedPredicateTypes(t, digest); !slices.Equal(got, want) {
		t.Errorf("attestation order = %v, want %v", got, want)
	}
}

// TestAttestConcurrencyBelowOneIsSequential pins that AttestConcurrency values
// below 1 mean sequential, not unbounded.
func TestAttestConcurrencyBelowOneIsSequential(t *testing.T) {
	old := AttestConcurrency
	t.Cleanup(func() { AttestConcurrency = old })
	AttestConcurrency = 0

	ctx := context.Background()
	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)
	repo, err := name.NewRepository(strings.TrimPrefix(srv.URL, "http://") + "/test-repo")
	if err != nil {
		t.Fatal(err)
	}
	digest := repo.Digest("sha256:" + strings.Repeat("a", 64))
	statements := newStatementsForDigest(t, digest, []string{"spdx", "cyclonedx", "custom"})

	fake := &slowRekorEntries{delay: 50 * time.Millisecond}
	rekorClient := &client.Rekor{Entries: fake}
	if err := Attest(ctx, SkipSame, statements, newTestCosigner(t), rekorClient, nil); err != nil {
		t.Fatalf("Attest() = %v", err)
	}
	calls, maxInFlight := fake.tracker.snapshot()
	if calls != len(statements) {
		t.Errorf("got %d rekor uploads, want %d", calls, len(statements))
	}
	if maxInFlight != 1 {
		t.Errorf("AttestConcurrency = 0 still overlapped uploads: max in flight %d, want 1", maxInFlight)
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

// requestsContaining returns the recorded "METHOD /path" lines that contain
// substr.
func (r *recordingRegistry) requestsContaining(substr string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var reqs []string
	for _, req := range r.reqs {
		if strings.Contains(req, substr) {
			reqs = append(reqs, req)
		}
	}
	return reqs
}

// referrerPredicateTypes returns the predicate types of every bundle referrer
// discoverable through digest, sorted.
func referrerPredicateTypes(t *testing.T, digest name.Digest) []string {
	t.Helper()
	var got []string
	for _, raw := range referrerManifests(t, digest) {
		var mf struct {
			Annotations map[string]string `json:"annotations"`
		}
		if err := json.Unmarshal(raw, &mf); err != nil {
			t.Fatal(err)
		}
		got = append(got, mf.Annotations[ociremote.BundlePredicateType])
	}
	slices.Sort(got)
	return got
}

// TestAttestBundleSignsPredicateTypesConcurrently covers the bundle path on
// both registry flavors: the statements are signed at the same time, the
// subject's referrers are listed once rather than once per statement, every
// statement ends up discoverable through the subject, and REPLACE and
// SKIPSAME re-runs leave the registry consistent. The fallback-tag case is the
// one where concurrent writes used to drop entries from the shared index.
func TestAttestBundleSignsPredicateTypesConcurrently(t *testing.T) {
	for _, tc := range []struct {
		name             string
		referrersSupport bool
	}{
		{name: "native referrers", referrersSupport: true},
		{name: "fallback tag index", referrersSupport: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			repo, rec := newRecordingTestRepo(t, tc.referrersSupport)
			// Never pushed, as in apkoaas, so the statements carry the subject
			// descriptor verbatim.
			digest := repo.Digest("sha256:" + strings.Repeat("c", 64))
			h, err := v1.NewHash(digest.DigestStr())
			if err != nil {
				t.Fatal(err)
			}
			statements := newStatementsForDigest(t, digest, []string{"spdx", "cyclonedx", "custom"})
			for _, stmt := range statements {
				stmt.SubjectDescriptor = &v1.Descriptor{Digest: h}
			}
			want := []string{
				"https://cosign.sigstore.dev/attestation/v1",
				"https://cyclonedx.org/bom",
				"https://spdx.dev/Document",
			}

			signer := &slowContentSigner{delay: 200 * time.Millisecond}
			signer.t = t
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
			if got := referrerPredicateTypes(t, digest); !slices.Equal(got, want) {
				t.Errorf("discoverable referrers = %v, want %v", got, want)
			}
			assertFallbackIndexConsistent(t, digest)

			// REPLACE deletes all three and writes three more; the fallback
			// index must end up listing exactly the new ones.
			if err := attestBundle(ctx, Replace, statements, signer, nil); err != nil {
				t.Fatalf("attestBundle(REPLACE) = %v", err)
			}
			replaced, _ := signer.tracker.snapshot()
			if got := replaced - calls; got != len(statements) {
				t.Errorf("REPLACE signed %d statements, want %d", got, len(statements))
			}
			if got := referrerPredicateTypes(t, digest); !slices.Equal(got, want) {
				t.Errorf("discoverable referrers after REPLACE = %v, want %v", got, want)
			}
			assertFallbackIndexConsistent(t, digest)

			// SKIPSAME finds every payload already present and signs nothing.
			// With no writes in this run (each write probes the Referrers API
			// too), the referrers requests are the conflict-resolution listing
			// alone, which must happen once per subject, not once per statement.
			rec.reset()
			if err := attestBundle(ctx, SkipSame, statements, signer, nil); err != nil {
				t.Fatalf("attestBundle(SKIPSAME) = %v", err)
			}
			skipped, _ := signer.tracker.snapshot()
			if got := skipped - replaced; got != 0 {
				t.Errorf("SKIPSAME re-run signed %d statements, want 0", got)
			}
			if got := rec.requestsContaining("/referrers/"); len(got) != 1 {
				t.Errorf("SKIPSAME listed referrers %d times for one subject, want 1: %v", len(got), got)
			}
			if got := referrerPredicateTypes(t, digest); !slices.Equal(got, want) {
				t.Errorf("discoverable referrers after SKIPSAME = %v, want %v", got, want)
			}
		})
	}
}

// TestAttestBundleRejectsDuplicatePredicateTypes mirrors newStatements for the
// bundle path: under SKIPSAME and REPLACE two statements of one predicate type
// would resolve against each other's write, so the batch is rejected before
// anything is signed. APPEND has no conflicts to resolve and writes both.
func TestAttestBundleRejectsDuplicatePredicateTypes(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t, false)
	digest := repo.Digest("sha256:" + strings.Repeat("f", 64))
	h, err := v1.NewHash(digest.DigestStr())
	if err != nil {
		t.Fatal(err)
	}
	statements := newStatementsForDigest(t, digest, []string{"spdx", "spdx"})
	for _, stmt := range statements {
		stmt.SubjectDescriptor = &v1.Descriptor{Digest: h}
	}

	signer := &slowContentSigner{}
	signer.t = t
	for _, conflict := range []string{SkipSame, Replace} {
		if err := attestBundle(ctx, conflict, statements, signer, nil); err == nil {
			t.Errorf("attestBundle(%s) succeeded with two statements of one predicate type", conflict)
		}
	}
	if calls, _ := signer.tracker.snapshot(); calls != 0 {
		t.Errorf("got %d bundle signs for rejected batches, want 0", calls)
	}

	if err := attestBundle(ctx, Append, statements, signer, nil); err != nil {
		t.Fatalf("attestBundle(APPEND) = %v", err)
	}
	if got := len(referrerManifests(t, digest)); got != len(statements) {
		t.Errorf("got %d referrers after APPEND, want %d", got, len(statements))
	}
	assertFallbackIndexConsistent(t, digest)
}
