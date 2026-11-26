package secant

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/chainguard-dev/terraform-provider-cosign/pkg/private/secant/types"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	intotov1 "github.com/in-toto/attestation/go/v1"
	ctypes "github.com/sigstore/cosign/v3/pkg/types"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"google.golang.org/protobuf/encoding/protojson"
)

// testDigests returns n digests in repo that were never pushed, as when a
// caller signs concurrently with its publish. fill picks the hex digit the
// digests are made of, so separate calls yield separate digests.
func testDigests(t *testing.T, repo name.Repository, fill string, n int) []name.Digest {
	t.Helper()
	digests := make([]name.Digest, 0, n)
	for i := range n {
		digests = append(digests, repo.Digest("sha256:"+strings.Repeat(fill, 63)+fmt.Sprint(i)))
	}
	return digests
}

// statementSubjects returns the sha256 subject digests of an in-toto statement
// payload, in order.
func statementSubjects(t *testing.T, payload []byte) []string {
	t.Helper()
	statement := &intotov1.Statement{}
	if err := protojson.Unmarshal(payload, statement); err != nil {
		t.Fatalf("unmarshaling statement: %v", err)
	}
	subjects := make([]string, 0, len(statement.Subject))
	for _, s := range statement.Subject {
		subjects = append(subjects, "sha256:"+s.Digest["sha256"])
	}
	return subjects
}

func digestStrings(digests []name.Digest) []string {
	out := make([]string, 0, len(digests))
	for _, d := range digests {
		out = append(out, d.DigestStr())
	}
	return out
}

// bundlePayloads returns the DSSE payload of every bundle referrer of d that
// carries predicateType.
func bundlePayloads(t *testing.T, d name.Digest, predicateType string) [][]byte {
	t.Helper()
	matching, err := matchingBundleReferrers(d, predicateType, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	payloads := make([][]byte, 0, len(matching))
	for _, m := range matching {
		p, err := referrerDSSEPayload(d.Repository, m.Digest, nil)
		if err != nil {
			t.Fatal(err)
		}
		payloads = append(payloads, p)
	}
	return payloads
}

// TestSignBundleDigestsSignsOnce is the point of the multi-subject path: an
// index and its two platform manifests get one signature between them, the
// bundle is discoverable through each digest, and its statement names all
// three in the order given.
func TestSignBundleDigestsSignsOnce(t *testing.T) {
	ctx := context.Background()

	for _, referrersSupport := range []bool{true, false} {
		t.Run(fmt.Sprintf("referrersSupport=%t", referrersSupport), func(t *testing.T) {
			repo, rec := newRecordingTestRepo(t, referrersSupport)
			digests := testDigests(t, repo, "a", 3)
			subjects := make([]signSubject, 0, len(digests))
			for _, d := range digests {
				subjects = append(subjects, signSubject{digest: d})
			}

			signer := &fakeContentSigner{t: t}
			if err := signBundleStatement(ctx, SkipSame, nil, signer, subjects, nil, nil); err != nil {
				t.Fatalf("signBundleStatement() = %v", err)
			}
			if signer.calls != 1 {
				t.Errorf("got %d sign operations for %d digests, want 1", signer.calls, len(digests))
			}
			var first []byte
			for i, d := range digests {
				payloads := bundlePayloads(t, d, ctypes.CosignSignPredicateType)
				if len(payloads) != 1 {
					t.Fatalf("got %d sign bundles for %s, want 1", len(payloads), d)
				}
				if got, want := statementSubjects(t, payloads[0]), digestStrings(digests); !slices.Equal(got, want) {
					t.Errorf("statement subjects on %s = %v, want %v", d, got, want)
				}
				if i == 0 {
					first = payloads[0]
				} else if !bytes.Equal(payloads[0], first) {
					t.Errorf("payload on %s differs from the one on %s", d, digests[0])
				}
				// The referrer of each digest must point at that digest, or the
				// registry would not list it there.
				for _, s := range signBundleSubjects(t, d) {
					if s == nil || s.Digest.String() != d.DigestStr() {
						t.Errorf("referrer subject for %s = %v", d, s)
					}
				}
				assertFallbackIndexConsistent(t, d)
			}

			// A SKIPSAME re-run finds the statement on every digest and signs
			// nothing.
			signer.calls = 0
			if err := signBundleStatement(ctx, SkipSame, nil, signer, subjects, nil, nil); err != nil {
				t.Fatalf("signBundleStatement() re-run = %v", err)
			}
			if signer.calls != 0 {
				t.Errorf("re-run performed %d sign operations, want 0", signer.calls)
			}

			// REPLACE re-signs once and still converges on one bundle each.
			if err := signBundleStatement(ctx, Replace, nil, signer, subjects, nil, nil); err != nil {
				t.Fatalf("signBundleStatement() REPLACE = %v", err)
			}
			if signer.calls != 1 {
				t.Errorf("REPLACE run performed %d sign operations, want 1", signer.calls)
			}
			for _, d := range digests {
				if got := len(bundlePayloads(t, d, ctypes.CosignSignPredicateType)); got != 1 {
					t.Errorf("got %d sign bundles for %s after REPLACE, want 1", got, d)
				}
				assertFallbackIndexConsistent(t, d)
				if reads := rec.subjectRequests(d, http.MethodGet, http.MethodHead); len(reads) != 0 {
					t.Errorf("subject manifest %s was read: %v", d, reads)
				}
			}
		})
	}
}

// TestSignBundleDigestsSharedChild covers a platform image that belongs to two
// sets of subjects: a rebuild changed the index and one platform and left the
// other platform's digest as it was. The shared digest already carries a sign
// statement naming it, so it is left alone, and the two builds can go on being
// re-run in turn without signing anything more.
func TestSignBundleDigestsSharedChild(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t, false)
	old := testDigests(t, repo, "b", 3) // index, amd64, arm64
	fresh := testDigests(t, repo, "c", 2)
	rebuiltDigests := []name.Digest{fresh[0], old[1], fresh[1]} // new index, same amd64, new arm64

	var before, rebuilt []signSubject
	for _, d := range old {
		before = append(before, signSubject{digest: d})
	}
	for _, d := range rebuiltDigests {
		rebuilt = append(rebuilt, signSubject{digest: d})
	}

	signer := &fakeContentSigner{t: t}
	if err := signBundleStatement(ctx, SkipSame, nil, signer, before, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := signBundleStatement(ctx, SkipSame, nil, signer, rebuilt, nil, nil); err != nil {
		t.Fatal(err)
	}
	if signer.calls != 2 {
		t.Errorf("got %d sign operations for two builds, want 2", signer.calls)
	}

	check := func() {
		t.Helper()
		want := map[string][]string{
			old[0].DigestStr():   digestStrings(old),
			old[1].DigestStr():   digestStrings(old), // shared: keeps the statement it had
			old[2].DigestStr():   digestStrings(old),
			fresh[0].DigestStr(): digestStrings(rebuiltDigests),
			fresh[1].DigestStr(): digestStrings(rebuiltDigests),
		}
		for d, subjects := range want {
			payloads := bundlePayloads(t, repo.Digest(d), ctypes.CosignSignPredicateType)
			if len(payloads) != 1 {
				t.Fatalf("got %d sign bundles for %s, want 1", len(payloads), d)
			}
			got := statementSubjects(t, payloads[0])
			if !slices.Equal(got, subjects) {
				t.Errorf("statement subjects on %s = %v, want %v", d, got, subjects)
			}
			if !slices.Contains(got, d) {
				t.Errorf("statement on %s does not name it: %v", d, got)
			}
			assertFallbackIndexConsistent(t, repo.Digest(d))
		}
	}
	check()

	// Both builds re-run, in turn. Neither replaces the other's bundle on the
	// shared digest, so neither finds anything to sign.
	for range 2 {
		if err := signBundleStatement(ctx, SkipSame, nil, signer, before, nil, nil); err != nil {
			t.Fatal(err)
		}
		if err := signBundleStatement(ctx, SkipSame, nil, signer, rebuilt, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	if signer.calls != 2 {
		t.Errorf("re-running both builds performed %d more sign operations, want 0", signer.calls-2)
	}
	check()
}

// TestAttestBundleSharedChild is the attestation side of a digest shared by
// two sets of subjects: the digest keeps a statement whose predicate is the
// one being written, and takes the new statement when the predicate changed.
func TestAttestBundleSharedChild(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t, false)
	old := testDigests(t, repo, "6", 3)
	fresh := testDigests(t, repo, "7", 2)
	rebuilt := []name.Digest{fresh[0], old[1], fresh[1]}

	attest := func(digests []name.Digest, predicate string) []*types.Statement {
		t.Helper()
		statements, err := NewMultiSubjectStatements(digests, strings.NewReader(predicate), testPredicateType)
		if err != nil {
			t.Fatal(err)
		}
		withSubjectDescriptors(t, statements)
		return statements
	}
	signer := &slowContentSigner{}
	signer.t = t
	signs := func() int {
		calls, _ := signer.tracker.snapshot()
		return calls
	}

	first := attest(old, `{"packages":["a=1"]}`)
	if err := attestBundle(ctx, SkipSame, first, signer, nil); err != nil {
		t.Fatal(err)
	}

	// Same predicate: one signature for the two new digests, and the shared
	// digest keeps what it has.
	if err := attestBundle(ctx, SkipSame, attest(rebuilt, `{"packages":["a=1"]}`), signer, nil); err != nil {
		t.Fatal(err)
	}
	if got := signs(); got != 2 {
		t.Errorf("got %d bundle signs, want 2", got)
	}
	payloads := bundlePayloads(t, old[1], testPredicateType)
	if len(payloads) != 1 || !bytes.Equal(payloads[0], first[0].Payload) {
		t.Errorf("shared digest did not keep its statement")
	}

	// A different predicate is a different claim, so the shared digest takes
	// the new statement.
	changed := attest(rebuilt, `{"packages":["a=2"]}`)
	if err := attestBundle(ctx, SkipSame, changed, signer, nil); err != nil {
		t.Fatal(err)
	}
	if got := signs(); got != 3 {
		t.Errorf("got %d bundle signs, want 3", got)
	}
	for _, d := range rebuilt {
		payloads := bundlePayloads(t, d, testPredicateType)
		if len(payloads) != 1 || !bytes.Equal(payloads[0], changed[0].Payload) {
			t.Errorf("%s does not carry the statement with the changed predicate", d)
		}
		assertFallbackIndexConsistent(t, d)
	}
}

func TestStatementCovers(t *testing.T) {
	repo := newTestRepo(t, true)
	digests := testDigests(t, repo, "8", 3)
	d := digests[1]
	const hex0, hex1, hex2 = "8888888888888888888888888888888888888888888888888888888888888880", "8888888888888888888888888888888888888888888888888888888888888881", "8888888888888888888888888888888888888888888888888888888888888882"
	subject := func(hex, extra string) string {
		return `{"name":"r","digest":{"sha256":"` + hex + `"}` + extra + `}`
	}
	statement := func(predicateType, predicate string, subjects ...string) []byte {
		return []byte(`{"_type":"https://in-toto.io/Statement/v1","subject":[` + strings.Join(subjects, ",") + `],"predicateType":"` + predicateType + `","predicate":` + predicate + `}`)
	}
	pending := statement("p", `{"a":1}`, subject(hex2, ""), subject(hex1, ""))

	for _, tt := range []struct {
		name     string
		existing []byte
		want     bool
	}{
		{"different siblings", statement("p", `{"a":1}`, subject(hex0, ""), subject(hex1, "")), true},
		{"same claim, different formatting", statement("p", `{ "a" : 1 }`, subject(hex1, "")), true},
		{"does not name the digest", statement("p", `{"a":1}`, subject(hex0, "")), false},
		{"different predicate", statement("p", `{"a":2}`, subject(hex1, "")), false},
		{"different predicate type", statement("q", `{"a":1}`, subject(hex1, "")), false},
		{"different subject annotations", statement("p", `{"a":1}`, subject(hex1, `,"annotations":{"k":"v"}`)), false},
		{"not a statement", []byte(`not json`), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := statementCovers(tt.existing, pending, d); got != tt.want {
				t.Errorf("statementCovers() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestSignBundleDigestsSingleMatchesSignBundleDigest pins that one digest takes
// the multi-subject path to the same statement as the single-digest one, so a
// caller can switch entry points without re-signing what is already signed.
func TestSignBundleDigestsSingleMatchesSignBundleDigest(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t, true)
	d := testDigests(t, repo, "d", 1)[0]

	signer := &fakeContentSigner{t: t}
	if err := signBundleDigest(ctx, SkipSame, nil, signer, d, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := signBundleStatement(ctx, SkipSame, nil, signer, []signSubject{{digest: d}}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if signer.calls != 1 {
		t.Errorf("got %d sign operations, want 1: the single-digest statements differ", signer.calls)
	}
}

func TestSignBundleDigestsRejectsRepeatedDigest(t *testing.T) {
	repo := newTestRepo(t, true)
	d := testDigests(t, repo, "e", 1)[0]

	signer := &fakeContentSigner{t: t}
	err := signBundleStatement(context.Background(), SkipSame, nil, signer, []signSubject{{digest: d}, {digest: d}}, nil, nil)
	if err == nil {
		t.Fatal("signBundleStatement() succeeded with a digest listed twice")
	}
	if signer.calls != 0 {
		t.Errorf("got %d sign operations for a rejected call, want 0", signer.calls)
	}
}

func TestNewMultiSubjectStatements(t *testing.T) {
	repo := newTestRepo(t, true)
	digests := testDigests(t, repo, "f", 3)
	const predicate = `{"buildType":"https://example.com/build"}`

	t.Run("one digest matches NewStatement", func(t *testing.T) {
		single, err := NewStatement(digests[0], strings.NewReader(predicate), testPredicateType)
		if err != nil {
			t.Fatal(err)
		}
		multi, err := NewMultiSubjectStatements(digests[:1], strings.NewReader(predicate), testPredicateType)
		if err != nil {
			t.Fatal(err)
		}
		if len(multi) != 1 || !bytes.Equal(multi[0].Payload, single.Payload) {
			t.Errorf("NewMultiSubjectStatements(1 digest) differs from NewStatement:\n got %s\nwant %s", multi[0].Payload, single.Payload)
		}
	})

	t.Run("one statement per digest sharing a payload", func(t *testing.T) {
		statements, err := NewMultiSubjectStatements(digests, strings.NewReader(predicate), testPredicateType)
		if err != nil {
			t.Fatal(err)
		}
		if len(statements) != len(digests) {
			t.Fatalf("got %d statements, want %d", len(statements), len(digests))
		}
		for i, stmt := range statements {
			if stmt.Digest != digests[i] {
				t.Errorf("statement %d is for %s, want %s", i, stmt.Digest, digests[i])
			}
			if stmt.Type != testPredicateType {
				t.Errorf("statement %d has type %q", i, stmt.Type)
			}
			if !bytes.Equal(stmt.Payload, statements[0].Payload) {
				t.Errorf("statement %d does not share the payload", i)
			}
		}

		var payload struct {
			PredicateType string `json:"predicateType"`
			Subject       []struct {
				Name   string            `json:"name"`
				Digest map[string]string `json:"digest"`
			} `json:"subject"`
			Predicate json.RawMessage `json:"predicate"`
		}
		if err := json.Unmarshal(statements[0].Payload, &payload); err != nil {
			t.Fatal(err)
		}
		if payload.PredicateType != testPredicateType {
			t.Errorf("predicateType = %q", payload.PredicateType)
		}
		if len(payload.Subject) != len(digests) {
			t.Fatalf("got %d subjects, want %d", len(payload.Subject), len(digests))
		}
		for i, s := range payload.Subject {
			if got, want := "sha256:"+s.Digest["sha256"], digests[i].DigestStr(); got != want {
				t.Errorf("subject %d = %s, want %s", i, got, want)
			}
			if s.Name != repo.String() {
				t.Errorf("subject %d name = %q, want %q", i, s.Name, repo.String())
			}
		}
		var got, want any
		if err := json.Unmarshal(payload.Predicate, &got); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(predicate), &want); err != nil {
			t.Fatal(err)
		}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("predicate = %v, want %v", got, want)
		}
	})

	t.Run("rejects no digests and repeats", func(t *testing.T) {
		if _, err := NewMultiSubjectStatements(nil, strings.NewReader(predicate), testPredicateType); err == nil {
			t.Error("succeeded with no digests")
		}
		if _, err := NewMultiSubjectStatements([]name.Digest{digests[0], digests[0]}, strings.NewReader(predicate), testPredicateType); err == nil {
			t.Error("succeeded with a digest listed twice")
		}
	})
}

// withSubjectDescriptors gives each statement a digest-only subject descriptor,
// as callers attesting an unpushed subject do.
func withSubjectDescriptors(t *testing.T, statements []*types.Statement) {
	t.Helper()
	for _, stmt := range statements {
		h, err := v1.NewHash(stmt.Digest.DigestStr())
		if err != nil {
			t.Fatal(err)
		}
		stmt.SubjectDescriptor = &v1.Descriptor{Digest: h}
	}
}

// TestAttestBundleSignsSharedPayloadOnce covers the apkoaas shape: provenance
// that is true of the index and both platform manifests is one multi-subject
// statement, while each digest keeps an SBOM of its own. The provenance must be
// signed once and the SBOMs once each.
func TestAttestBundleSignsSharedPayloadOnce(t *testing.T) {
	const spdx = "https://spdx.dev/Document"

	for _, referrersSupport := range []bool{true, false} {
		t.Run(fmt.Sprintf("referrersSupport=%t", referrersSupport), func(t *testing.T) {
			ctx := context.Background()
			repo := newTestRepo(t, referrersSupport)
			digests := testDigests(t, repo, "1", 3)

			provenance, err := NewMultiSubjectStatements(digests, strings.NewReader(`{"builder":"shared"}`), testPredicateType)
			if err != nil {
				t.Fatal(err)
			}
			statements := slices.Clone(provenance)
			for i, d := range digests {
				sbom, err := NewStatement(d, strings.NewReader(fmt.Sprintf(`{"SPDXID":"SPDXRef-%d"}`, i)), "spdxjson")
				if err != nil {
					t.Fatal(err)
				}
				statements = append(statements, sbom)
			}
			withSubjectDescriptors(t, statements)

			signer := &slowContentSigner{}
			signer.t = t
			if err := attestBundle(ctx, SkipSame, statements, signer, nil); err != nil {
				t.Fatalf("attestBundle() = %v", err)
			}
			if calls, _ := signer.tracker.snapshot(); calls != 1+len(digests) {
				t.Errorf("got %d bundle signs, want %d: one shared provenance and one SBOM per digest", calls, 1+len(digests))
			}
			for _, d := range digests {
				if got, want := referrerPredicateTypes(t, d), []string{testPredicateType, spdx}; !slices.Equal(got, want) {
					t.Errorf("referrers of %s = %v, want %v", d, got, want)
				}
				payloads := bundlePayloads(t, d, testPredicateType)
				if len(payloads) != 1 || !bytes.Equal(payloads[0], provenance[0].Payload) {
					t.Errorf("provenance on %s is not the shared statement", d)
				}
				assertFallbackIndexConsistent(t, d)
			}

			// SKIPSAME finds everything in place.
			before, _ := signer.tracker.snapshot()
			if err := attestBundle(ctx, SkipSame, statements, signer, nil); err != nil {
				t.Fatalf("attestBundle() re-run = %v", err)
			}
			if after, _ := signer.tracker.snapshot(); after != before {
				t.Errorf("SKIPSAME re-run signed %d statements, want 0", after-before)
			}

			// REPLACE signs the shared statement once again, not once per digest.
			if err := attestBundle(ctx, Replace, statements, signer, nil); err != nil {
				t.Fatalf("attestBundle(REPLACE) = %v", err)
			}
			if after, _ := signer.tracker.snapshot(); after-before != 1+len(digests) {
				t.Errorf("REPLACE signed %d statements, want %d", after-before, 1+len(digests))
			}
			for _, d := range digests {
				if got, want := referrerPredicateTypes(t, d), []string{testPredicateType, spdx}; !slices.Equal(got, want) {
					t.Errorf("referrers of %s after REPLACE = %v, want %v", d, got, want)
				}
				assertFallbackIndexConsistent(t, d)
			}
		})
	}
}

// TestAttestBundleSharedPayloadPartialRetry covers a run that died after
// writing the shared statement to one digest: the retry leaves that digest
// alone and signs once for the rest.
func TestAttestBundleSharedPayloadPartialRetry(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t, false)
	digests := testDigests(t, repo, "2", 3)
	statements, err := NewMultiSubjectStatements(digests, strings.NewReader(`{"builder":"shared"}`), testPredicateType)
	if err != nil {
		t.Fatal(err)
	}
	withSubjectDescriptors(t, statements)

	signer := &slowContentSigner{}
	signer.t = t
	if err := attestBundle(ctx, SkipSame, statements[:1], signer, nil); err != nil {
		t.Fatal(err)
	}
	if err := attestBundle(ctx, SkipSame, statements, signer, nil); err != nil {
		t.Fatal(err)
	}
	if calls, _ := signer.tracker.snapshot(); calls != 2 {
		t.Errorf("got %d bundle signs, want 2: the first write and one for the two remaining digests", calls)
	}
	for _, d := range digests {
		if got := len(bundlePayloads(t, d, testPredicateType)); got != 1 {
			t.Errorf("got %d provenance bundles for %s, want 1", got, d)
		}
	}
}

// TestAttestBundleAppendSignsRepeatsOnOneSubject pins that sharing a signature
// is between subjects only: under APPEND the same payload twice on one subject
// is two attestations, as before.
func TestAttestBundleAppendSignsRepeatsOnOneSubject(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t, true)
	d := testDigests(t, repo, "3", 1)[0]

	var statements []*types.Statement
	for range 2 {
		stmt, err := NewStatement(d, strings.NewReader(`{"same":true}`), "spdxjson")
		if err != nil {
			t.Fatal(err)
		}
		statements = append(statements, stmt)
	}
	withSubjectDescriptors(t, statements)

	signer := &slowContentSigner{}
	signer.t = t
	if err := attestBundle(ctx, Append, statements, signer, nil); err != nil {
		t.Fatal(err)
	}
	if calls, _ := signer.tracker.snapshot(); calls != 2 {
		t.Errorf("got %d bundle signs, want 2", calls)
	}
}

// TestMultiSubjectStatementsVerifyOnEachSubject checks the claim the
// multi-subject path rests on, against the verifier cosign v3 uses: one signed
// statement naming several digests verifies for each of them, and for no
// other digest.
func TestMultiSubjectStatementsVerifyOnEachSubject(t *testing.T) {
	ctx := context.Background()
	repo, _ := newRecordingTestRepo(t, true)
	digests := testDigests(t, repo, "4", 3)
	other := testDigests(t, repo, "5", 1)[0]

	// Capture the sign statement SignBundleDigests produces.
	capture := &fakeContentSigner{t: t}
	subjects := make([]signSubject, 0, len(digests))
	for _, d := range digests {
		subjects = append(subjects, signSubject{digest: d})
	}
	if err := signBundleStatement(ctx, SkipSame, nil, capture, subjects, nil, nil); err != nil {
		t.Fatal(err)
	}
	signPayloads := bundlePayloads(t, digests[0], ctypes.CosignSignPredicateType)
	if len(signPayloads) != 1 {
		t.Fatalf("got %d sign bundles, want 1", len(signPayloads))
	}
	attestations, err := NewMultiSubjectStatements(digests, strings.NewReader(`{"builder":"shared"}`), testPredicateType)
	if err != nil {
		t.Fatal(err)
	}

	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := verify.NewVerifier(vs, verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1))
	if err != nil {
		t.Fatal(err)
	}

	for name, payload := range map[string][]byte{
		"signature":   signPayloads[0],
		"attestation": attestations[0].Payload,
	} {
		t.Run(name, func(t *testing.T) {
			entity, err := vs.Attest("signer@example.com", "https://issuer.example.com", payload)
			if err != nil {
				t.Fatal(err)
			}
			policyFor := func(d string) verify.PolicyBuilder {
				raw, err := hex.DecodeString(strings.TrimPrefix(d, "sha256:"))
				if err != nil {
					t.Fatal(err)
				}
				return verify.NewPolicy(verify.WithArtifactDigest("sha256", raw), verify.WithoutIdentitiesUnsafe())
			}
			for _, d := range digests {
				if _, err := verifier.Verify(entity, policyFor(d.DigestStr())); err != nil {
					t.Errorf("verifying %s: %v", d.DigestStr(), err)
				}
			}
			if _, err := verifier.Verify(entity, policyFor(other.DigestStr())); err == nil {
				t.Errorf("verified %s, which the statement does not name", other.DigestStr())
			}
		})
	}
}
