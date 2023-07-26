package tlog

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	cbundle "github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/tuf"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

func Upload(ctx context.Context, rekorClient *client.Rekor, pe models.ProposedEntry) (*models.LogEntryAnon, error) {
	params := entries.NewCreateLogEntryParamsWithContext(ctx)
	params.SetProposedEntry(pe)
	resp, err := rekorClient.Entries.CreateLogEntry(params)
	if err != nil {
		// If the entry already exists, we get a specific error.
		var existsErr *entries.CreateLogEntryConflict
		if errors.As(err, &existsErr) {
			fmt.Println("Signature already exists.")
			uriSplit := strings.Split(existsErr.Location.String(), "/")
			uuid := uriSplit[len(uriSplit)-1]
			e, err := getTlogEntry(ctx, rekorClient, uuid)
			if err != nil {
				return nil, err
			}
			rekorPubsFromAPI, err := rekorPubsFromClient(rekorClient)
			if err != nil {
				return nil, err
			}
			return e, verifyTLogEntryOffline(ctx, e, rekorPubsFromAPI)
		}
		return nil, fmt.Errorf("creating log entry: %w", err)
	}
	// UUID is at the end of location
	for _, p := range resp.Payload {
		return &p, nil
	}
	return nil, errors.New("bad response from server")
}

func getTlogEntry(ctx context.Context, rekorClient *client.Rekor, entryUUID string) (*models.LogEntryAnon, error) {
	params := entries.NewGetLogEntryByUUIDParamsWithContext(ctx)
	params.SetEntryUUID(entryUUID)
	resp, err := rekorClient.Entries.GetLogEntryByUUID(params)
	if err != nil {
		return nil, err
	}
	for k, e := range resp.Payload {
		// Validate that request EntryUUID matches the response UUID and response Tree ID
		if err := isExpectedResponseUUID(entryUUID, k, *e.LogID); err != nil {
			return nil, fmt.Errorf("unexpected entry returned from rekor server: %w", err)
		}
		// Check that body hash matches UUID
		if err := verifyUUID(k, e); err != nil {
			return nil, err
		}
		return &e, nil
	}
	return nil, errors.New("empty response")
}

// verifyTLogEntryOffline verifies a TLog entry against a map of trusted rekorPubKeys indexed
// by log id.
func verifyTLogEntryOffline(ctx context.Context, e *models.LogEntryAnon, rekorPubKeys *trustedTransparencyLogPubKeys) error {
	if e.Verification == nil || e.Verification.InclusionProof == nil {
		return errors.New("inclusion proof not provided")
	}

	if rekorPubKeys == nil || rekorPubKeys.Keys == nil {
		return errors.New("no trusted rekor public keys provided")
	}
	// Make sure all the rekorPubKeys are ecsda.PublicKeys
	for k, v := range rekorPubKeys.Keys {
		if _, ok := v.PubKey.(*ecdsa.PublicKey); !ok {
			return fmt.Errorf("rekor Public key for LogID %s is not type ecdsa.PublicKey", k)
		}
	}

	hashes := [][]byte{}
	for _, h := range e.Verification.InclusionProof.Hashes {
		hb, _ := hex.DecodeString(h)
		hashes = append(hashes, hb)
	}

	rootHash, _ := hex.DecodeString(*e.Verification.InclusionProof.RootHash)
	entryBytes, err := base64.StdEncoding.DecodeString(e.Body.(string))
	if err != nil {
		return err
	}
	leafHash := rfc6962.DefaultHasher.HashLeaf(entryBytes)

	// Verify the inclusion proof.
	if err := proof.VerifyInclusion(rfc6962.DefaultHasher, uint64(*e.Verification.InclusionProof.LogIndex), uint64(*e.Verification.InclusionProof.TreeSize),
		leafHash, hashes, rootHash); err != nil {
		return fmt.Errorf("verifying inclusion proof: %w", err)
	}

	// Verify rekor's signature over the SET.
	payload := cbundle.RekorPayload{
		Body:           e.Body,
		IntegratedTime: *e.IntegratedTime,
		LogIndex:       *e.LogIndex,
		LogID:          *e.LogID,
	}

	pubKey, ok := rekorPubKeys.Keys[payload.LogID]
	if !ok {
		return errors.New("rekor log public key not found for payload. Check your TUF root (see cosign initialize) or set a custom key with env var SIGSTORE_REKOR_PUBLIC_KEY")
	}
	if err := verifySET(payload, []byte(e.Verification.SignedEntryTimestamp), pubKey.PubKey.(*ecdsa.PublicKey)); err != nil {
		return fmt.Errorf("verifying signedEntryTimestamp: %w", err)
	}
	return nil
}

// TransparencyLogPubKey contains the ECDSA verification key and the current status
// of the key according to TUF metadata, whether it's active or expired.
type transparencyLogPubKey struct {
	PubKey crypto.PublicKey
	Status tuf.StatusKind
}

// This is a map of TransparencyLog public keys indexed by log ID that's used
// in verification.
type trustedTransparencyLogPubKeys struct {
	// A map of keys indexed by log ID
	Keys map[string]transparencyLogPubKey
}

func verifySET(bundlePayload cbundle.RekorPayload, signature []byte, pub *ecdsa.PublicKey) error {
	contents, err := json.Marshal(bundlePayload)
	if err != nil {
		return fmt.Errorf("marshaling: %w", err)
	}
	canonicalized, err := jsoncanonicalizer.Transform(contents)
	if err != nil {
		return fmt.Errorf("canonicalizing: %w", err)
	}

	// verify the SET against the public key
	hash := sha256.Sum256(canonicalized)
	if !ecdsa.VerifyASN1(pub, hash[:], signature) {
		return fmt.Errorf("unable to verify SET")
	}
	return nil
}

// rekorPubsFromClient returns a RekorPubKey keyed by the log ID from the Rekor client.
// NOTE: This **must not** be used in the verification path, but may be used in the
// sign path to validate return responses are consistent from Rekor.
func rekorPubsFromClient(rekorClient *client.Rekor) (*trustedTransparencyLogPubKeys, error) {
	publicKeys := newTrustedTransparencyLogPubKeys()
	pubOK, err := rekorClient.Pubkey.GetPublicKey(nil)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch rekor public key from rekor: %w", err)
	}
	if err := publicKeys.AddTransparencyLogPubKey([]byte(pubOK.Payload), tuf.Active); err != nil {
		return nil, fmt.Errorf("constructRekorPubKey: %w", err)
	}
	return &publicKeys, nil
}

func newTrustedTransparencyLogPubKeys() trustedTransparencyLogPubKeys {
	return trustedTransparencyLogPubKeys{Keys: make(map[string]transparencyLogPubKey, 0)}
}

// constructRekorPubkey returns a log ID and RekorPubKey from a given
// byte-array representing the PEM-encoded Rekor key and a status.
func (t *trustedTransparencyLogPubKeys) AddTransparencyLogPubKey(pemBytes []byte, status tuf.StatusKind) error {
	pubKey, err := cryptoutils.UnmarshalPEMToPublicKey(pemBytes)
	if err != nil {
		return err
	}
	keyID, err := GetTransparencyLogID(pubKey)
	if err != nil {
		return err
	}
	t.Keys[keyID] = transparencyLogPubKey{PubKey: pubKey, Status: status}
	return nil
}

// GetTransparencyLogID generates a SHA256 hash of a DER-encoded public key.
// (see RFC 6962 S3.2)
// In CT V1 the log id is a hash of the public key.
func GetTransparencyLogID(pub crypto.PublicKey) (string, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(pubBytes)
	return hex.EncodeToString(digest[:]), nil
}

// Validates UUID and also TreeID if present.
func isExpectedResponseUUID(requestEntryUUID string, responseEntryUUID string, treeid string) error {
	// Comparare UUIDs
	requestUUID, err := getUUID(requestEntryUUID)
	if err != nil {
		return err
	}
	responseUUID, err := getUUID(responseEntryUUID)
	if err != nil {
		return err
	}
	if requestUUID != responseUUID {
		return fmt.Errorf("expected EntryUUID %s got UUID %s", requestEntryUUID, responseEntryUUID)
	}
	// Compare tree ID if it is in the request.
	requestTreeID, err := getTreeUUID(requestEntryUUID)
	if err != nil {
		return err
	}
	if requestTreeID != "" {
		tid, err := getTreeUUID(treeid)
		if err != nil {
			return err
		}
		if requestTreeID != tid {
			return fmt.Errorf("expected EntryUUID %s got UUID %s from Tree %s", requestEntryUUID, responseEntryUUID, treeid)
		}
	}
	return nil
}

func verifyUUID(entryUUID string, e models.LogEntryAnon) error {
	// Verify and get the UUID.
	uid, err := getUUID(entryUUID)
	if err != nil {
		return err
	}
	uuid, err := hex.DecodeString(uid)
	if err != nil {
		return err
	}

	// Verify leaf hash matches hash of the entry body.
	computedLeafHash, err := computeLeafHash(&e)
	if err != nil {
		return err
	}
	if !bytes.Equal(computedLeafHash, uuid) {
		return fmt.Errorf("computed leaf hash did not match UUID")
	}
	return nil
}

const treeIDHexStringLen = 16
const uuidHexStringLen = 64
const entryIDHexStringLen = treeIDHexStringLen + uuidHexStringLen

func getUUID(entryUUID string) (string, error) {
	switch len(entryUUID) {
	case uuidHexStringLen:
		if _, err := hex.DecodeString(entryUUID); err != nil {
			return "", fmt.Errorf("uuid %v is not a valid hex string: %w", entryUUID, err)
		}
		return entryUUID, nil
	case entryIDHexStringLen:
		uid := entryUUID[len(entryUUID)-uuidHexStringLen:]
		return getUUID(uid)
	default:
		return "", fmt.Errorf("invalid ID len %v for %v", len(entryUUID), entryUUID)
	}
}

func computeLeafHash(e *models.LogEntryAnon) ([]byte, error) {
	entryBytes, err := base64.StdEncoding.DecodeString(e.Body.(string))
	if err != nil {
		return nil, err
	}
	return rfc6962.DefaultHasher.HashLeaf(entryBytes), nil
}

func getTreeUUID(entryUUID string) (string, error) {
	switch len(entryUUID) {
	case uuidHexStringLen:
		// No Tree ID provided
		return "", nil
	case entryIDHexStringLen:
		tid := entryUUID[:treeIDHexStringLen]
		return getTreeUUID(tid)
	case treeIDHexStringLen:
		// Check that it's a valid int64 in hex (base 16)
		i, err := strconv.ParseInt(entryUUID, 16, 64)
		if err != nil {
			return "", fmt.Errorf("could not convert treeID %v to int64: %w", entryUUID, err)
		}
		// Check for invalid TreeID values
		if i == 0 {
			return "", fmt.Errorf("0 is not a valid TreeID")
		}
		return entryUUID, nil
	default:
		return "", fmt.Errorf("invalid ID len %v for %v", len(entryUUID), entryUUID)
	}
}
