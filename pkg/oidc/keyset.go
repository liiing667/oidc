package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
	"strings"

	jose "github.com/go-jose/go-jose/v4"
)

const (
	KeyUseSignature = "sig"
)

var (
	ErrKeyMultiple = errors.New("multiple possible keys match")
	ErrKeyNone     = errors.New("no possible keys matches")
	// ErrKeyDuplicateID is returned when a JWKS publishes more than one key
	// with the same non-empty kid and use, which makes key selection ambiguous.
	// It typically indicates that a signing key was rotated while reusing the
	// old kid. Give every generation its own unique kid instead.
	ErrKeyDuplicateID = errors.New("multiple keys with the same key id")
)

// KeySet represents a set of JSON Web Keys
// - remotely fetch via discovery and jwks_uri -> `remoteKeySet`
// - held by the OP itself in storage -> `openIDKeySet`
// - dynamically aggregated by request for OAuth JWT Profile Assertion -> `jwtProfileKeySet`
type KeySet interface {
	// VerifySignature verifies the signature with the given keyset and returns the raw payload
	VerifySignature(ctx context.Context, jws *jose.JSONWebSignature) (payload []byte, err error)
}

// GetKeyIDAndAlg returns the `kid` and `alg` claim from the JWS header
func GetKeyIDAndAlg(jws *jose.JSONWebSignature) (string, string) {
	keyID := ""
	alg := ""
	for _, sig := range jws.Signatures {
		keyID = sig.Header.KeyID
		alg = sig.Header.Algorithm
		break
	}
	return keyID, alg
}

// FindKey searches the given JSON Web Keys for the requested key ID, usage and key type
//
// will return the key immediately if matches exact (id, usage, type)
//
// will return false none or multiple match
//
// deprecated: use FindMatchingKey which will return an error (more specific) instead of just a bool
// moved implementation already to FindMatchingKey
func FindKey(keyID, use, expectedAlg string, keys ...jose.JSONWebKey) (jose.JSONWebKey, bool) {
	key, err := FindMatchingKey(keyID, use, expectedAlg, keys...)
	return key, err == nil
}

// FindMatchingKey searches the given JSON Web Keys for the requested key ID, usage and alg type
//
// will return the key immediately if matches exact (id, usage, type)
//
// will return a specific error if none (ErrKeyNone) or multiple (ErrKeyMultiple) match
func FindMatchingKey(keyID, use, expectedAlg string, keys ...jose.JSONWebKey) (key jose.JSONWebKey, err error) {
	var validKeys []jose.JSONWebKey
	var exactMatches []jose.JSONWebKey
	for _, k := range keys {
		// ignore all keys with wrong use (let empty use of published key pass)
		if k.Use != use && k.Use != "" {
			continue
		}
		// ignore all keys with wrong algorithm type
		if !algToKeyType(k.Key, expectedAlg) {
			continue
		}
		// A JWKS key that advertises an explicit alg must use the exact same
		// alg as the JWT. Matching only on the key type would let an RS256 key
		// be selected for a PS256 token, or an old generation be chosen after
		// an alg change. Keys without an advertised alg keep the legacy
		// type-only behavior.
		if k.Algorithm != "" && k.Algorithm != expectedAlg {
			continue
		}
		// if we get here, use and alg match, so an equal (not empty) keyID is an exact match
		if k.KeyID == keyID && keyID != "" {
			exactMatches = append(exactMatches, k)
			continue
		}
		// keyIDs did not match or at least one was empty (if later, then it could be a match)
		if k.KeyID == "" || keyID == "" {
			validKeys = append(validKeys, k)
		}
	}
	// Exact kid matches win over empty-kid candidates.
	if len(exactMatches) == 1 {
		return exactMatches[0], nil
	}
	if len(exactMatches) > 1 {
		// Multiple keys share the same kid and are compatible with the JWT
		// alg. The JWKS is ambiguous, which usually means a kid was reused
		// across generations. Reject instead of picking one arbitrarily.
		return key, fmt.Errorf("%w: %q", ErrKeyDuplicateID, keyID)
	}
	// if we get here, no match was possible at all (use / alg) or no exact match due to
	// the signed JWT and / or the published keys didn't have a kid
	// if later applies and only one key could be found, we'll return it
	// otherwise a corresponding error will be thrown
	if len(validKeys) == 1 {
		return validKeys[0], nil
	}
	if len(validKeys) > 1 {
		return key, ErrKeyMultiple
	}
	return key, ErrKeyNone
}

func algToKeyType(key any, alg string) bool {
	if strings.HasPrefix(alg, "RS") || strings.HasPrefix(alg, "PS") {
		_, ok := key.(*rsa.PublicKey)
		return ok
	}
	if strings.HasPrefix(alg, "ES") {
		_, ok := key.(*ecdsa.PublicKey)
		return ok
	}
	if alg == string(jose.EdDSA) {
		_, ok := key.(ed25519.PublicKey)
		return ok
	}
	return false
}
