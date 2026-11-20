package op

import (
	"context"
	"errors"
	"fmt"

	jose "github.com/go-jose/go-jose/v4"
)

var ErrSignerCreationFailed = errors.New("signer creation failed")

type SigningKey interface {
	SignatureAlgorithm() jose.SignatureAlgorithm
	Key() any
	ID() string
}

// KeyGenerations is an optional Storage capability that ties the signing
// identity, the published JWKS and signature verification to one ordered set
// of key generations.
//
// A plain [Storage] already exposes SigningKey and KeySet separately. When a
// storage implements KeyGenerations, the provider can verify that the signing
// generation is present in the published set and that every published kid is
// unique. This makes the typical rotation mistakes fail fast:
//
//   - reusing a kid for a new generation, which leaves relying parties with an
//     ambiguous or stale JWKS cache;
//   - a JWKS document or cache that lags behind the signing side, so a freshly
//     issued token cannot be verified;
//   - publishing two keys with the same kid but a different alg or key material.
//
// Generations are ordered oldest to newest. The newest element is the current
// signing generation and must also be part of the returned [Key] set. Older
// generations are kept published for the verification window of tokens that
// were issued before the rotation.
type KeyGenerations interface {
	// KeyGenerations returns all published signing generations, oldest first.
	// The last element is the current generation used for signing.
	KeyGenerations(ctx context.Context) ([]Key, error)
}

// ErrKeyGeneration is returned when the signing key and the published JWKS do
// not agree on the current generation, or when the JWKS is ambiguous.
var ErrKeyGeneration = errors.New("key generation mismatch")

// ValidateKeyGenerations asserts that the JWKS used for publishing and
// verification shares one consistent generation view:
//
//   - every kid occurs at most once, so a kid uniquely identifies one
//     generation and one alg;
//   - the current signing key's kid is published, so newly issued tokens can
//     always be verified;
//   - every published key uses the signature use.
//
// It returns nil when the generations are consistent.
func ValidateKeyGenerations(signing SigningKey, keys []Key) error {
	kids := make(map[string]Key, len(keys))
	var current Key
	for _, key := range keys {
		if key.Use() != "" && key.Use() != "sig" {
			continue
		}
		if key.ID() == "" {
			continue
		}
		if existing, ok := kids[key.ID()]; ok {
			return fmt.Errorf("%w: duplicate kid %q (alg %q and %q)",
				ErrKeyGeneration, key.ID(), existing.Algorithm(), key.Algorithm())
		}
		kids[key.ID()] = key
		if key.ID() == signing.ID() {
			current = key
		}
	}
	if current == nil {
		return fmt.Errorf("%w: signing kid %q is not part of the published JWKS",
			ErrKeyGeneration, signing.ID())
	}
	if current.Algorithm() != signing.SignatureAlgorithm() {
		return fmt.Errorf("%w: signing kid %q uses alg %q but JWKS advertises %q",
			ErrKeyGeneration, signing.ID(), signing.SignatureAlgorithm(), current.Algorithm())
	}
	return nil
}

// signingKeyFromStorage returns the current [SigningKey]. When the storage
// also implements [KeyGenerations], it validates that the signing generation
// and the published JWKS share one consistent generation view before a token
// is issued. Storages that only implement [Storage] keep the legacy behavior.
func signingKeyFromStorage(ctx context.Context, storage Storage) (SigningKey, error) {
	signing, err := storage.SigningKey(ctx)
	if err != nil {
		return nil, err
	}
	generations, ok := storage.(KeyGenerations)
	if !ok {
		return signing, nil
	}
	keys, err := generations.KeyGenerations(ctx)
	if err != nil {
		return nil, err
	}
	if err := ValidateKeyGenerations(signing, keys); err != nil {
		return nil, err
	}
	return signing, nil
}

func SignerFromKey(key SigningKey) (jose.Signer, error) {
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: key.SignatureAlgorithm(),
		Key: &jose.JSONWebKey{
			Key:   key.Key(),
			KeyID: key.ID(),
		},
	}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return nil, ErrSignerCreationFailed // TODO: log / wrap error?
	}
	return signer, nil
}

type Key interface {
	ID() string
	Algorithm() jose.SignatureAlgorithm
	Use() string
	Key() any
}
