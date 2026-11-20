package oidc

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"reflect"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindKey(t *testing.T) {
	type args struct {
		keyID       string
		use         string
		expectedAlg string
		keys        []jose.JSONWebKey
	}
	type res struct {
		key jose.JSONWebKey
		err error
	}
	tests := []struct {
		name string
		args args
		res  res
	}{
		{
			"no keys, ErrKeyNone",
			args{
				keyID:       "",
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keys:        nil,
			},
			res{
				key: jose.JSONWebKey{},
				err: ErrKeyNone,
			},
		},
		{
			"single key enc, ErrKeyNone",
			args{
				keyID:       "",
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keys: []jose.JSONWebKey{
					{
						Use: "enc",
						Key: &rsa.PublicKey{},
					},
				},
			},
			res{
				key: jose.JSONWebKey{},
				err: ErrKeyNone,
			},
		},
		{
			"single key wrong algorithm, ErrKeyNone",
			args{
				keyID:       "",
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keys: []jose.JSONWebKey{
					{
						Use: "sig",
						Key: &rsa.PrivateKey{},
					},
				},
			},
			res{
				key: jose.JSONWebKey{},
				err: ErrKeyNone,
			},
		},
		{
			"single key no kid, no jwt kid, match",
			args{
				keyID:       "",
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keys: []jose.JSONWebKey{
					{
						Use: "sig",
						Key: &rsa.PublicKey{},
					},
				},
			},
			res{
				key: jose.JSONWebKey{
					Use: "sig",
					Key: &rsa.PublicKey{},
				},
				err: nil,
			},
		},
		{
			"single key kid, jwt no kid, match",
			args{
				keyID:       "",
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keys: []jose.JSONWebKey{
					{
						Use:   "sig",
						KeyID: "id",
						Key:   &rsa.PublicKey{},
					},
				},
			},
			res{
				key: jose.JSONWebKey{
					Use:   "sig",
					KeyID: "id",
					Key:   &rsa.PublicKey{},
				},
				err: nil,
			},
		},
		{
			"single key no kid, jwt with kid, match",
			args{
				keyID:       "id",
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keys: []jose.JSONWebKey{
					{
						Use: "sig",
						Key: &rsa.PublicKey{},
					},
				},
			},
			res{
				key: jose.JSONWebKey{
					Use: "sig",
					Key: &rsa.PublicKey{},
				},
				err: nil,
			},
		},
		{
			"single key no use, jwt with kid, match",
			args{
				keyID:       "id",
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keys: []jose.JSONWebKey{
					{
						KeyID: "id",
						Key:   &rsa.PublicKey{},
					},
				},
			},
			res{
				key: jose.JSONWebKey{
					KeyID: "id",
					Key:   &rsa.PublicKey{},
				},
				err: nil,
			},
		},
		{
			"single key wrong kid, ErrKeyNone",
			args{
				keyID:       "id",
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keys: []jose.JSONWebKey{
					{
						Use:   "sig",
						KeyID: "id2",
						Key:   &rsa.PublicKey{},
					},
				},
			},
			res{
				key: jose.JSONWebKey{},
				err: ErrKeyNone,
			},
		},
		{
			"multiple keys no kid, jwt no kid, ErrKeyMultiple",
			args{
				keyID:       "",
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keys: []jose.JSONWebKey{
					{
						Use: "sig",
						Key: &rsa.PublicKey{},
					},
					{
						Use: "sig",
						Key: &rsa.PublicKey{},
					},
				},
			},
			res{
				key: jose.JSONWebKey{},
				err: ErrKeyMultiple,
			},
		},
		{
			"multiple keys with kid, jwt no kid, ErrKeyMultiple",
			args{
				keyID:       "",
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keys: []jose.JSONWebKey{
					{
						Use:   "sig",
						KeyID: "id1",
						Key:   &rsa.PublicKey{},
					},
					{
						Use:   "sig",
						KeyID: "id2",
						Key:   &rsa.PublicKey{},
					},
				},
			},
			res{
				key: jose.JSONWebKey{},
				err: ErrKeyMultiple,
			},
		},
		{
			"multiple keys, single sig key, jwt no kid, match",
			args{
				keyID:       "",
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keys: []jose.JSONWebKey{
					{
						Use: "sig",
						Key: &rsa.PublicKey{},
					},
					{
						Use: "enc",
						Key: &rsa.PublicKey{},
					},
				},
			},
			res{
				key: jose.JSONWebKey{
					Use: "sig",
					Key: &rsa.PublicKey{},
				},
				err: nil,
			},
		},
		{
			"multiple keys no kid, jwt with kid, ErrKeyMultiple",
			args{
				keyID:       "id",
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keys: []jose.JSONWebKey{
					{
						Use: "sig",
						Key: &rsa.PublicKey{},
					},
					{
						Use: "sig",
						Key: &rsa.PublicKey{},
					},
				},
			},
			res{
				key: jose.JSONWebKey{},
				err: ErrKeyMultiple,
			},
		},
		{
			"multiple keys with kid, jwt with kid, match",
			args{
				keyID:       "id1",
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keys: []jose.JSONWebKey{
					{
						Use:   "sig",
						KeyID: "id1",
						Key:   &rsa.PublicKey{},
					},
					{
						Use:   "sig",
						KeyID: "id2",
						Key:   &rsa.PublicKey{},
					},
				},
			},
			res{
				key: jose.JSONWebKey{
					Use:   "sig",
					KeyID: "id1",
					Key:   &rsa.PublicKey{},
				},
				err: nil,
			},
		},
		{
			"multiple keys, single sig key, jwt with kid, match",
			args{
				keyID:       "id1",
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keys: []jose.JSONWebKey{
					{
						Use: "sig",
						Key: &rsa.PublicKey{},
					},
					{
						Use: "enc",
						Key: &rsa.PublicKey{},
					},
				},
			},
			res{
				key: jose.JSONWebKey{
					Use: "sig",
					Key: &rsa.PublicKey{},
				},
				err: nil,
			},
		},
		{
			"multiple keys, no use, jwt with kid, match",
			args{
				keyID:       "id1",
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keys: []jose.JSONWebKey{
					{
						KeyID: "id1",
						Key:   &rsa.PublicKey{},
					},
					{
						KeyID: "id2",
						Key:   &rsa.PublicKey{},
					},
				},
			},
			res{
				key: jose.JSONWebKey{
					KeyID: "id1",
					Key:   &rsa.PublicKey{},
				},
				err: nil,
			},
		},
		{
			"multiple keys, no use, jwt without kid, ErrKeyMultiple",
			args{
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keys: []jose.JSONWebKey{
					{
						KeyID: "id1",
						Key:   &rsa.PublicKey{},
					},
					{
						KeyID: "id2",
						Key:   &rsa.PublicKey{},
					},
				},
			},
			res{
				key: jose.JSONWebKey{},
				err: ErrKeyMultiple,
			},
		},
		{
			"multiple keys, no use or id, jwt with kid, ErrKeyMultiple",
			args{
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keyID:       "id1",
				keys: []jose.JSONWebKey{
					{
						Key: &rsa.PublicKey{},
					},
					{
						Key: &rsa.PublicKey{},
					},
				},
			},
			res{
				key: jose.JSONWebKey{},
				err: ErrKeyMultiple,
			},
		},
		{
			"multiple keys (only one matching alg), jwt with kid, match",
			args{
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keyID:       "id1",
				keys: []jose.JSONWebKey{
					{
						Key: &rsa.PublicKey{},
					},
					{
						Key: &ecdsa.PublicKey{},
					},
				},
			},
			res{
				key: jose.JSONWebKey{
					Key: &rsa.PublicKey{},
				},
				err: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FindMatchingKey(tt.args.keyID, tt.args.use, tt.args.expectedAlg, tt.args.keys...)
			if (tt.res.err != nil && !errors.Is(err, tt.res.err)) || (tt.res.err == nil && err != nil) {
				t.Errorf("FindKey() error, got = %v, want = %v", err, tt.res.err)
			}
			if !reflect.DeepEqual(got, tt.res.key) {
				t.Errorf("FindKey() got = %v, want %v", got, tt.res.key)
			}
		})
	}
}

func TestFindMatchingKey_ExactAlgorithm(t *testing.T) {
	rsaKey := &rsa.PublicKey{}

	t.Run("advertised alg matches token alg", func(t *testing.T) {
		key := jose.JSONWebKey{Use: "sig", KeyID: "id", Algorithm: "RS256", Key: rsaKey}
		got, err := FindMatchingKey("id", KeyUseSignature, "RS256", key)
		require.NoError(t, err)
		assert.Equal(t, "id", got.KeyID)
	})

	t.Run("advertised alg differs from token alg", func(t *testing.T) {
		// Same RSA key type, but the JWKS still pins RS256 while the token is PS256.
		key := jose.JSONWebKey{Use: "sig", KeyID: "id", Algorithm: "RS256", Key: rsaKey}
		_, err := FindMatchingKey("id", KeyUseSignature, "PS256", key)
		assert.ErrorIs(t, err, ErrKeyNone)
	})

	t.Run("no advertised alg keeps type-only matching", func(t *testing.T) {
		key := jose.JSONWebKey{Use: "sig", KeyID: "id", Key: rsaKey}
		got, err := FindMatchingKey("id", KeyUseSignature, "PS256", key)
		require.NoError(t, err)
		assert.Equal(t, "id", got.KeyID)
	})

	t.Run("same kid different alg resolves the exact generation", func(t *testing.T) {
		old := jose.JSONWebKey{Use: "sig", KeyID: "shared", Algorithm: "RS256", Key: rsaKey}
		new := jose.JSONWebKey{Use: "sig", KeyID: "shared", Algorithm: "PS256", Key: rsaKey}
		got, err := FindMatchingKey("shared", KeyUseSignature, "PS256", old, new)
		require.NoError(t, err)
		assert.Equal(t, "PS256", got.Algorithm)
	})
}

func TestFindMatchingKey_DuplicateKid(t *testing.T) {
	rsaKey := &rsa.PublicKey{}

	t.Run("same kid and same alg is ambiguous", func(t *testing.T) {
		first := jose.JSONWebKey{Use: "sig", KeyID: "shared", Algorithm: "RS256", Key: rsaKey}
		second := jose.JSONWebKey{Use: "sig", KeyID: "shared", Algorithm: "RS256", Key: rsaKey}
		_, err := FindMatchingKey("shared", KeyUseSignature, "RS256", first, second)
		assert.ErrorIs(t, err, ErrKeyDuplicateID)
	})

	t.Run("unique kids still match", func(t *testing.T) {
		first := jose.JSONWebKey{Use: "sig", KeyID: "kid-1", Algorithm: "RS256", Key: rsaKey}
		second := jose.JSONWebKey{Use: "sig", KeyID: "kid-2", Algorithm: "RS256", Key: rsaKey}
		got, err := FindMatchingKey("kid-2", KeyUseSignature, "RS256", first, second)
		require.NoError(t, err)
		assert.Equal(t, "kid-2", got.KeyID)
	})
}
