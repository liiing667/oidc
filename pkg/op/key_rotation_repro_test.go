package op_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// genKey is one signing generation: a private key, its published JWK and the
// alg it is signed / advertised with.
type genKey struct {
	generation uint64
	kid        string
	alg        jose.SignatureAlgorithm
	priv       any
	pub        any
}

func newGenKey(t *testing.T, generation uint64, kid string, alg jose.SignatureAlgorithm) *genKey {
	t.Helper()
	g := &genKey{generation: generation, kid: kid, alg: alg}
	switch {
	case strings.HasPrefix(string(alg), "RS"), strings.HasPrefix(string(alg), "PS"):
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		g.priv, g.pub = priv, &priv.PublicKey
	case strings.HasPrefix(string(alg), "ES"):
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		g.priv, g.pub = priv, &priv.PublicKey
	default:
		t.Fatalf("unsupported test alg %q", alg)
	}
	return g
}

// SigningKey view: private material used to issue tokens.
func (g *genKey) ID() string                                  { return g.kid }
func (g *genKey) SignatureAlgorithm() jose.SignatureAlgorithm { return g.alg }

// The op.Key and op.SigningKey interfaces both call Key. genKey serves as a
// signing key, while publicGenKey wraps it as a published JWK.
func (g *genKey) Key() any                           { return g.priv }
func (g *genKey) Algorithm() jose.SignatureAlgorithm { return g.alg }
func (g *genKey) Use() string                        { return oidc.KeyUseSignature }

// publicGenKey exposes only the public key in the published JWKS.
type publicGenKey struct{ *genKey }

func (p *publicGenKey) Key() any { return p.pub }

// rotatingStorage keeps an ordered list of generations. Signing always uses the
// newest generation, KeySet and KeyGenerations share the same ordered view.
type rotatingStorage struct {
	op.Storage

	generations []*genKey
	// published overrides what KeySet returns, to simulate a JWKS document that
	// is out of sync with the signing side.
	published []*genKey
	// duplicatePublished, when true, publishes the same kid twice.
	duplicatePublished bool
}

func (s *rotatingStorage) SigningKey(_ context.Context) (op.SigningKey, error) {
	return s.generations[len(s.generations)-1], nil
}

func (s *rotatingStorage) SignatureAlgorithms(_ context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{s.generations[len(s.generations)-1].alg}, nil
}

func (s *rotatingStorage) activeGenerations() []*genKey {
	if s.published != nil {
		return s.published
	}
	return s.generations
}

func (s *rotatingStorage) KeySet(_ context.Context) ([]op.Key, error) {
	gens := s.activeGenerations()
	keys := make([]op.Key, 0, len(gens)+1)
	for _, g := range gens {
		keys = append(keys, &publicGenKey{g})
	}
	if s.duplicatePublished {
		keys = append(keys, &publicGenKey{gens[len(gens)-1]})
	}
	return keys, nil
}

// KeyGenerations implements op.KeyGenerations, without the artificial duplicate
// used by the JWKS document tests: the generation view itself stays consistent.
func (s *rotatingStorage) KeyGenerations(_ context.Context) ([]op.Key, error) {
	gens := s.activeGenerations()
	keys := make([]op.Key, 0, len(gens))
	for _, g := range gens {
		keys = append(keys, &publicGenKey{g})
	}
	return keys, nil
}

func signJWT(t *testing.T, g *genKey, payload string) string {
	t.Helper()
	signer, err := op.SignerFromKey(g)
	require.NoError(t, err)
	obj, err := signer.Sign([]byte(payload))
	require.NoError(t, err)
	token, err := obj.CompactSerialize()
	require.NoError(t, err)
	return token
}

// jwksTransport serves the current KeySet view over HTTP, so a rp.RemoteKeySet
// can cache it like a real relying party.
type jwksTransport struct{ storage *rotatingStorage }

func (rt *jwksTransport) RoundTrip(*http.Request) (*http.Response, error) {
	keys, err := rt.storage.KeySet(context.Background())
	if err != nil {
		return nil, err
	}
	body := op.KeysJSON(keys)
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}, nil
}

func parseJWS(t *testing.T, token string) *jose.JSONWebSignature {
	t.Helper()
	jws, err := jose.ParseSignedCompact(token,
		[]jose.SignatureAlgorithm{jose.RS256, jose.PS256, jose.ES256})
	require.NoError(t, err)
	return jws
}

const rotationPayload = `{"sub":"subject","iss":"https://issuer.example"}`

// TestKeyRotation_NormalRotation is the healthy baseline: a unique kid per
// generation, the old generation stays published during its verification
// window, and both server-side and cached relying-party verification work.
func TestKeyRotation_NormalRotation(t *testing.T) {
	old := newGenKey(t, 1, "kid-generation-1", jose.RS256)
	new := newGenKey(t, 2, "kid-generation-2", jose.RS256)
	storage := &rotatingStorage{generations: []*genKey{old, new}}

	signing, err := storage.SigningKey(context.Background())
	require.NoError(t, err)
	keys, err := storage.KeySet(context.Background())
	require.NoError(t, err)
	require.NoError(t, op.ValidateKeyGenerations(signing, keys))

	oldToken := signJWT(t, old, rotationPayload)
	newToken := signJWT(t, new, rotationPayload)

	serverKeySet := &op.OpenIDKeySet{Storage: storage}
	for name, token := range map[string]string{"old generation": oldToken, "new generation": newToken} {
		t.Run(name, func(t *testing.T) {
			payload, err := serverKeySet.VerifySignature(context.Background(), parseJWS(t, token))
			require.NoError(t, err)
			assert.JSONEq(t, rotationPayload, string(payload))
		})
	}

	// Relying party first caches the old JWKS, then the OP rotates and publishes
	// both generations during the overlap window.
	remote := rp.NewRemoteKeySet(
		&http.Client{Transport: &jwksTransport{storage: storage}},
		"https://issuer.example/keys")

	storage.published = []*genKey{old}
	_, err = remote.VerifySignature(context.Background(), parseJWS(t, oldToken))
	require.NoError(t, err)

	storage.published = nil
	for name, token := range map[string]string{
		"cached old token":         oldToken,
		"new token after rotation": newToken,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := remote.VerifySignature(context.Background(), parseJWS(t, token))
			require.NoError(t, err)
		})
	}
}

// TestKeyRotation_DuplicateKid verifies that publishing two generations with
// the same kid is rejected as ambiguous instead of silently picking one.
func TestKeyRotation_DuplicateKid(t *testing.T) {
	old := newGenKey(t, 1, "shared-kid", jose.RS256)
	new := newGenKey(t, 2, "shared-kid", jose.RS256)
	storage := &rotatingStorage{
		generations:        []*genKey{old, new},
		duplicatePublished: true,
	}

	newToken := signJWT(t, new, rotationPayload)
	_, err := (&op.OpenIDKeySet{Storage: storage}).
		VerifySignature(context.Background(), parseJWS(t, newToken))
	require.Error(t, err)
	assert.ErrorIs(t, err, oidc.ErrKeyDuplicateID)

	keys, err := storage.KeySet(context.Background())
	require.NoError(t, err)
	require.Len(t, op.JSONWebKeySet(keys).Keys, 3)

	// The shared generation validator rejects the same ambiguous JWKS up front.
	signing, err := storage.SigningKey(context.Background())
	require.NoError(t, err)
	err = op.ValidateKeyGenerations(signing, keys)
	require.Error(t, err)
	assert.ErrorIs(t, err, op.ErrKeyGeneration)
}

// TestKeyRotation_AlgConflict covers same-kid generations that change alg.
func TestKeyRotation_AlgConflict(t *testing.T) {
	// Different key families: the stale JWKS only holds the old RSA generation
	// while the new token is EC, so verification must fail loudly.
	old := newGenKey(t, 1, "shared-kid", jose.RS256)
	new := newGenKey(t, 2, "shared-kid", jose.ES256)
	storage := &rotatingStorage{generations: []*genKey{old, new}}

	newToken := signJWT(t, new, rotationPayload)
	payload, err := (&op.OpenIDKeySet{Storage: storage}).
		VerifySignature(context.Background(), parseJWS(t, newToken))
	require.NoError(t, err)
	assert.JSONEq(t, rotationPayload, string(payload))

	storage.published = []*genKey{old}
	_, err = (&op.OpenIDKeySet{Storage: storage}).
		VerifySignature(context.Background(), parseJWS(t, newToken))
	require.Error(t, err)

	// Same family (RS256 -> PS256) but an explicit JWK alg: the exact alg must
	// now be enforced instead of matching on the RSA key type alone.
	rsaOld := newGenKey(t, 3, "rsa-kid", jose.RS256)
	rsaNew := newGenKey(t, 4, "rsa-kid", jose.PS256)
	rsaStorage := &rotatingStorage{
		generations: []*genKey{rsaOld, rsaNew},
		published:   []*genKey{rsaOld},
	}
	rsaToken := signJWT(t, rsaNew, rotationPayload)
	_, err = (&op.OpenIDKeySet{Storage: rsaStorage}).
		VerifySignature(context.Background(), parseJWS(t, rsaToken))
	require.Error(t, err)
	assert.ErrorIs(t, err, oidc.ErrKeyNone)

	// With both algs published under the shared kid, exact alg matching picks
	// the PS256 generation unambiguously and verification succeeds. This is why
	// a same-kid alg rotation can still verify, as long as the JWKS is current.
	rsaStorage.published = nil
	payload, err = (&op.OpenIDKeySet{Storage: rsaStorage}).
		VerifySignature(context.Background(), parseJWS(t, rsaToken))
	require.NoError(t, err)
	assert.JSONEq(t, rotationPayload, string(payload))

	// The genuinely ambiguous case is two keys with the same kid AND the same
	// alg: no exact-alg filter can tell the generations apart.
	dupA := newGenKey(t, 5, "dup-kid", jose.RS256)
	dupB := newGenKey(t, 6, "dup-kid", jose.RS256)
	dupStorage := &rotatingStorage{
		generations:        []*genKey{dupA, dupB},
		duplicatePublished: true,
	}
	_, err = (&op.OpenIDKeySet{Storage: dupStorage}).
		VerifySignature(context.Background(), parseJWS(t, signJWT(t, dupB, rotationPayload)))
	require.Error(t, err)
	assert.ErrorIs(t, err, oidc.ErrKeyDuplicateID)
}

// TestKeyRotation_StaleClientCacheSameKid is the headline regression. Before
// the fix, a relying party whose cache held the old generation never re-fetched
// when the kid was reused, so every rotated token failed permanently.
func TestKeyRotation_StaleClientCacheSameKid(t *testing.T) {
	old := newGenKey(t, 1, "shared-kid", jose.RS256)
	new := newGenKey(t, 2, "shared-kid", jose.RS256)
	storage := &rotatingStorage{generations: []*genKey{old}}

	remote := rp.NewRemoteKeySet(
		&http.Client{Transport: &jwksTransport{storage: storage}},
		"https://issuer.example/keys")

	oldToken := signJWT(t, old, rotationPayload)
	_, err := remote.VerifySignature(context.Background(), parseJWS(t, oldToken))
	require.NoError(t, err)

	// Rotation reuses the kid; the JWKS endpoint now serves only the new generation.
	storage.generations = []*genKey{new}
	newToken := signJWT(t, new, rotationPayload)

	// With the fix, the cached exact-kid failure triggers a remote re-fetch and
	// verification succeeds against the freshly published generation.
	payload, err := remote.VerifySignature(context.Background(), parseJWS(t, newToken))
	require.NoError(t, err)
	assert.JSONEq(t, rotationPayload, string(payload))

	// Sanity check: with unique kids the same recovery already worked before.
	uniqueOld := newGenKey(t, 1, "kid-1", jose.RS256)
	uniqueNew := newGenKey(t, 2, "kid-2", jose.RS256)
	storage.generations = []*genKey{uniqueOld}
	uniqueRemote := rp.NewRemoteKeySet(
		&http.Client{Transport: &jwksTransport{storage: storage}},
		"https://issuer.example/keys")
	_, err = uniqueRemote.VerifySignature(context.Background(),
		parseJWS(t, signJWT(t, uniqueOld, rotationPayload)))
	require.NoError(t, err)

	storage.generations = []*genKey{uniqueOld, uniqueNew}
	_, err = uniqueRemote.VerifySignature(context.Background(),
		parseJWS(t, signJWT(t, uniqueNew, rotationPayload)))
	require.NoError(t, err)
}

// TestKeyRotation_SigningAndJWKSGenerationShared locks the generation
// coordination contract: the current signing kid must be published with the
// same alg, and duplicate kids are rejected.
func TestKeyRotation_SigningAndJWKSGenerationShared(t *testing.T) {
	t.Run("consistent across rotations", func(t *testing.T) {
		storage := &rotatingStorage{}
		for generation := uint64(1); generation <= 3; generation++ {
			storage.generations = append(storage.generations,
				newGenKey(t, generation, "kid-"+string(rune('0'+generation)), jose.RS256))
			signing, err := storage.SigningKey(context.Background())
			require.NoError(t, err)
			keys, err := storage.KeyGenerations(context.Background())
			require.NoError(t, err)
			require.NoError(t, op.ValidateKeyGenerations(signing, keys))
		}
	})

	t.Run("signing kid missing from JWKS", func(t *testing.T) {
		signing := newGenKey(t, 2, "kid-2", jose.RS256)
		published := []op.Key{newGenKey(t, 1, "kid-1", jose.RS256)}
		err := op.ValidateKeyGenerations(signing, published)
		require.Error(t, err)
		assert.ErrorIs(t, err, op.ErrKeyGeneration)
	})

	t.Run("alg mismatch on shared kid", func(t *testing.T) {
		signing := newGenKey(t, 2, "kid-2", jose.PS256)
		published := []op.Key{newGenKey(t, 2, "kid-2", jose.RS256)}
		err := op.ValidateKeyGenerations(signing, published)
		require.Error(t, err)
		assert.True(t, errors.Is(err, op.ErrKeyGeneration))
	})
}
