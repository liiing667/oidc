package rp

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tu "github.com/zitadel/oidc/v3/internal/testutil"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func TestJsonWebKeySet_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name       string
		jsonData   string
		wantKeyLen int
		wantErr    bool
		errPrefix  string
	}{
		{
			name:       "valid key set",
			jsonData:   `{"keys":[{"kty":"RSA","use":"sig","kid":"key1","alg":"RS256","n":"n-value","e":"e-value"}]}`,
			wantKeyLen: 1,
			wantErr:    false,
		},
		{
			name:       "empty key set",
			jsonData:   `{"keys":[]}`,
			wantKeyLen: 0,
			wantErr:    false,
		},
		{
			name:       "unknown key type",
			jsonData:   `{"keys":[{"kty":"UNKNOWN","use":"sig","kid":"key1"}]}`,
			wantKeyLen: 0,
			wantErr:    false,
		},
		{
			name:       "mixed valid and unknown key types",
			jsonData:   `{"keys":[{"kty":"RSA","use":"sig","kid":"key1","alg":"RS256","n":"n-value","e":"e-value"},{"kty":"UNKNOWN","use":"sig","kid":"key2"}]}`,
			wantKeyLen: 1,
			wantErr:    false,
		},
		{
			name:       "invalid json",
			jsonData:   `{"keys":[{]`,
			wantKeyLen: 0,
			wantErr:    true,
			errPrefix:  "oidc: failed to unmarshall key set: ",
		},
		{
			name:       "other error during key unmarshal",
			jsonData:   `{"keys":[{"kty":"RSA","use":"sig","kid":"key1","alg":"RS256"}]}`,
			wantKeyLen: 0,
			wantErr:    true,
			errPrefix:  "oidc: failed to unmarshal key 0 from set: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var keySet jsonWebKeySet
			err := keySet.UnmarshalJSON([]byte(tt.jsonData))

			if tt.wantErr {
				assert.Error(t, err)
				assert.NotErrorIs(t, err, jose.ErrUnsupportedKeyType)
				assert.True(t, strings.HasPrefix(err.Error(), tt.errPrefix))

			} else {
				assert.NoError(t, err)
				assert.Len(t, keySet.Keys, tt.wantKeyLen)
			}
		})
	}
}

func TestRemoteKeySet_VerifySignature_WrapsFetchError(t *testing.T) {
	errTransport := errors.New("connection refused")

	tests := []struct {
		name      string
		transport roundTripFunc
		wantErr   error
	}{
		{
			name: "transport error",
			transport: func(*http.Request) (*http.Response, error) {
				return nil, errTransport
			},
			wantErr: errTransport,
		},
		{
			name: "response too large",
			transport: func(r *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(strings.Repeat(" ", int(httphelper.MaxResponseBodySize)+1))),
					Request:    r,
				}, nil
			},
			wantErr: httphelper.ErrResponseBodyTooLarge,
		},
		{
			name: "oauth error response",
			transport: func(r *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusServiceUnavailable,
					Body:       io.NopCloser(strings.NewReader(`{"error":"server_error","error_description":"key store unavailable"}`)),
					Request:    r,
				}, nil
			},
			wantErr: &oidc.Error{ErrorType: oidc.ServerError, Description: "key store unavailable"},
		},
	}

	payload, err := tu.Signer.Sign([]byte(`{"sub":"subject"}`))
	require.NoError(t, err)
	token, err := payload.CompactSerialize()
	require.NoError(t, err)
	jws, err := jose.ParseSignedCompact(token, []jose.SignatureAlgorithm{tu.SignatureAlgorithm})
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keySet := NewRemoteKeySet(&http.Client{Transport: tt.transport}, "https://example.com/keys")
			_, err := keySet.VerifySignature(context.Background(), jws)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestRemoteKeySet_RefetchesOnReusedKid(t *testing.T) {
	// Two generations that intentionally share the same kid. The relying party
	// first caches the old generation; after rotation the JWKS endpoint serves
	// only the new generation. Verification must re-fetch instead of failing on
	// the stale cache entry, because both JWKs advertise an explicit alg.
	oldKey, newKey := mustRSAKey(t, 2048), mustRSAKey(t, 2048)

	sign := func(key *rsa.PrivateKey) *jose.JSONWebSignature {
		signer, err := jose.NewSigner(jose.SigningKey{
			Algorithm: jose.RS256,
			Key:       &jose.JSONWebKey{Key: key, KeyID: "shared-kid", Algorithm: string(jose.RS256)},
		}, nil)
		require.NoError(t, err)
		object, err := signer.Sign([]byte(`{"sub":"subject"}`))
		require.NoError(t, err)
		compact, err := object.CompactSerialize()
		require.NoError(t, err)
		jws, err := jose.ParseSignedCompact(compact, []jose.SignatureAlgorithm{jose.RS256})
		require.NoError(t, err)
		return jws
	}

	jwksBody := func(key *rsa.PrivateKey) string {
		jwk := jose.JSONWebKey{
			Key:       &key.PublicKey,
			KeyID:     "shared-kid",
			Algorithm: string(jose.RS256),
			Use:       oidc.KeyUseSignature,
		}
		body, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
		require.NoError(t, err)
		return string(body)
	}

	var currentBody string
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(currentBody)),
			Request:    &http.Request{URL: mustParseURL(t, "https://example.com/keys")},
		}, nil
	})

	keySet := NewRemoteKeySet(&http.Client{Transport: transport}, "https://example.com/keys")

	// Prime the cache with generation 1.
	currentBody = jwksBody(oldKey)
	_, err := keySet.VerifySignature(context.Background(), sign(oldKey))
	require.NoError(t, err)

	// Rotate to generation 2 while reusing the kid and update the endpoint.
	currentBody = jwksBody(newKey)
	payload, err := keySet.VerifySignature(context.Background(), sign(newKey))
	require.NoError(t, err)
	assert.JSONEq(t, `{"sub":"subject"}`, string(payload))
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	require.NoError(t, err)
	return parsed
}
