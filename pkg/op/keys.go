package op

import (
	"context"
	"encoding/json"
	"net/http"

	jose "github.com/go-jose/go-jose/v4"

	httphelper "github.com/zitadel/oidc/v3/pkg/http"
)

type KeyProvider interface {
	KeySet(context.Context) ([]Key, error)
}

func keysHandler(k KeyProvider) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		Keys(w, r, k)
	}
}

func Keys(w http.ResponseWriter, r *http.Request, k KeyProvider) {
	ctx, span := Tracer.Start(r.Context(), "Keys")
	r = r.WithContext(ctx)
	defer span.End()

	keySet, err := k.KeySet(r.Context())
	if err != nil {
		httphelper.MarshalJSONWithStatus(w, err, http.StatusInternalServerError)
		return
	}
	httphelper.MarshalJSON(w, jsonWebKeySet(keySet))
}

func jsonWebKeySet(keys []Key) *jose.JSONWebKeySet {
	webKeys := make([]jose.JSONWebKey, len(keys))
	for i, key := range keys {
		webKeys[i] = jose.JSONWebKey{
			KeyID:     key.ID(),
			Algorithm: string(key.Algorithm()),
			Use:       key.Use(),
			Key:       key.Key(),
		}
	}
	return &jose.JSONWebKeySet{Keys: webKeys}
}

// JSONWebKeySet converts the OP [Key] list into a [jose.JSONWebKeySet].
// It uses exactly the same mapping as the /keys endpoint, so callers can
// rely on the same kid, alg and use values that are published to relying
// parties.
func JSONWebKeySet(keys []Key) *jose.JSONWebKeySet {
	return jsonWebKeySet(keys)
}

// KeysJSON serializes the OP [Key] list into the JSON document that the
// /keys endpoint publishes as a JWKS.
func KeysJSON(keys []Key) string {
	body, err := json.Marshal(jsonWebKeySet(keys))
	if err != nil {
		panic(err)
	}
	return string(body)
}
