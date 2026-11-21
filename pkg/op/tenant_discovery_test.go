package op_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/oidc/v3/example/server/storage"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// newTenantProvider builds a LegacyServer whose issuer follows the
// request host and the tenant on the context, as WithTenantPrefix sets it.
func newTenantProvider(t *testing.T, prefix string) http.Handler {
	t.Helper()
	store := storage.NewStorage(storage.NewUserStore("https://op.example.com/"))
	provider, err := op.NewProvider(
		&op.Config{CryptoKey: [32]byte{}, DefaultLogoutRedirectURI: "/logged-out"},
		store,
		op.IssuerFromPath(prefix),
		op.WithAllowInsecure(),
	)
	require.NoError(t, err)
	return op.RegisterLegacyServer(
		op.NewLegacyServer(provider, *op.DefaultEndpoints),
		op.AuthorizeCallbackHandler(provider),
		op.WithTenantPrefix(prefix),
	)
}

func getDiscovery(t *testing.T, h http.Handler, target string) (int, *oidc.DiscoveryConfiguration) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Host = "op.example.com"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		return rec.Code, nil
	}
	config := new(oidc.DiscoveryConfiguration)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), config))
	return rec.Code, config
}

// TestLegacyServer_tenantDiscoveryIsolation is the regression for a
// metadata leak across tenants: the discovery of one tenant must name
// that tenant's issuer and endpoints, never those of another tenant or
// of the empty tenant.
func TestLegacyServer_tenantDiscoveryIsolation(t *testing.T) {
	h := newTenantProvider(t, "/oauth")

	tenants := map[string]string{
		"p1": "http://op.example.com/oauth/p1",
		"p2": "http://op.example.com/oauth/p2",
	}
	for tenant, issuer := range tenants {
		t.Run("tenant "+tenant, func(t *testing.T) {
			status, config := getDiscovery(t, h, "/oauth/"+tenant+"/.well-known/openid-configuration")
			require.Equal(t, http.StatusOK, status)
			assert.Equal(t, issuer, config.Issuer)
			assert.Equal(t, issuer+"/authorize", config.AuthorizationEndpoint)
			assert.Equal(t, issuer+"/oauth/token", config.TokenEndpoint)
			assert.Equal(t, issuer+"/keys", config.JwksURI)
			assert.Equal(t, issuer+"/userinfo", config.UserinfoEndpoint)
		})
	}

	t.Run("empty tenant keeps the platform issuer", func(t *testing.T) {
		const issuer = "http://op.example.com/oauth"
		status, config := getDiscovery(t, h, "/oauth/.well-known/openid-configuration")
		require.Equal(t, http.StatusOK, status)
		assert.Equal(t, issuer, config.Issuer)
		assert.Equal(t, issuer+"/authorize", config.AuthorizationEndpoint)
	})

	t.Run("a tenant switch changes the issuer", func(t *testing.T) {
		_, first := getDiscovery(t, h, "/oauth/p1/.well-known/openid-configuration")
		_, second := getDiscovery(t, h, "/oauth/p2/.well-known/openid-configuration")
		require.NotNil(t, first)
		require.NotNil(t, second)
		assert.NotEqual(t, first.Issuer, second.Issuer)
		assert.NotEqual(t, first.TokenEndpoint, second.TokenEndpoint)
	})

	t.Run("encoded tenant is decoded and keeps its origin", func(t *testing.T) {
		status, config := getDiscovery(t, h, "/oauth/p%31/.well-known/openid-configuration")
		require.Equal(t, http.StatusOK, status)
		assert.Equal(t, "http://op.example.com/oauth/p1", config.Issuer)
	})

	t.Run("encoded slash is still a 404, not another tenant", func(t *testing.T) {
		status, _ := getDiscovery(t, h, "/oauth/p%2F1/.well-known/openid-configuration")
		assert.Equal(t, http.StatusNotFound, status)
	})

	t.Run("trailing slash is still a 404, not another tenant", func(t *testing.T) {
		status, _ := getDiscovery(t, h, "/oauth/p1/.well-known/openid-configuration/")
		assert.Equal(t, http.StatusNotFound, status)
	})
}

// TestLegacyServer_tenantDiscoveryWithoutPrefix covers tenants directly
// under the host, WithTenantPrefix("").
func TestLegacyServer_tenantDiscoveryWithoutPrefix(t *testing.T) {
	h := newTenantProvider(t, "")

	status, config := getDiscovery(t, h, "/p1/.well-known/openid-configuration")
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, "http://op.example.com/p1", config.Issuer)
	assert.Equal(t, "http://op.example.com/p1/authorize", config.AuthorizationEndpoint)

	status, config = getDiscovery(t, h, "/.well-known/openid-configuration")
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, "http://op.example.com", config.Issuer)
}

// TestLegacyServer_singleTenantRoutesStayIntact makes sure the tenant
// aware issuer does not change requests a single-tenant provider serves.
func TestLegacyServer_singleTenantRoutesStayIntact(t *testing.T) {
	h := newTenantProvider(t, "/oauth")

	req := httptest.NewRequest(http.MethodGet, "/oauth/p1/healthz", nil)
	req.Host = "op.example.com"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	// A route outside the prefix is refused by the tenant router.
	req = httptest.NewRequest(http.MethodGet, "/authorize", nil)
	req.Host = "op.example.com"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}
