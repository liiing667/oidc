package op_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"github.com/zitadel/oidc/v3/pkg/op/mock"
)

func refreshTokenRequest(t *testing.T, form url.Values) (int, *oidc.AccessTokenResponse, *oidc.Error) {
	t.Helper()
	u, err := url.Parse(testProvider.TokenEndpoint().Absolute(testIssuer))
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, u.String(), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	testProvider.ServeHTTP(rec, req)

	resp := rec.Result()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	if resp.StatusCode != http.StatusOK {
		errResp := new(oidc.Error)
		require.NoError(t, json.Unmarshal(body, errResp))
		return resp.StatusCode, nil, errResp
	}

	tokenResp := new(oidc.AccessTokenResponse)
	require.NoError(t, json.Unmarshal(body, tokenResp))
	return resp.StatusCode, tokenResp, nil
}

func newRefreshToken(t *testing.T, scopes []string) (string, op.Client) {
	t.Helper()
	storage := testProvider.Storage().(routesTestStorage)
	ctx := op.ContextWithIssuer(context.Background(), testIssuer)

	client, err := storage.GetClientByClientID(ctx, "web")
	require.NoError(t, err)

	authReq, err := storage.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID:     client.GetID(),
		RedirectURI:  "https://example.com",
		Scopes:       oidc.SpaceDelimitedArray(scopes),
		ResponseType: oidc.ResponseTypeCode,
	}, "id1")
	require.NoError(t, err)
	storage.AuthRequestDone(authReq.GetID())

	_, refreshToken, _, err := op.CreateAccessToken(ctx, authReq, op.AccessTokenTypeBearer, testProvider, client, "")
	require.NoError(t, err)
	require.NotEmpty(t, refreshToken)
	return refreshToken, client
}

func TestRefreshTokenExchange_EndToEnd(t *testing.T) {
	originalScopes := []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess, oidc.ScopeEmail, oidc.ScopeProfile}

	t.Run("normal refresh rotates the token and invalidates the old one", func(t *testing.T) {
		refreshToken, client := newRefreshToken(t, originalScopes)

		status, tokenResp, errResp := refreshTokenRequest(t, url.Values{
			"grant_type":    {string(oidc.GrantTypeRefreshToken)},
			"refresh_token": {refreshToken},
			"client_id":     {client.GetID()},
			"client_secret": {"secret"},
		})
		require.Equal(t, http.StatusOK, status, errResp)
		require.NotEmpty(t, tokenResp.RefreshToken)
		assert.NotEqual(t, refreshToken, tokenResp.RefreshToken)
		assert.Equal(t, oidc.SpaceDelimitedArray(originalScopes).String(), strings.Join(tokenResp.Scope, " "))

		// Refresh token rotation: reusing the rotated (old) token must fail.
		status, _, errResp = refreshTokenRequest(t, url.Values{
			"grant_type":    {string(oidc.GrantTypeRefreshToken)},
			"refresh_token": {refreshToken},
			"client_id":     {client.GetID()},
			"client_secret": {"secret"},
		})
		require.Equal(t, http.StatusBadRequest, status)
		assert.ErrorIs(t, errResp, oidc.ErrInvalidGrant())

		// The freshly rotated token keeps working.
		status, tokenResp, errResp = refreshTokenRequest(t, url.Values{
			"grant_type":    {string(oidc.GrantTypeRefreshToken)},
			"refresh_token": {tokenResp.RefreshToken},
			"client_id":     {client.GetID()},
			"client_secret": {"secret"},
		})
		require.Equal(t, http.StatusOK, status, errResp)
		assert.NotEmpty(t, tokenResp.AccessToken)
	})

	t.Run("legitimate scope narrowing is accepted", func(t *testing.T) {
		refreshToken, client := newRefreshToken(t, originalScopes)

		status, tokenResp, errResp := refreshTokenRequest(t, url.Values{
			"grant_type":    {string(oidc.GrantTypeRefreshToken)},
			"refresh_token": {refreshToken},
			"scope":         {oidc.ScopeOpenID + " " + oidc.ScopeEmail},
			"client_id":     {client.GetID()},
			"client_secret": {"secret"},
		})
		require.Equal(t, http.StatusOK, status, errResp)
		assert.Equal(t, oidc.SpaceDelimitedArray{oidc.ScopeOpenID, oidc.ScopeEmail}, tokenResp.Scope)
	})

	t.Run("scope expansion is rejected", func(t *testing.T) {
		refreshToken, client := newRefreshToken(t, originalScopes)

		status, _, errResp := refreshTokenRequest(t, url.Values{
			"grant_type":    {string(oidc.GrantTypeRefreshToken)},
			"refresh_token": {refreshToken},
			"scope":         {oidc.ScopeOpenID + " " + oidc.ScopePhone},
			"client_id":     {client.GetID()},
			"client_secret": {"secret"},
		})
		require.Equal(t, http.StatusBadRequest, status)
		assert.ErrorIs(t, errResp, oidc.ErrInvalidScope())
	})

	t.Run("cross client refresh is rejected", func(t *testing.T) {
		refreshToken, _ := newRefreshToken(t, originalScopes)

		status, _, errResp := refreshTokenRequest(t, url.Values{
			"grant_type":    {string(oidc.GrantTypeRefreshToken)},
			"refresh_token": {refreshToken},
			"client_id":     {"api"},
			"client_secret": {"secret"},
		})
		require.Equal(t, http.StatusBadRequest, status)
		assert.ErrorIs(t, errResp, oidc.ErrInvalidGrant())
	})
}

// refreshExchanger wraps the real testProvider but serves a mocked Storage,
// so the refresh validation can be exercised in isolation while keeping all
// other provider behavior (decoder, supported auth methods, ...) intact.
type refreshExchanger struct {
	op.OpenIDProvider
	storage op.Storage
}

func (e *refreshExchanger) Storage() op.Storage {
	return e.storage
}

type stubRefreshTokenRequest struct {
	clientID   string
	scopes     []string
	expiration time.Time
}

func (s *stubRefreshTokenRequest) GetAMR() []string                 { return nil }
func (s *stubRefreshTokenRequest) GetAudience() []string            { return nil }
func (s *stubRefreshTokenRequest) GetAuthTime() time.Time           { return time.Now() }
func (s *stubRefreshTokenRequest) GetClientID() string              { return s.clientID }
func (s *stubRefreshTokenRequest) GetScopes() []string              { return s.scopes }
func (s *stubRefreshTokenRequest) GetSubject() string               { return "user-1" }
func (s *stubRefreshTokenRequest) SetCurrentScopes(scopes []string) { s.scopes = scopes }
func (s *stubRefreshTokenRequest) GetRefreshTokenExpiration() time.Time {
	return s.expiration
}

// refreshRequestNoExpiration does not implement RefreshTokenRequestExpiration,
// to verify backward compatible behavior for requests without expiration.
type refreshRequestNoExpiration struct {
	clientID string
	scopes   []string
}

func (s *refreshRequestNoExpiration) GetAMR() []string                 { return nil }
func (s *refreshRequestNoExpiration) GetAudience() []string            { return nil }
func (s *refreshRequestNoExpiration) GetAuthTime() time.Time           { return time.Now() }
func (s *refreshRequestNoExpiration) GetClientID() string              { return s.clientID }
func (s *refreshRequestNoExpiration) GetScopes() []string              { return s.scopes }
func (s *refreshRequestNoExpiration) GetSubject() string               { return "user-1" }
func (s *refreshRequestNoExpiration) SetCurrentScopes(scopes []string) { s.scopes = scopes }

func newRefreshMocks(t *testing.T) (*refreshExchanger, *mock.MockStorage, *mock.MockClient) {
	t.Helper()
	ctrl := gomock.NewController(t)
	storage := mock.NewMockStorage(ctrl)
	client := mock.NewMockClient(ctrl)
	client.EXPECT().AuthMethod().AnyTimes().Return(oidc.AuthMethodBasic)
	client.EXPECT().GrantTypes().AnyTimes().Return([]oidc.GrantType{oidc.GrantTypeRefreshToken})
	return &refreshExchanger{OpenIDProvider: testProvider, storage: storage}, storage, client
}

func TestValidateRefreshTokenRequest(t *testing.T) {
	const (
		clientID     = "web_client"
		otherClient  = "other_client"
		refreshToken = "refresh-token"
	)
	originalScopes := []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess, oidc.ScopeEmail, oidc.ScopeProfile}

	tests := []struct {
		name        string
		tokenReq    *oidc.RefreshTokenRequest
		authRequest op.RefreshTokenRequest
		clientID    string
		clockSkew   time.Duration
		wantErr     error
		wantScopes  []string
	}{
		{
			name: "missing refresh token",
			tokenReq: &oidc.RefreshTokenRequest{
				ClientID:     clientID,
				ClientSecret: "secret",
			},
			wantErr: oidc.ErrInvalidRequest(),
		},
		{
			name: "normal refresh keeps original scopes",
			tokenReq: &oidc.RefreshTokenRequest{
				RefreshToken: refreshToken,
				ClientID:     clientID,
				ClientSecret: "secret",
			},
			authRequest: &stubRefreshTokenRequest{
				clientID:   clientID,
				scopes:     originalScopes,
				expiration: time.Now().Add(time.Hour),
			},
			clientID:   clientID,
			wantScopes: originalScopes,
		},
		{
			name: "legitimate scope narrowing",
			tokenReq: &oidc.RefreshTokenRequest{
				RefreshToken: refreshToken,
				Scopes:       oidc.SpaceDelimitedArray{oidc.ScopeOpenID, oidc.ScopeEmail},
				ClientID:     clientID,
				ClientSecret: "secret",
			},
			authRequest: &stubRefreshTokenRequest{
				clientID:   clientID,
				scopes:     originalScopes,
				expiration: time.Now().Add(time.Hour),
			},
			clientID:   clientID,
			wantScopes: []string{oidc.ScopeOpenID, oidc.ScopeEmail},
		},
		{
			name: "scope expansion rejected",
			tokenReq: &oidc.RefreshTokenRequest{
				RefreshToken: refreshToken,
				Scopes:       oidc.SpaceDelimitedArray{oidc.ScopeOpenID, oidc.ScopePhone},
				ClientID:     clientID,
				ClientSecret: "secret",
			},
			authRequest: &stubRefreshTokenRequest{
				clientID:   clientID,
				scopes:     originalScopes,
				expiration: time.Now().Add(time.Hour),
			},
			clientID: clientID,
			wantErr:  oidc.ErrInvalidScope(),
		},
		{
			name: "cross client refresh rejected",
			tokenReq: &oidc.RefreshTokenRequest{
				RefreshToken: refreshToken,
				ClientID:     otherClient,
				ClientSecret: "secret",
			},
			authRequest: &stubRefreshTokenRequest{
				clientID:   clientID,
				scopes:     originalScopes,
				expiration: time.Now().Add(time.Hour),
			},
			clientID: otherClient,
			wantErr:  oidc.ErrInvalidGrant(),
		},
		{
			name: "expired refresh token rejected",
			tokenReq: &oidc.RefreshTokenRequest{
				RefreshToken: refreshToken,
				ClientID:     clientID,
				ClientSecret: "secret",
			},
			authRequest: &stubRefreshTokenRequest{
				clientID:   clientID,
				scopes:     originalScopes,
				expiration: time.Now().Add(-time.Minute),
			},
			clientID: clientID,
			wantErr:  oidc.ErrInvalidGrant(),
		},
		{
			name: "expiration within clock skew accepted",
			tokenReq: &oidc.RefreshTokenRequest{
				RefreshToken: refreshToken,
				ClientID:     clientID,
				ClientSecret: "secret",
			},
			authRequest: &stubRefreshTokenRequest{
				clientID:   clientID,
				scopes:     originalScopes,
				expiration: time.Now().Add(-30 * time.Second),
			},
			clientID:   clientID,
			clockSkew:  time.Minute,
			wantScopes: originalScopes,
		},
		{
			name: "zero expiration is not evaluated",
			tokenReq: &oidc.RefreshTokenRequest{
				RefreshToken: refreshToken,
				ClientID:     clientID,
				ClientSecret: "secret",
			},
			authRequest: &stubRefreshTokenRequest{
				clientID: clientID,
				scopes:   originalScopes,
			},
			clientID:   clientID,
			wantScopes: originalScopes,
		},
		{
			name: "request without expiration interface stays compatible",
			tokenReq: &oidc.RefreshTokenRequest{
				RefreshToken: refreshToken,
				ClientID:     clientID,
				ClientSecret: "secret",
			},
			authRequest: &refreshRequestNoExpiration{
				clientID: clientID,
				scopes:   originalScopes,
			},
			clientID:   clientID,
			wantScopes: originalScopes,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exchanger, storage, client := newRefreshMocks(t)
			ctx := context.Background()

			if tt.tokenReq.RefreshToken != "" {
				client.EXPECT().GetID().AnyTimes().Return(tt.clientID)
				client.EXPECT().ClockSkew().AnyTimes().Return(tt.clockSkew)
				storage.EXPECT().GetClientByClientID(gomock.Any(), tt.clientID).Return(client, nil)
				storage.EXPECT().AuthorizeClientIDSecret(gomock.Any(), tt.clientID, "secret").Return(nil)
				storage.EXPECT().TokenRequestByRefreshToken(gomock.Any(), refreshToken).
					Return(tt.authRequest, nil)
			}

			request, gotClient, err := op.ValidateRefreshTokenRequest(ctx, tt.tokenReq, exchanger)
			if tt.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
				assert.Nil(t, request)
				assert.Nil(t, gotClient)
				return
			}
			require.NoError(t, err)
			assert.Same(t, client, gotClient)
			assert.Equal(t, tt.wantScopes, request.GetScopes())
		})
	}
}

func TestValidateRefreshTokenScopes(t *testing.T) {
	originalScopes := []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess, oidc.ScopeEmail}

	tests := []struct {
		name            string
		requestedScopes []string
		wantErr         error
		wantScopes      []string
	}{
		{
			name:            "empty request keeps original scopes",
			requestedScopes: nil,
			wantScopes:      originalScopes,
		},
		{
			name:            "subset scopes accepted",
			requestedScopes: []string{oidc.ScopeOpenID, oidc.ScopeEmail},
			wantScopes:      []string{oidc.ScopeOpenID, oidc.ScopeEmail},
		},
		{
			name:            "unknown scope rejected",
			requestedScopes: []string{oidc.ScopeOpenID, oidc.ScopePhone},
			wantErr:         oidc.ErrInvalidScope(),
			wantScopes:      originalScopes,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := &stubRefreshTokenRequest{
				clientID: "web_client",
				scopes:   originalScopes,
			}
			err := op.ValidateRefreshTokenScopes(tt.requestedScopes, request)
			if tt.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.wantScopes, request.GetScopes())
		})
	}
}
