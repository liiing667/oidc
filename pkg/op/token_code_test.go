package op_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/oidc/v3/example/server/storage"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// tokenCountingStorage wraps the example storage and counts the access tokens
// actually created, so tests can assert the final number of issued tokens.
type tokenCountingStorage struct {
	*storage.Storage
	accessTokens atomic.Int64
}

func (s *tokenCountingStorage) CreateAccessToken(ctx context.Context, request op.TokenRequest) (string, time.Time, error) {
	id, exp, err := s.Storage.CreateAccessToken(ctx, request)
	if err == nil {
		s.accessTokens.Add(1)
	}
	return id, exp, err
}

func (s *tokenCountingStorage) CreateAccessAndRefreshTokens(ctx context.Context, request op.TokenRequest, currentRefreshToken string) (string, string, time.Time, error) {
	id, refreshToken, exp, err := s.Storage.CreateAccessAndRefreshTokens(ctx, request, currentRefreshToken)
	if err == nil {
		s.accessTokens.Add(1)
	}
	return id, refreshToken, exp, err
}

func (s *tokenCountingStorage) tokenCount() int64 {
	return s.accessTokens.Load()
}

func newCodeExchangeProvider(t *testing.T) (op.OpenIDProvider, *tokenCountingStorage) {
	t.Helper()
	s := &tokenCountingStorage{Storage: storage.NewStorage(storage.NewUserStore(testIssuer))}
	keySet := &op.OpenIDKeySet{Storage: s}
	provider, err := op.NewOpenIDProvider(testIssuer, testConfig, s,
		op.WithAllowInsecure(),
		op.WithAccessTokenKeySet(keySet),
		op.WithIDTokenHintKeySet(keySet),
	)
	require.NoError(t, err)
	return provider, s
}

// createAuthRequestWithCode registers a done auth request for the client with an
// S256 code challenge derived from the verifier and stores the code for it.
// It returns the auth request ID.
func createAuthRequestWithCode(t *testing.T, s *tokenCountingStorage, clientID, code, verifier string) string {
	t.Helper()
	ctx := op.ContextWithIssuer(context.Background(), testIssuer)
	challenge := sha256.Sum256([]byte(verifier))
	authReq, err := s.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID:            clientID,
		RedirectURI:         "https://example.com",
		Scopes:              oidc.SpaceDelimitedArray{oidc.ScopeOpenID},
		ResponseType:        oidc.ResponseTypeCode,
		CodeChallenge:       base64.RawURLEncoding.EncodeToString(challenge[:]),
		CodeChallengeMethod: oidc.CodeChallengeMethodS256,
	}, "id1")
	require.NoError(t, err)
	require.NoError(t, s.AuthRequestDone(authReq.GetID()))
	require.NoError(t, s.SaveAuthCode(ctx, authReq.GetID(), code))
	return authReq.GetID()
}

func codeExchangeForm(code, clientID, verifier string) url.Values {
	form := url.Values{
		"grant_type":   {string(oidc.GrantTypeCode)},
		"code":         {code},
		"redirect_uri": {"https://example.com"},
	}
	if clientID != "" {
		form.Set("client_id", clientID)
	}
	if verifier != "" {
		form.Set("code_verifier", verifier)
	}
	return form
}

// exchangeCode posts an authorization_code token request directly to the
// CodeExchange handler and returns the status code. basicAuth, when given,
// must be a username/password pair for a confidential client.
func exchangeCode(t *testing.T, provider op.OpenIDProvider, form url.Values, basicAuth ...string) (int, *oidc.AccessTokenResponse) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, testIssuer+"oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if len(basicAuth) == 2 {
		req.SetBasicAuth(basicAuth[0], basicAuth[1])
	}
	req = req.WithContext(op.ContextWithIssuer(req.Context(), testIssuer))
	rec := httptest.NewRecorder()
	op.CodeExchange(rec, req, provider)
	res := rec.Result()
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return res.StatusCode, nil
	}
	resp := new(oidc.AccessTokenResponse)
	require.NoError(t, json.NewDecoder(res.Body).Decode(resp))
	require.NotEmpty(t, resp.AccessToken)
	return res.StatusCode, resp
}

func TestCodeExchange_S256_PublicClient(t *testing.T) {
	provider, s := newCodeExchangeProvider(t)
	verifier := "correct-horse-battery-staple"
	createAuthRequestWithCode(t, s, "native", "code-s256-public", verifier)

	status, resp := exchangeCode(t, provider, codeExchangeForm("code-s256-public", "native", verifier))
	require.Equal(t, http.StatusOK, status)
	require.NotNil(t, resp)
	assert.Equal(t, int64(1), s.tokenCount())
}

func TestCodeExchange_S256_ConfidentialClient(t *testing.T) {
	provider, s := newCodeExchangeProvider(t)
	verifier := "correct-horse-battery-staple"
	createAuthRequestWithCode(t, s, "web", "code-s256-confidential", verifier)

	status, resp := exchangeCode(t, provider, codeExchangeForm("code-s256-confidential", "", verifier), "web", "secret")
	require.Equal(t, http.StatusOK, status)
	require.NotNil(t, resp)
	assert.Equal(t, int64(1), s.tokenCount())
}

func TestCodeExchange_DuplicateRedemption(t *testing.T) {
	provider, s := newCodeExchangeProvider(t)
	verifier := "correct-horse-battery-staple"
	createAuthRequestWithCode(t, s, "native", "code-duplicate", verifier)

	status, _ := exchangeCode(t, provider, codeExchangeForm("code-duplicate", "native", verifier))
	require.Equal(t, http.StatusOK, status)

	status, resp := exchangeCode(t, provider, codeExchangeForm("code-duplicate", "native", verifier))
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Nil(t, resp)
	assert.Equal(t, int64(1), s.tokenCount(), "redeeming the same code twice must not issue a second token")
}

func TestCodeExchange_WrongVerifierNotRetryable(t *testing.T) {
	provider, s := newCodeExchangeProvider(t)
	verifier := "correct-horse-battery-staple"
	createAuthRequestWithCode(t, s, "native", "code-verifier", verifier)

	status, _ := exchangeCode(t, provider, codeExchangeForm("code-verifier", "native", "wrong-verifier"))
	assert.Equal(t, http.StatusBadRequest, status)

	status, _ = exchangeCode(t, provider, codeExchangeForm("code-verifier", "native", verifier))
	assert.Equal(t, http.StatusBadRequest, status, "the failed attempt must consume the code")
	assert.Equal(t, int64(0), s.tokenCount())
}

func TestCodeExchange_WrongClient(t *testing.T) {
	provider, s := newCodeExchangeProvider(t)
	verifier := "correct-horse-battery-staple"
	createAuthRequestWithCode(t, s, "web", "code-client", verifier)

	// "api" presents its own valid credentials, but the code was issued to "web".
	status, _ := exchangeCode(t, provider, codeExchangeForm("code-client", "", verifier), "api", "secret")
	assert.Equal(t, http.StatusBadRequest, status)

	status, _ = exchangeCode(t, provider, codeExchangeForm("code-client", "", verifier), "web", "secret")
	assert.Equal(t, http.StatusBadRequest, status, "the failed attempt must consume the code")
	assert.Equal(t, int64(0), s.tokenCount())
}

func TestCodeExchange_CancelledAuthRequest(t *testing.T) {
	provider, s := newCodeExchangeProvider(t)
	verifier := "correct-horse-battery-staple"
	id := createAuthRequestWithCode(t, s, "native", "code-cancel", verifier)

	// the flow is cancelled: the pending auth request (and its code) is removed
	ctx := op.ContextWithIssuer(context.Background(), testIssuer)
	require.NoError(t, s.DeleteAuthRequest(ctx, id))

	status, _ := exchangeCode(t, provider, codeExchangeForm("code-cancel", "native", verifier))
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, int64(0), s.tokenCount())
}

func TestCodeExchange_ConcurrentRedemption(t *testing.T) {
	provider, s := newCodeExchangeProvider(t)
	verifier := "correct-horse-battery-staple"
	createAuthRequestWithCode(t, s, "native", "code-race", verifier)

	const attempts = 10
	statuses := make([]int, attempts)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range statuses {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			form := codeExchangeForm("code-race", "native", verifier)
			req := httptest.NewRequest(http.MethodPost, testIssuer+"oauth/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req = req.WithContext(op.ContextWithIssuer(req.Context(), testIssuer))
			rec := httptest.NewRecorder()
			op.CodeExchange(rec, req, provider)
			statuses[i] = rec.Result().StatusCode
		}(i)
	}
	close(start)
	wg.Wait()

	success := 0
	for _, status := range statuses {
		if status == http.StatusOK {
			success++
			continue
		}
		assert.Equal(t, http.StatusBadRequest, status)
	}
	assert.Equal(t, 1, success, "exactly one concurrent exchange may succeed")
	assert.Equal(t, int64(1), s.tokenCount())
}
