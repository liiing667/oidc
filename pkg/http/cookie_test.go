package http

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testCookieKey = []byte("test1234test1234test1234test1234")

func newTestHandler(t *testing.T, opts ...CookieHandlerOpt) *CookieHandler {
	t.Helper()
	return NewCookieHandler(testCookieKey, testCookieKey, opts...)
}

func setRequest(t *testing.T, method, target string) *http.Request {
	t.Helper()
	return httptest.NewRequest(method, target, nil)
}

func setAndRead(t *testing.T, handler *CookieHandler, setReq, readReq *http.Request, name, value string) (string, error) {
	t.Helper()
	rec := httptest.NewRecorder()
	if handler.IsRequestAware() {
		require.NoError(t, handler.SetRequestAwareCookie(setReq, rec, name, value))
	} else {
		require.NoError(t, handler.SetCookie(setReq, rec, name, value))
	}

	for _, cookie := range rec.Result().Cookies() {
		readReq.AddCookie(cookie)
	}
	return handler.CheckCookie(readReq, name)
}

// A cookie set on an origin is readable again on the very same origin,
// including the query-state comparison used by the OIDC state flow.
func TestCookieHandler_OriginBoundRoundTrip(t *testing.T) {
	handler := newTestHandler(t, WithUnsecure())
	const name, value = "state", "state-value"

	setReq := setRequest(t, http.MethodGet, "http://app.example.com/login")
	rec := httptest.NewRecorder()
	require.NoError(t, handler.SetCookie(setReq, rec, name, value))

	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 1)
	cookie := cookies[0]
	assert.Equal(t, name, cookie.Name)
	// Host-only: no Domain attribute, so the browser never sends the
	// cookie to another host.
	assert.Empty(t, cookie.Domain)
	assert.Equal(t, "/", cookie.Path)
	assert.True(t, cookie.HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
	assert.False(t, cookie.Secure)

	readReq := setRequest(t, http.MethodGet, "http://app.example.com/callback?"+name+"="+value)
	readReq.AddCookie(cookie)

	got, err := handler.CheckCookie(readReq, name)
	require.NoError(t, err)
	assert.Equal(t, value, got)

	got, err = handler.CheckQueryCookie(readReq, name)
	require.NoError(t, err)
	assert.Equal(t, value, got)
}

// DeleteCookie must emit an expired replacement cookie with the same path so
// that the browser actually removes the origin-bound cookie.
func TestCookieHandler_DeleteCookie(t *testing.T) {
	handler := newTestHandler(t, WithUnsecure())
	rec := httptest.NewRecorder()

	handler.DeleteCookie(rec, "state")

	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 1)
	cookie := cookies[0]
	assert.Equal(t, "state", cookie.Name)
	assert.Equal(t, -1, cookie.MaxAge)
	assert.Equal(t, "/", cookie.Path)
	assert.Empty(t, cookie.Domain)
}

// A cookie issued for one host must not be accepted when the same request is
// presented to another host, even though both may receive it through a
// misconfigured or attacker-controlled Domain scope.
func TestCookieHandler_RejectsCrossHost(t *testing.T) {
	handler := newTestHandler(t, WithUnsecure())

	setReq := setRequest(t, http.MethodGet, "http://app.example.com/login")
	readReq := setRequest(t, http.MethodGet, "http://evil.example.com/callback")

	_, err := setAndRead(t, handler, setReq, readReq, "state", "secret")
	require.ErrorIs(t, err, ErrCookieOriginMismatch)
}

// A cookie set over HTTPS must not be usable on a plain-HTTP request to the
// same host. This blocks a downgrade attack where traffic is forced onto
// HTTP and the (still transmitted) cookie is replayed.
func TestCookieHandler_RejectsSchemeDowngrade(t *testing.T) {
	handler := newTestHandler(t)

	setReq := setRequest(t, http.MethodGet, "https://app.example.com/login")
	readReq := setRequest(t, http.MethodGet, "http://app.example.com/callback")

	_, err := setAndRead(t, handler, setReq, readReq, "state", "secret")
	require.ErrorIs(t, err, ErrCookieOriginMismatch)
}

// And the inverse: an HTTP-issued cookie is not accepted over HTTPS either.
func TestCookieHandler_RejectsSchemeUpgrade(t *testing.T) {
	handler := newTestHandler(t, WithUnsecure())

	setReq := setRequest(t, http.MethodGet, "http://app.example.com/login")
	readReq := setRequest(t, http.MethodGet, "https://app.example.com/callback")

	_, err := setAndRead(t, handler, setReq, readReq, "state", "secret")
	require.ErrorIs(t, err, ErrCookieOriginMismatch)
}

// securecookie embeds a timestamp and rejects values older than MaxAge,
// so an expired session cookie can no longer be decoded.
func TestCookieHandler_RejectsExpiredCookie(t *testing.T) {
	handler := newTestHandler(t, WithUnsecure(), WithMaxAge(1))

	setReq := setRequest(t, http.MethodGet, "http://app.example.com/login")
	rec := httptest.NewRecorder()
	require.NoError(t, handler.SetCookie(setReq, rec, "state", "secret"))

	// securecookie timestamps have second resolution; sleep past two full
	// ticks so the value is guaranteed to be older than the one-second MaxAge.
	time.Sleep(2100 * time.Millisecond)

	readReq := setRequest(t, http.MethodGet, "http://app.example.com/callback")
	for _, cookie := range rec.Result().Cookies() {
		readReq.AddCookie(cookie)
	}
	_, err := handler.CheckCookie(readReq, "state")
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrCookieOriginMismatch)
}

// When an attacker injects a second cookie with the same name (e.g. via a
// parent-domain cookie), the request is ambiguous and must be rejected
// instead of silently using either value.
func TestCookieHandler_RejectsDuplicateCookies(t *testing.T) {
	handler := newTestHandler(t, WithUnsecure())
	const name = "state"

	setReq := setRequest(t, http.MethodGet, "http://app.example.com/login")
	rec := httptest.NewRecorder()
	require.NoError(t, handler.SetCookie(setReq, rec, name, "legitimate"))
	legitCookie := rec.Result().Cookies()[0]

	// A second, separately encoded value that passes crypto checks but is
	// distinct from the legitimate one.
	rec2 := httptest.NewRecorder()
	require.NoError(t, handler.SetCookie(setReq, rec2, name, "injected"))
	injectedCookie := rec2.Result().Cookies()[0]

	readReq := setRequest(t, http.MethodGet, "http://app.example.com/callback")
	readReq.AddCookie(legitCookie)
	readReq.AddCookie(injectedCookie)

	_, err := handler.CheckCookie(readReq, name)
	require.ErrorIs(t, err, ErrDuplicateCookie)
}

// A missing cookie surfaces the standard net/http no-cookie error.
func TestCookieHandler_MissingCookie(t *testing.T) {
	handler := newTestHandler(t, WithUnsecure())
	readReq := setRequest(t, http.MethodGet, "http://app.example.com/callback")

	_, err := handler.CheckCookie(readReq, "state")
	require.ErrorIs(t, err, http.ErrNoCookie)
}

// Origin binding also applies to request-aware handlers, whose securecookie
// instance is derived per request.
func TestRequestAwareCookieHandler_OriginBound(t *testing.T) {
	handler := NewRequestAwareCookieHandler(
		func(*http.Request) (*securecookie.SecureCookie, error) {
			return securecookie.New(testCookieKey, testCookieKey), nil
		},
		WithUnsecure(),
	)

	t.Run("same origin succeeds", func(t *testing.T) {
		setReq := setRequest(t, http.MethodGet, "http://app.example.com/login")
		readReq := setRequest(t, http.MethodGet, "http://app.example.com/callback")
		value, err := setAndRead(t, handler, setReq, readReq, "pkce", "verifier")
		require.NoError(t, err)
		assert.Equal(t, "verifier", value)
	})

	t.Run("cross host rejected", func(t *testing.T) {
		setReq := setRequest(t, http.MethodGet, "http://app.example.com/login")
		readReq := setRequest(t, http.MethodGet, "http://evil.example.com/callback")
		_, err := setAndRead(t, handler, setReq, readReq, "pkce", "verifier")
		require.ErrorIs(t, err, ErrCookieOriginMismatch)
	})

	t.Run("duplicate rejected", func(t *testing.T) {
		const name = "pkce"
		setReq := setRequest(t, http.MethodGet, "http://app.example.com/login")

		rec := httptest.NewRecorder()
		require.NoError(t, handler.SetRequestAwareCookie(setReq, rec, name, "one"))
		rec2 := httptest.NewRecorder()
		require.NoError(t, handler.SetRequestAwareCookie(setReq, rec2, name, "two"))

		readReq := setRequest(t, http.MethodGet, "http://app.example.com/callback")
		readReq.AddCookie(rec.Result().Cookies()[0])
		readReq.AddCookie(rec2.Result().Cookies()[0])

		_, err := handler.CheckCookie(readReq, name)
		require.ErrorIs(t, err, ErrDuplicateCookie)
	})

	t.Run("request-aware func error propagated", func(t *testing.T) {
		wantErr := errors.New("no session")
		failing := NewRequestAwareCookieHandler(
			func(*http.Request) (*securecookie.SecureCookie, error) {
				return nil, wantErr
			},
			WithUnsecure(),
		)
		readReq := setRequest(t, http.MethodGet, "http://app.example.com/callback")
		readReq.AddCookie(&http.Cookie{Name: "pkce", Value: "whatever"})
		_, err := failing.CheckCookie(readReq, "pkce")
		require.ErrorIs(t, err, wantErr)
	})
}

// A terminating TLS proxy is supported via the standard X-Forwarded-Proto
// header: set and read on the same forwarded origin succeed.
func TestCookieHandler_ForwardedProto(t *testing.T) {
	handler := newTestHandler(t)

	setReq := setRequest(t, http.MethodGet, "https://app.example.com/login")
	setReq.Header.Set("X-Forwarded-Proto", "https")
	readReq := setRequest(t, http.MethodGet, "http://app.example.com/callback")
	readReq.Header.Set("X-Forwarded-Proto", "https")

	value, err := setAndRead(t, handler, setReq, readReq, "state", "secret")
	require.NoError(t, err)
	assert.Equal(t, "secret", value)
}

// End-to-end check on a real TLS listener: a cookie set by the HTTPS server
// is accepted on another HTTPS request to the same host but rejected when the
// identical cookie is presented over plain HTTP.
func TestCookieHandler_TLSDowngradeOnRealServer(t *testing.T) {
	handler := newTestHandler(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, handler.SetCookie(r, w, "state", "secret"))
	})
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		value, err := handler.CheckCookie(r, "state")
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(value))
	})

	server := httptest.NewTLSServer(mux)
	defer server.Close()

	client := server.Client()

	loginResp, err := client.Get(server.URL + "/login")
	require.NoError(t, err)
	require.NoError(t, loginResp.Body.Close())
	require.Len(t, loginResp.Cookies(), 1)
	cookie := loginResp.Cookies()[0]
	assert.True(t, cookie.Secure)
	assert.Empty(t, cookie.Domain)

	// Same origin over HTTPS: accepted.
	req, err := http.NewRequest(http.MethodGet, server.URL+"/callback", nil)
	require.NoError(t, err)
	req.AddCookie(cookie)
	okResp, err := client.Do(req)
	require.NoError(t, err)
	require.NoError(t, okResp.Body.Close())
	assert.Equal(t, http.StatusOK, okResp.StatusCode)

	// Downgrade to plain HTTP on the same host: rejected. The httptest TLS
	// server only speaks TLS, so build the request manually and call the
	// handler with a non-TLS request carrying the same cookie.
	httpReq := httptest.NewRequest(http.MethodGet, "http://"+req.URL.Host+"/callback", nil)
	httpReq.AddCookie(cookie)
	_, err = handler.CheckCookie(httpReq, "state")
	require.ErrorIs(t, err, ErrCookieOriginMismatch)
}
