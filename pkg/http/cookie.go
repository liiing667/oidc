package http

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/securecookie"
)

var (
	// ErrCookieOriginMismatch is returned when a cookie was issued for a
	// different origin (scheme and host) than the current request.
	ErrCookieOriginMismatch = errors.New("cookie origin does not match the request origin")

	// ErrDuplicateCookie is returned when more than one cookie with the
	// same name is sent in a request. Only a single, unambiguous cookie
	// is accepted.
	ErrDuplicateCookie = errors.New("multiple cookies with the same name")
)

// originBoundValue wraps the actual cookie value together with the origin
// (scheme and host) of the request that set the cookie. Because the payload
// is authenticated and encrypted by securecookie, an attacker cannot forge
// or alter the embedded origin. It is only accepted again when the reading
// request uses the same origin.
type originBoundValue struct {
	Origin string
	Value  string
}

type CookieHandler struct {
	securecookie     *securecookie.SecureCookie
	secureCookieFunc func(r *http.Request) (*securecookie.SecureCookie, error)
	secureOnly       bool
	sameSite         http.SameSite
	maxAge           int
	path             string
}

func NewCookieHandler(hashKey, encryptKey []byte, opts ...CookieHandlerOpt) *CookieHandler {
	c := &CookieHandler{
		securecookie: securecookie.New(hashKey, encryptKey),
		secureOnly:   true,
		sameSite:     http.SameSiteLaxMode,
		path:         "/",
	}

	for _, opt := range opts {
		opt(c)
	}
	return c
}

func NewRequestAwareCookieHandler(secureCookieFunc func(r *http.Request) (*securecookie.SecureCookie, error), opts ...CookieHandlerOpt) *CookieHandler {
	c := &CookieHandler{
		secureCookieFunc: secureCookieFunc,
		secureOnly:       true,
		sameSite:         http.SameSiteLaxMode,
		path:             "/",
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

type CookieHandlerOpt func(*CookieHandler)

func WithUnsecure() CookieHandlerOpt {
	return func(c *CookieHandler) {
		c.secureOnly = false
	}
}

func WithSameSite(sameSite http.SameSite) CookieHandlerOpt {
	return func(c *CookieHandler) {
		c.sameSite = sameSite
	}
}

func WithMaxAge(maxAge int) CookieHandlerOpt {
	return func(c *CookieHandler) {
		c.maxAge = maxAge
		if c.IsRequestAware() {
			return
		}

		c.securecookie.MaxAge(maxAge)
	}
}

// WithDomain is retained for source compatibility. Cookies are now issued
// as host-only cookies and cryptographically bound to the request origin,
// so an explicit Domain attribute would re-introduce cross-host sharing.
// The option is therefore a no-op.
//
// Deprecated: origin-bound, host-only cookies are always used.
func WithDomain(string) CookieHandlerOpt {
	return func(*CookieHandler) {}
}

func WithPath(path string) CookieHandlerOpt {
	return func(c *CookieHandler) {
		c.path = path
	}
}

// requestOrigin returns the origin (scheme and host) the request is served
// on. The scheme is derived from the actual connection (TLS) or the
// standard X-Forwarded-Proto header set by a trusted terminating proxy.
// The host is taken from the request Host header, which is always the
// host the client targeted.
func requestOrigin(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if forwardedProto := r.Header.Get("X-Forwarded-Proto"); forwardedProto != "" {
		if idx := strings.IndexByte(forwardedProto, ','); idx >= 0 {
			forwardedProto = forwardedProto[:idx]
		}
		if forwardedProto = strings.TrimSpace(forwardedProto); forwardedProto != "" {
			scheme = forwardedProto
		}
	}
	return scheme + "://" + r.Host
}

func (c *CookieHandler) CheckCookie(r *http.Request, name string) (string, error) {
	cookies := r.CookiesNamed(name)
	if len(cookies) == 0 {
		return "", http.ErrNoCookie
	}
	if len(cookies) > 1 {
		return "", fmt.Errorf("%w: %s", ErrDuplicateCookie, name)
	}

	secureCookie := c.securecookie
	if c.IsRequestAware() {
		var err error
		secureCookie, err = c.secureCookieFunc(r)
		if err != nil {
			return "", err
		}
	}

	var bound originBoundValue
	if err := secureCookie.Decode(name, cookies[0].Value, &bound); err != nil {
		return "", err
	}
	if bound.Origin != requestOrigin(r) {
		return "", fmt.Errorf("%w: cookie issued for %q, request origin %q",
			ErrCookieOriginMismatch, bound.Origin, requestOrigin(r))
	}
	return bound.Value, nil
}

func (c *CookieHandler) CheckQueryCookie(r *http.Request, name string) (string, error) {
	value, err := c.CheckCookie(r, name)
	if err != nil {
		return "", err
	}
	if value != r.FormValue(name) {
		return "", errors.New(name + " does not compare")
	}
	return value, nil
}

func (c *CookieHandler) CreateCookie(r *http.Request, name, value string) (*http.Cookie, error) {
	return c.createCookie(r, name, value, c.securecookie)
}

func (c *CookieHandler) createCookie(r *http.Request, name, value string, secureCookie *securecookie.SecureCookie) (*http.Cookie, error) {
	encoded, err := secureCookie.Encode(name, originBoundValue{
		Origin: requestOrigin(r),
		Value:  value,
	})
	if err != nil {
		return nil, err
	}
	return &http.Cookie{
		Name:     name,
		Value:    encoded,
		Path:     c.path,
		MaxAge:   c.maxAge,
		HttpOnly: true,
		Secure:   c.secureOnly,
		SameSite: c.sameSite,
	}, nil
}

func (c *CookieHandler) CreateSecureCookie(r *http.Request, name, value string) (*http.Cookie, error) {
	secureCookie, err := c.secureCookieFunc(r)
	if err != nil {
		return nil, err
	}
	return c.createCookie(r, name, value, secureCookie)
}

func (c *CookieHandler) SetCookie(r *http.Request, w http.ResponseWriter, name, value string) error {
	if c.IsRequestAware() {
		return errors.New("cookie handler is request aware")
	}

	cookie, err := c.CreateCookie(r, name, value)
	if err != nil {
		return err
	}

	http.SetCookie(w, cookie)
	return nil
}

func (c *CookieHandler) SetRequestAwareCookie(r *http.Request, w http.ResponseWriter, name string, value string) error {
	if !c.IsRequestAware() {
		return errors.New("cookie handler is not request aware")
	}

	cookie, err := c.CreateSecureCookie(r, name, value)
	if err != nil {
		return err
	}

	http.SetCookie(w, cookie)
	return nil
}

func (c *CookieHandler) DeleteCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     c.path,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   c.secureOnly,
		SameSite: c.sameSite,
	})
}

func (c *CookieHandler) IsRequestAware() bool {
	return c.secureCookieFunc != nil
}
