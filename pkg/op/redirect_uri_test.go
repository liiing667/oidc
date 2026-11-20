package op

import "testing"

func TestCanonicalizeRedirectURI(t *testing.T) {
	tests := []struct {
		name       string
		rawURL     string
		wantOK     bool
		wantScheme string
		wantHost   string
		wantPort   string
		wantPath   string
		wantQuery  string
		wantFrag   string
		wantLoop   bool
	}{
		{
			name:       "https with default port",
			rawURL:     "https://example.com:443/callback?a=1#f",
			wantOK:     true,
			wantScheme: "https",
			wantHost:   "example.com",
			wantPort:   "",
			wantPath:   "/callback",
			wantQuery:  "a=1",
			wantFrag:   "f",
			wantLoop:   false,
		},
		{
			name:       "http with default port",
			rawURL:     "http://example.com:80/callback",
			wantOK:     true,
			wantScheme: "http",
			wantHost:   "example.com",
			wantPort:   "",
			wantPath:   "/callback",
			wantLoop:   false,
		},
		{
			name:       "non-default port kept",
			rawURL:     "https://example.com:8443/callback",
			wantOK:     true,
			wantScheme: "https",
			wantHost:   "example.com",
			wantPort:   "8443",
			wantPath:   "/callback",
			wantLoop:   false,
		},
		{
			name:       "trailing dot and upper case removed",
			rawURL:     "https://EXAMPLE.COM./callback",
			wantOK:     true,
			wantScheme: "https",
			wantHost:   "example.com",
			wantPort:   "",
			wantPath:   "/callback",
			wantLoop:   false,
		},
		{
			name:       "ipv6 long form canonicalized",
			rawURL:     "http://[0:0:0:0:0:0:0:1]:80/callback",
			wantOK:     true,
			wantScheme: "http",
			wantHost:   "::1",
			wantPort:   "",
			wantPath:   "/callback",
			wantLoop:   true,
		},
		{
			name:       "ipv4 mapped ipv6 canonicalized to v4",
			rawURL:     "http://[::ffff:127.0.0.1]/callback",
			wantOK:     true,
			wantScheme: "http",
			wantHost:   "127.0.0.1",
			wantPort:   "",
			wantPath:   "/callback",
			wantLoop:   true,
		},
		{
			name:       "localhost trailing dot is loopback",
			rawURL:     "http://localhost.:4200/callback",
			wantOK:     true,
			wantScheme: "http",
			wantHost:   "localhost",
			wantPort:   "4200",
			wantPath:   "/callback",
			wantLoop:   true,
		},
		{
			name:       "non-loopback v6 keeps canonical address",
			rawURL:     "http://[2001:db8::1]/callback",
			wantOK:     true,
			wantScheme: "http",
			wantHost:   "2001:db8::1",
			wantPort:   "",
			wantPath:   "/callback",
			wantLoop:   false,
		},
		{
			name:   "custom scheme cannot be canonicalized",
			rawURL: "custom://callback",
			wantOK: false,
		},
		{
			name:   "encoded non-url cannot be canonicalized",
			rawURL: "https%3A%2F%2Fexample.com%2Fcallback",
			wantOK: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := canonicalizeRedirectURI(tt.rawURL)
			if ok != tt.wantOK {
				t.Fatalf("canonicalizeRedirectURI() ok = %v, want %v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if got.scheme != tt.wantScheme || got.host != tt.wantHost || got.port != tt.wantPort ||
				got.path != tt.wantPath || got.rawQuery != tt.wantQuery || got.fragment != tt.wantFrag ||
				got.loopback != tt.wantLoop {
				t.Errorf("canonicalizeRedirectURI() = %+v, want scheme=%q host=%q port=%q path=%q query=%q frag=%q loopback=%v",
					got, tt.wantScheme, tt.wantHost, tt.wantPort, tt.wantPath, tt.wantQuery, tt.wantFrag, tt.wantLoop)
			}
		})
	}
}

func TestRedirectURIsEquivalent(t *testing.T) {
	tests := []struct {
		name       string
		request    string
		registered string
		want       bool
	}{
		// Equivalent URI families must reach the same conclusion.
		{"default port https", "https://example.com:443/cb", "https://example.com/cb", true},
		{"default port http", "http://example.com/cb", "http://example.com:80/cb", true},
		{"trailing dot", "https://example.com./cb", "https://example.com/cb", true},
		{"host case", "https://EXAMPLE.com/cb", "https://example.com/cb", true},
		{"ipv6 long form", "http://[0:0:0:0:0:0:0:1]/cb", "http://[::1]/cb", true},
		{"ipv4 mapped ipv6", "http://[::ffff:127.0.0.1]:9/cb", "http://127.0.0.1/cb", true},
		{"loopback dynamic port", "http://127.0.0.1:51004/cb", "http://127.0.0.1/cb", true},
		{"loopback cross host", "http://[::1]:51004/cb", "http://localhost/cb", true},
		{"loopback trailing dot", "http://localhost.:51004/cb", "http://127.0.0.1/cb", true},
		{"same query", "http://127.0.0.1:51004/cb?a=1", "http://127.0.0.1/cb?a=1", true},
		{"custom scheme exact", "custom://callback", "custom://callback", true},

		// Rejections: look-alikes and downgrades must not match.
		{"non-default port", "https://example.com:8443/cb", "https://example.com/cb", false},
		{"different host", "https://evil.com/cb", "https://example.com/cb", false},
		{"dotted look-alike", "https://example.com.evil.com/cb", "https://example.com/cb", false},
		{"loopback scheme mismatch", "http://127.0.0.1:9/cb", "https://127.0.0.1/cb", false},
		{"non-loopback scheme mismatch", "http://example.com/cb", "https://example.com/cb", false},
		{"different path", "http://127.0.0.1:9/other", "http://127.0.0.1/cb", false},
		{"different query", "http://127.0.0.1:9/cb?b=2", "http://127.0.0.1/cb?a=1", false},
		{"fragment present", "https://example.com/cb#f", "https://example.com/cb", false},
		{"custom scheme mismatch", "custom://callback", "other://callback", false},
		{"encoded uri", "https%3A%2F%2Fexample.com%2Fcb", "https://example.com/cb", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := redirectURIsEquivalent(tt.request, tt.registered); got != tt.want {
				t.Errorf("redirectURIsEquivalent(%q, %q) = %v, want %v", tt.request, tt.registered, got, tt.want)
			}
			// Comparison is symmetric for canonical URIs.
			if got := redirectURIsEquivalent(tt.registered, tt.request); got != tt.want {
				t.Errorf("redirectURIsEquivalent(%q, %q) reversed = %v, want %v", tt.registered, tt.request, got, tt.want)
			}
		})
	}
}
