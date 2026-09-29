package main

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestIsBlockedIP(t *testing.T) {
	tests := []struct {
		ip      string
		blocked bool
	}{
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"93.184.216.34", false},
		{"100.63.255.255", false},
		{"100.128.0.0", false},
		{"198.17.255.255", false},
		{"198.20.0.0", false},
		{"2606:4700:4700::1111", false},
		{"2001:4860:4860::8888", false},
		{"::ffff:8.8.8.8", false},

		{"127.0.0.1", true},
		{"127.255.255.255", true},
		{"::1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.1.1", true},
		{"fd00::1", true},
		{"169.254.169.254", true},
		{"fe80::1", true},
		{"224.0.0.1", true},
		{"ff02::1", true},
		{"0.0.0.0", true},
		{"::", true},
		{"0.1.2.3", true},
		{"100.64.0.1", true},
		{"100.127.255.255", true},
		{"192.0.0.1", true},
		{"198.18.0.1", true},
		{"198.19.255.255", true},
		{"240.0.0.1", true},
		{"255.255.255.255", true},
		{"64:ff9b::a00:1", true},
		// IPv4-mapped IPv6 forms
		{"::ffff:127.0.0.1", true},
		{"::ffff:10.0.0.1", true},
		{"::ffff:192.168.0.1", true},
		{"::ffff:169.254.169.254", true},
		{"::ffff:100.64.0.1", true},
		{"::ffff:0.0.0.0", true},
		{"::ffff:198.18.0.1", true},
		{"::ffff:240.0.0.1", true},
	}
	for _, tc := range tests {
		if got := isBlockedIP(netip.MustParseAddr(tc.ip)); got != tc.blocked {
			t.Errorf("isBlockedIP(%s) = %v, want %v", tc.ip, got, tc.blocked)
		}
	}
}

func TestGuardDialFailsClosed(t *testing.T) {
	if err := guardDial("tcp", "not-an-addr", nil); err != errBlockedTarget {
		t.Errorf("unparseable address: got %v, want errBlockedTarget", err)
	}
	if err := guardDial("tcp4", "8.8.8.8:443", nil); err != nil {
		t.Errorf("public address: got %v, want nil", err)
	}
}

func proxyReq(t *testing.T, h http.Handler, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Truto-StaticGate-Token", "secret")
	req.Header.Set("Truto-Target-URL", target)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestProxyRefusesPrivateTargets(t *testing.T) {
	hit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
	}))
	defer upstream.Close()

	client := &http.Client{Timeout: 5 * time.Second, Transport: newTransport()}
	h := forwardHandler("secret", client)

	targets := []string{
		upstream.URL, // http://127.0.0.1:<port>
		strings.Replace(upstream.URL, "127.0.0.1", "[::ffff:127.0.0.1]", 1),
		"http://localhost:" + strings.Split(upstream.URL, ":")[2],
		"http://169.254.169.254/latest/meta-data/",
	}
	for _, target := range targets {
		rec := proxyReq(t, h, target)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403 (body %q)", target, rec.Code, rec.Body.String())
		}
		if got := strings.TrimSpace(rec.Body.String()); got != `{"error":"target not allowed"}` {
			t.Errorf("%s: body %q", target, got)
		}
	}
	if hit {
		t.Error("upstream server was reached")
	}
}

// ponytail: no e2e redirect-to-private test; it needs a reachable public first hop, and
// the dial guard is the single choke point every hop goes through (covered above).
