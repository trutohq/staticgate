package main

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// captureLogs redirects the std logger and returns the buffer.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &buf
}

func TestIPTiers(t *testing.T) {
	always := []string{
		"127.0.0.1", "127.255.255.255", "::1",
		"169.254.169.254", "fe80::1", "ff02::1", "224.0.0.1", // link-local unicast + link-local multicast
		"0.0.0.0", "::", "0.1.2.3",
		"::ffff:127.0.0.1", "::ffff:169.254.169.254", "::ffff:0.0.0.0",
	}
	private := []string{
		"10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1", "fd00::1",
		"239.1.1.1", "100.64.0.1", "100.127.255.255", "192.0.0.1",
		"198.18.0.1", "198.19.255.255", "240.0.0.1", "255.255.255.255", "64:ff9b::a00:1",
		"::ffff:10.0.0.1", "::ffff:192.168.0.1", "::ffff:100.64.0.1", "::ffff:198.18.0.1", "::ffff:240.0.0.1",
	}
	public := []string{
		"8.8.8.8", "1.1.1.1", "93.184.216.34", "100.63.255.255", "100.128.0.0",
		"198.17.255.255", "198.20.0.0", "2606:4700:4700::1111", "2001:4860:4860::8888", "::ffff:8.8.8.8",
	}
	for _, s := range always {
		ip := netip.MustParseAddr(s)
		if !isAlwaysBlockedIP(ip) {
			t.Errorf("%s: want always-blocked", s)
		}
		if !(guardConfig{}).blocked(ip) {
			t.Errorf("%s: want blocked with private tier off", s)
		}
	}
	for _, s := range private {
		ip := netip.MustParseAddr(s)
		if isAlwaysBlockedIP(ip) || !isPrivateBlockedIP(ip) {
			t.Errorf("%s: want private tier only", s)
		}
		if (guardConfig{}).blocked(ip) {
			t.Errorf("%s: must be allowed when private tier is off", s)
		}
		if !(guardConfig{blockPrivate: true}).blocked(ip) {
			t.Errorf("%s: want blocked when private tier is on", s)
		}
	}
	for _, s := range public {
		ip := netip.MustParseAddr(s)
		if isAlwaysBlockedIP(ip) || isPrivateBlockedIP(ip) {
			t.Errorf("%s: want public", s)
		}
	}
}

func TestControlModes(t *testing.T) {
	ctx := context.Background()
	buf := captureLogs(t)

	// log mode (default): everything allowed, would-be blocks are logged.
	logMode := guardConfig{blockPrivate: true}
	for _, addr := range []string{"127.0.0.1:80", "169.254.169.254:80", "10.0.0.1:80", "not-an-addr"} {
		if err := logMode.control(ctx, "tcp", addr, nil); err != nil {
			t.Errorf("log mode %s: got %v, want nil", addr, err)
		}
	}
	if got := strings.Count(buf.String(), "would block target"); got != 4 {
		t.Errorf("log mode: %d would-block lines, want 4:\n%s", got, buf.String())
	}
	buf.Reset()
	if err := logMode.control(ctx, "tcp4", "8.8.8.8:443", nil); err != nil || buf.Len() != 0 {
		t.Errorf("public addr in log mode: err %v, log %q", err, buf.String())
	}

	// enforce mode, private tier off (default): tier 1 blocked, private allowed.
	enf := guardConfig{enforce: true}
	for _, addr := range []string{"127.0.0.1:80", "[::1]:80", "169.254.169.254:80", "[fe80::1]:80", "0.0.0.0:80", "not-an-addr"} {
		if err := enf.control(ctx, "tcp", addr, nil); err != errBlockedTarget {
			t.Errorf("enforce %s: got %v, want errBlockedTarget", addr, err)
		}
	}
	for _, addr := range []string{"10.0.0.1:80", "192.168.1.1:80", "100.64.0.1:80", "[fd00::1]:80", "8.8.8.8:443"} {
		if err := enf.control(ctx, "tcp", addr, nil); err != nil {
			t.Errorf("enforce, private off, %s: got %v, want nil", addr, err)
		}
	}

	// enforce mode + private tier on.
	enfPriv := guardConfig{enforce: true, blockPrivate: true}
	for _, addr := range []string{"10.0.0.1:80", "192.168.1.1:80", "100.64.0.1:80", "[fd00::1]:80"} {
		if err := enfPriv.control(ctx, "tcp", addr, nil); err != errBlockedTarget {
			t.Errorf("enforce, private on, %s: got %v, want errBlockedTarget", addr, err)
		}
	}
	if err := enfPriv.control(ctx, "tcp4", "8.8.8.8:443", nil); err != nil {
		t.Errorf("public address: got %v, want nil", err)
	}
}

func TestGuardConfigFromEnv(t *testing.T) {
	if g := guardConfigFromEnv(); g.enforce || g.blockPrivate {
		t.Errorf("defaults: got %+v, want log mode, private off", g)
	}
	t.Setenv("STATICGATE_BLOCK_MODE", "enforce")
	t.Setenv("STATICGATE_BLOCK_PRIVATE_NETWORKS", "true")
	if g := guardConfigFromEnv(); !g.enforce || !g.blockPrivate {
		t.Errorf("set: got %+v", g)
	}
	t.Setenv("STATICGATE_BLOCK_MODE", "bogus")
	if g := guardConfigFromEnv(); g.enforce {
		t.Errorf("unknown mode must fall back to log, got %+v", g)
	}
}

func TestTransportMatchesDefault(t *testing.T) {
	def := http.DefaultTransport.(*http.Transport)
	got := newTransport(guardConfig{})
	if got.Proxy == nil || reflect.ValueOf(got.Proxy).Pointer() != reflect.ValueOf(http.ProxyFromEnvironment).Pointer() {
		t.Error("Proxy must be http.ProxyFromEnvironment")
	}
	if got.DialContext == nil {
		t.Error("DialContext must be set")
	}
	if got.ForceAttemptHTTP2 != def.ForceAttemptHTTP2 ||
		got.MaxIdleConns != def.MaxIdleConns ||
		got.MaxIdleConnsPerHost != def.MaxIdleConnsPerHost ||
		got.MaxConnsPerHost != def.MaxConnsPerHost ||
		got.IdleConnTimeout != def.IdleConnTimeout ||
		got.TLSHandshakeTimeout != def.TLSHandshakeTimeout ||
		got.ExpectContinueTimeout != def.ExpectContinueTimeout ||
		got.ResponseHeaderTimeout != def.ResponseHeaderTimeout ||
		got.DisableKeepAlives != def.DisableKeepAlives ||
		got.DisableCompression != def.DisableCompression {
		t.Errorf("transport settings differ from DefaultTransport:\n got %+v\n def %+v", got, def)
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

func loopbackTargets(upstreamURL string) []string {
	return []string{
		upstreamURL, // http://127.0.0.1:<port>
		strings.Replace(upstreamURL, "127.0.0.1", "[::ffff:127.0.0.1]", 1),
		"http://localhost:" + strings.Split(upstreamURL, ":")[2],
	}
}

// Default (log mode): the request goes through unchanged and the would-be block is logged.
func TestProxyLogModeAllowsAndLogs(t *testing.T) {
	hits := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusTeapot)
	}))
	defer upstream.Close()
	buf := captureLogs(t)

	client := &http.Client{Timeout: 5 * time.Second, Transport: newTransport(guardConfig{})}
	h := forwardHandler("secret", client)
	// [::ffff:127.0.0.1] may not be routable on every host; only assert on the plain forms.
	for _, target := range []string{upstream.URL, "http://localhost:" + strings.Split(upstream.URL, ":")[2]} {
		if rec := proxyReq(t, h, target); rec.Code != http.StatusTeapot {
			t.Errorf("%s: status %d, want 418 passthrough", target, rec.Code)
		}
	}
	if hits != 2 {
		t.Errorf("upstream hits %d, want 2", hits)
	}
	if !strings.Contains(buf.String(), `"message":"would block target"`) {
		t.Errorf("missing would-block log:\n%s", buf.String())
	}
}

func TestProxyEnforceRefusesLoopbackAndMetadata(t *testing.T) {
	hit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
	}))
	defer upstream.Close()

	client := &http.Client{Timeout: 5 * time.Second, Transport: newTransport(guardConfig{enforce: true})}
	h := forwardHandler("secret", client)

	targets := append(loopbackTargets(upstream.URL), "http://169.254.169.254/latest/meta-data/")
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
