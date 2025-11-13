package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

type jsonLog struct {
	Timestamp  string `json:"timestamp"`
	Method     string `json:"method,omitempty"`
	TargetURL  string `json:"target_url,omitempty"`
	StatusCode int    `json:"status_code,omitempty"`
	DurationMs int64  `json:"duration_ms,omitempty"`
	Error      string `json:"error,omitempty"`
	Message    string `json:"message,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// remove hop-by-hop headers that must not be forwarded
func sanitizeHeaders(h http.Header) {
	hopHeaders := []string{
		"Connection",
		"Proxy-Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	}
	for _, k := range hopHeaders {
		h.Del(k)
	}
}

func validateTokenHeader(r *http.Request, expected string) bool {
	token := strings.TrimSpace(r.Header.Get("Truto-StaticGate-Token"))
	if token == "" {
		logJSON(jsonLog{
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			Message:   "token validation failed: empty token",
		})
		return false
	}
	isValid := token == expected
	if !isValid {
		// Log token info for debugging (masked for security)
		maskedToken := ""
		if len(token) > 8 {
			maskedToken = token[:4] + "..." + token[len(token)-4:]
		} else {
			maskedToken = "***"
		}
		logJSON(jsonLog{
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			Message:   "token validation failed: token mismatch",
			Error:     "received token: " + maskedToken,
		})
	}
	return isValid
}

// doRequestWithRedirects is a generic redirect handler:
// - Works for all methods.
// - Replays bodies safely using bodyBytes.
// - Implements browser-like semantics for 301/302/303 vs 307/308.
// - Detects simple URL loops and caps total redirects.
func doRequestWithRedirects(
	ctx context.Context,
	client *http.Client,
	method string,
	startURL *url.URL,
	headers http.Header,
	bodyBytes []byte,
	maxRedirects int,
) (*http.Response, *url.URL, error) {

	currentMethod := method
	currentURL := startURL
	visited := make(map[string]struct{})

	for i := 0; i <= maxRedirects; i++ {
		// Build body for this attempt
		var body io.ReadCloser
		if len(bodyBytes) > 0 && currentMethod != http.MethodGet && currentMethod != http.MethodHead {
			body = io.NopCloser(bytes.NewReader(bodyBytes))
		} else {
			body = nil
		}

		req, err := http.NewRequestWithContext(ctx, currentMethod, currentURL.String(), body)
		if err != nil {
			return nil, currentURL, err
		}
		// Clone headers
		req.Header = headers.Clone()
		sanitizeHeaders(req.Header)

		resp, err := client.Do(req)
		if err != nil {
			return nil, currentURL, err
		}

		// If not a redirect or no Location header, we are done.
		if resp.StatusCode < 300 || resp.StatusCode > 399 {
			return resp, currentURL, nil
		}
		loc := resp.Header.Get("Location")
		if loc == "" {
			// No Location, nothing to follow.
			return resp, currentURL, nil
		}

		// Resolve next URL
		locURL, err := url.Parse(loc)
		if err != nil {
			return resp, currentURL, nil
		}
		nextURL := currentURL.ResolveReference(locURL)

		// Log redirect hop
		logJSON(jsonLog{
			Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
			Method:     currentMethod,
			TargetURL:  currentURL.String() + " -> " + nextURL.String(),
			StatusCode: resp.StatusCode,
			Message:    "upstream redirect",
		})

		// Detect loop by URL
		if _, seen := visited[nextURL.String()]; seen {
			// We already visited this URL. Return the redirect response as-is.
			return resp, nextURL, nil
		}
		visited[nextURL.String()] = struct{}{}

		// Close intermediate response body before next hop
		_ = resp.Body.Close()

		// Decide next method/body semantics per status code.

		switch resp.StatusCode {
		case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther:
			// 301, 302, 303: browsers switch non-GET/HEAD to GET and drop body.
			if currentMethod != http.MethodGet && currentMethod != http.MethodHead {
				currentMethod = http.MethodGet
				bodyBytes = nil
			}
		case http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
			// 307, 308: must preserve method and body per RFC.
			// We already handle body replay via bodyBytes, so nothing to change.
		default:
			// Other 3xx: do nothing special.
		}

		currentURL = nextURL
	}

	// Too many redirects
	return nil, currentURL, &url.Error{
		Op:  currentMethod,
		URL: currentURL.String(),
		Err: io.EOF,
	}
}

func forwardHandler(expectedToken string, httpClient *http.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		if r.URL.Path == "/up" && r.Method == http.MethodGet {
			duration := time.Since(start)
			writeJSON(w, http.StatusOK, map[string]string{"status": "up"})
			logJSON(jsonLog{
				Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
				Method:     r.Method,
				TargetURL:  "/up",
				StatusCode: http.StatusOK,
				DurationMs: duration.Milliseconds(),
				Message:    "health check",
			})
			return
		}

		if expectedToken == "" || !validateTokenHeader(r, expectedToken) {
			duration := time.Since(start)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			logJSON(jsonLog{
				Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
				Method:     r.Method,
				StatusCode: http.StatusUnauthorized,
				DurationMs: duration.Milliseconds(),
				Error:      "unauthorized",
			})
			return
		}

		rawTarget := r.Header.Get("Truto-Target-URL")
		if rawTarget == "" {
			duration := time.Since(start)
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing Truto-Target-URL header"})
			logJSON(jsonLog{
				Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
				Method:     r.Method,
				StatusCode: http.StatusBadRequest,
				DurationMs: duration.Milliseconds(),
				Error:      "missing Truto-Target-URL header",
			})
			return
		}

		targetURL, err := url.Parse(rawTarget)
		if err != nil || !(targetURL.Scheme == "http" || targetURL.Scheme == "https") || targetURL.Host == "" {
			duration := time.Since(start)
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid Truto-Target-URL"})
			logJSON(jsonLog{
				Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
				Method:     r.Method,
				StatusCode: http.StatusBadRequest,
				DurationMs: duration.Milliseconds(),
				Error:      "invalid Truto-Target-URL",
			})
			return
		}

		// Read request body for reuse across potential redirects
		var payload []byte
		if r.Body != nil {
			payload, _ = io.ReadAll(r.Body)
			_ = r.Body.Close()
		}

		// Prepare headers for upstream (exclude Truto-* headers)
		upstreamHeaders := make(http.Header)
		for k, vals := range r.Header {
			lk := strings.ToLower(k)
			if strings.HasPrefix(lk, "truto-") {
				continue
			}
			for _, v := range vals {
				upstreamHeaders.Add(k, v)
			}
		}
		sanitizeHeaders(upstreamHeaders)

		resp, finalURL, err := doRequestWithRedirects(
			r.Context(),
			httpClient,
			r.Method,
			targetURL,
			upstreamHeaders,
			payload,
			10, // maxRedirects
		)
		duration := time.Since(start)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "upstream request error"})
			logJSON(jsonLog{
				Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
				Method:     r.Method,
				TargetURL:  finalURL.String(),
				StatusCode: http.StatusBadGateway,
				DurationMs: duration.Milliseconds(),
				Error:      err.Error(),
			})
			return
		}
		defer resp.Body.Close()

		// Write back response
		for k, vals := range resp.Header {
			// Avoid hop-by-hop headers
			if strings.EqualFold(k, "Transfer-Encoding") || strings.EqualFold(k, "Connection") {
				continue
			}
			for _, v := range vals {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)

		logJSON(jsonLog{
			Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
			Method:     r.Method,
			TargetURL:  finalURL.String(),
			StatusCode: resp.StatusCode,
			DurationMs: duration.Milliseconds(),
		})
	}
}

func logJSON(entry jsonLog) {
	b, err := json.Marshal(entry)
	if err != nil {
		log.Printf("{\"timestamp\":%q,\"message\":%q}", time.Now().UTC().Format(time.RFC3339Nano), "failed to marshal log")
		return
	}
	log.Println(string(b))
}

func main() {
	apiKey := getEnv("STATICGATE_API_KEY", "")
	port := getEnv("PORT", "80")

	// Log API key info for debugging (masked for security)
	maskedApiKey := ""
	if apiKey != "" {
		if len(apiKey) > 8 {
			maskedApiKey = apiKey[:4] + "..." + apiKey[len(apiKey)-4:]
		} else {
			maskedApiKey = "***"
		}
	} else {
		maskedApiKey = "(empty)"
	}
	logJSON(jsonLog{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Message:   "staticgate configuration",
		Error:     "API key: " + maskedApiKey + ", port: " + port,
	})

	httpClient := &http.Client{
		Timeout: 60 * time.Second,
	}

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           http.HandlerFunc(forwardHandler(apiKey, httpClient)),
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 30 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Graceful shutdown
	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		logJSON(jsonLog{Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Message: "staticgate starting"})
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logJSON(jsonLog{Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Error: err.Error(), Message: "server error"})
		}
	}()

	<-done
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	logJSON(jsonLog{Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Message: "staticgate stopped"})
}
