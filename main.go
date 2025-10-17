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

		// Read request body for reuse
		var payload []byte
		if r.Body != nil {
			payload, _ = io.ReadAll(r.Body)
			_ = r.Body.Close()
		}
		body := io.NopCloser(bytes.NewReader(payload))

		outReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL.String(), body)
		if err != nil {
			duration := time.Since(start)
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "request build failed"})
			logJSON(jsonLog{
				Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
				Method:     r.Method,
				TargetURL:  targetURL.String(),
				StatusCode: http.StatusBadGateway,
				DurationMs: duration.Milliseconds(),
				Error:      "request build failed",
			})
			return
		}

		// Copy headers except Truto-* prefixed headers
		for k, vals := range r.Header {
			if strings.HasPrefix(strings.ToLower(k), "truto-") {
				continue
			}
			for _, v := range vals {
				outReq.Header.Add(k, v)
			}
		}
		sanitizeHeaders(outReq.Header)

		resp, err := httpClient.Do(outReq)
		duration := time.Since(start)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "upstream request error"})
			logJSON(jsonLog{
				Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
				Method:     r.Method,
				TargetURL:  targetURL.String(),
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
			TargetURL:  targetURL.String(),
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

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           http.TimeoutHandler(http.HandlerFunc(forwardHandler(apiKey, &http.Client{Timeout: 60 * time.Second})), 120*time.Second, "upstream timeout"),
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 30 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Graceful shutdown
	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		logJSON(jsonLog{Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Message: "staticgate starting", TargetURL: "", StatusCode: 0})
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
