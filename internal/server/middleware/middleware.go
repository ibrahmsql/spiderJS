package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ibrahmsql/spiderjs/internal/utils/logger"
)

// Middleware represents a middleware function
type Middleware func(http.Handler) http.Handler

// Chain chains multiple middleware together
func Chain(middlewares ...Middleware) Middleware {
	return func(next http.Handler) http.Handler {
		for i := len(middlewares) - 1; i >= 0; i-- {
			next = middlewares[i](next)
		}
		return next
	}
}

// Logger is a middleware that logs requests
func Logger(log *logger.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Create a custom response writer to capture status code
			crw := &customResponseWriter{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
			}

			// Process request
			next.ServeHTTP(crw, r)

			// Calculate duration
			duration := time.Since(start)

			// Log request
			log.Info("Request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", crw.statusCode,
				"duration", duration.String(),
				"ip", getClientIP(r),
				"user_agent", r.UserAgent(),
			)
		})
	}
}

// RateLimit is a middleware that limits request rate
func RateLimit(rps int, burst int) Middleware {
	// Create token bucket
	var mu sync.Mutex
	tokens := burst
	lastRefill := time.Now()
	refillRate := time.Second / time.Duration(rps)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Refill tokens
			mu.Lock()
			now := time.Now()
			elapsed := now.Sub(lastRefill)
			if elapsed > refillRate {
				newTokens := int(elapsed / refillRate)
				tokens += newTokens
				if tokens > burst {
					tokens = burst
				}
				lastRefill = now
			}

			// Check if token available
			if tokens <= 0 {
				mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", "1")
				w.WriteHeader(http.StatusTooManyRequests)
				w.Write([]byte(`{"error":"Too many requests"}`))
				return
			}

			// Take token
			tokens--
			mu.Unlock()

			// Process request
			next.ServeHTTP(w, r)
		})
	}
}

// APIKey is a middleware that checks for API key
func APIKey(validKeys []string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip authentication for OPTIONS requests
			if r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}

			// Get API key from header
			key := r.Header.Get("X-API-Key")
			if key == "" {
				// Try query parameter
				key = r.URL.Query().Get("api_key")
			}

			// Check if key is valid
			valid := false
			for _, validKey := range validKeys {
				if key == validKey {
					valid = true
					break
				}
			}

			// Return error if key is invalid
			if !valid {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"error":"Invalid API key"}`))
				return
			}

			// Process request
			next.ServeHTTP(w, r)
		})
	}
}

// CORS is a middleware that adds CORS headers
func CORS(allowedOrigins []string, allowedMethods []string, allowedHeaders []string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get origin
			origin := r.Header.Get("Origin")
			if origin == "" {
				// Process request without CORS headers
				next.ServeHTTP(w, r)
				return
			}

			// Check if origin is allowed
			allowed := false
			for _, allowedOrigin := range allowedOrigins {
				if allowedOrigin == "*" || allowedOrigin == origin {
					allowed = true
					break
				}
			}

			// Set CORS headers
			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", strings.Join(allowedMethods, ", "))
				w.Header().Set("Access-Control-Allow-Headers", strings.Join(allowedHeaders, ", "))
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Access-Control-Max-Age", "86400")
			}

			// Handle preflight request
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusOK)
				return
			}

			// Process request
			next.ServeHTTP(w, r)
		})
	}
}

// Timeout is a middleware that adds a timeout to requests
func Timeout(timeout time.Duration) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Create context with timeout
			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			defer cancel()

			// Process request with timeout context
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Recovery is a middleware that recovers from panics
func Recovery(log *logger.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					// Log error
					log.ErrorMsg("Panic recovered: %v", err)

					// Return error
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte(`{"error":"Internal server error"}`))
				}
			}()

			// Process request
			next.ServeHTTP(w, r)
		})
	}
}

// RequestID is a middleware that adds a request ID to the context
func RequestID() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get request ID from header
			requestID := r.Header.Get("X-Request-ID")
			if requestID == "" {
				// Generate new request ID
				requestID = fmt.Sprintf("%d", time.Now().UnixNano())
			}

			// Set request ID header
			w.Header().Set("X-Request-ID", requestID)

			// Add request ID to context
			ctx := context.WithValue(r.Context(), "request_id", requestID)

			// Process request
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// customResponseWriter is a wrapper around http.ResponseWriter that captures the status code
type customResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

// WriteHeader captures the status code
func (crw *customResponseWriter) WriteHeader(statusCode int) {
	crw.statusCode = statusCode
	crw.ResponseWriter.WriteHeader(statusCode)
}

// getClientIP returns the client IP address from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		// Return first IP in list
		return strings.Split(forwarded, ",")[0]
	}

	// Check X-Real-IP header
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return realIP
	}

	// Return remote address
	return r.RemoteAddr
}
