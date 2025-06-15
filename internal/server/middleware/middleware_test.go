package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ibrahmsql/spiderjs/internal/utils/logger"
	"github.com/stretchr/testify/assert"
)

func TestChain(t *testing.T) {
	// Create test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test"))
	})

	// Create test middleware
	middleware1 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Test-1", "1")
			next.ServeHTTP(w, r)
		})
	}

	middleware2 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Test-2", "2")
			next.ServeHTTP(w, r)
		})
	}

	// Chain middleware
	handler := Chain(middleware1, middleware2)(testHandler)

	// Create test request
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()

	// Call handler
	handler.ServeHTTP(rec, req)

	// Check response
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "test", rec.Body.String())
	assert.Equal(t, "1", rec.Header().Get("X-Test-1"))
	assert.Equal(t, "2", rec.Header().Get("X-Test-2"))
}

func TestLogger(t *testing.T) {
	// Create test logger
	log := logger.NewLogger()

	// Create test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test"))
	})

	// Create logger middleware
	handler := Logger(log)(testHandler)

	// Create test request
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()

	// Call handler
	handler.ServeHTTP(rec, req)

	// Check response
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "test", rec.Body.String())
}

func TestRateLimit(t *testing.T) {
	// Create test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test"))
	})

	// Create rate limit middleware (2 requests per second, burst of 2)
	handler := RateLimit(2, 2)(testHandler)

	// Create test request
	req := httptest.NewRequest("GET", "/", nil)

	// First request should succeed
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req)
	assert.Equal(t, http.StatusOK, rec1.Code)
	assert.Equal(t, "test", rec1.Body.String())

	// Second request should succeed
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req)
	assert.Equal(t, http.StatusOK, rec2.Code)
	assert.Equal(t, "test", rec2.Body.String())

	// Third request should fail (rate limit exceeded)
	rec3 := httptest.NewRecorder()
	handler.ServeHTTP(rec3, req)
	assert.Equal(t, http.StatusTooManyRequests, rec3.Code)
	assert.Equal(t, `{"error":"Too many requests"}`, rec3.Body.String())
	assert.Equal(t, "1", rec3.Header().Get("Retry-After"))

	// Wait for token refill
	time.Sleep(1 * time.Second)

	// Fourth request should succeed (tokens refilled)
	rec4 := httptest.NewRecorder()
	handler.ServeHTTP(rec4, req)
	assert.Equal(t, http.StatusOK, rec4.Code)
	assert.Equal(t, "test", rec4.Body.String())
}

func TestAPIKey(t *testing.T) {
	// Create test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test"))
	})

	// Create API key middleware
	validKeys := []string{"valid-key"}
	handler := APIKey(validKeys)(testHandler)

	// Test with valid API key in header
	req1 := httptest.NewRequest("GET", "/", nil)
	req1.Header.Set("X-API-Key", "valid-key")
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	assert.Equal(t, http.StatusOK, rec1.Code)
	assert.Equal(t, "test", rec1.Body.String())

	// Test with valid API key in query parameter
	req2 := httptest.NewRequest("GET", "/?api_key=valid-key", nil)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusOK, rec2.Code)
	assert.Equal(t, "test", rec2.Body.String())

	// Test with invalid API key
	req3 := httptest.NewRequest("GET", "/", nil)
	req3.Header.Set("X-API-Key", "invalid-key")
	rec3 := httptest.NewRecorder()
	handler.ServeHTTP(rec3, req3)
	assert.Equal(t, http.StatusUnauthorized, rec3.Code)
	assert.Equal(t, `{"error":"Invalid API key"}`, rec3.Body.String())

	// Test with no API key
	req4 := httptest.NewRequest("GET", "/", nil)
	rec4 := httptest.NewRecorder()
	handler.ServeHTTP(rec4, req4)
	assert.Equal(t, http.StatusUnauthorized, rec4.Code)
	assert.Equal(t, `{"error":"Invalid API key"}`, rec4.Body.String())

	// Test OPTIONS request (should bypass authentication)
	req5 := httptest.NewRequest("OPTIONS", "/", nil)
	rec5 := httptest.NewRecorder()
	handler.ServeHTTP(rec5, req5)
	assert.Equal(t, http.StatusOK, rec5.Code)
	assert.Equal(t, "test", rec5.Body.String())
}

func TestCORS(t *testing.T) {
	// Create test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test"))
	})

	// Create CORS middleware
	allowedOrigins := []string{"https://example.com", "https://test.com"}
	allowedMethods := []string{"GET", "POST", "PUT", "DELETE"}
	allowedHeaders := []string{"Content-Type", "Authorization", "X-API-Key"}
	handler := CORS(allowedOrigins, allowedMethods, allowedHeaders)(testHandler)

	// Test with allowed origin
	req1 := httptest.NewRequest("GET", "/", nil)
	req1.Header.Set("Origin", "https://example.com")
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	assert.Equal(t, http.StatusOK, rec1.Code)
	assert.Equal(t, "test", rec1.Body.String())
	assert.Equal(t, "https://example.com", rec1.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "GET, POST, PUT, DELETE", rec1.Header().Get("Access-Control-Allow-Methods"))
	assert.Equal(t, "Content-Type, Authorization, X-API-Key", rec1.Header().Get("Access-Control-Allow-Headers"))
	assert.Equal(t, "true", rec1.Header().Get("Access-Control-Allow-Credentials"))
	assert.Equal(t, "86400", rec1.Header().Get("Access-Control-Max-Age"))

	// Test with disallowed origin
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.Header.Set("Origin", "https://evil.com")
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusOK, rec2.Code)
	assert.Equal(t, "test", rec2.Body.String())
	assert.Equal(t, "", rec2.Header().Get("Access-Control-Allow-Origin"))

	// Test OPTIONS request
	req3 := httptest.NewRequest("OPTIONS", "/", nil)
	req3.Header.Set("Origin", "https://example.com")
	rec3 := httptest.NewRecorder()
	handler.ServeHTTP(rec3, req3)
	assert.Equal(t, http.StatusOK, rec3.Code)
	assert.Equal(t, "", rec3.Body.String())
	assert.Equal(t, "https://example.com", rec3.Header().Get("Access-Control-Allow-Origin"))
}

func TestTimeout(t *testing.T) {
	// Create test handler that sleeps
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if context is canceled
		select {
		case <-r.Context().Done():
			// Context canceled
			return
		case <-time.After(100 * time.Millisecond):
			// Request completed
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("test"))
		}
	})

	// Create timeout middleware with short timeout
	shortHandler := Timeout(50 * time.Millisecond)(testHandler)

	// Create test request
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()

	// Call handler with short timeout
	shortHandler.ServeHTTP(rec, req)

	// Request should be canceled, no response written
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "", rec.Body.String())

	// Create timeout middleware with long timeout
	longHandler := Timeout(200 * time.Millisecond)(testHandler)

	// Create test request
	req = httptest.NewRequest("GET", "/", nil)
	rec = httptest.NewRecorder()

	// Call handler with long timeout
	longHandler.ServeHTTP(rec, req)

	// Request should complete
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "test", rec.Body.String())
}

func TestRecovery(t *testing.T) {
	// Create test logger
	log := logger.NewLogger()

	// Create test handler that panics
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	})

	// Create recovery middleware
	handler := Recovery(log)(testHandler)

	// Create test request
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()

	// Call handler
	handler.ServeHTTP(rec, req)

	// Check response
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, `{"error":"Internal server error"}`, rec.Body.String())
}

func TestRequestID(t *testing.T) {
	// Create test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get request ID from context
		requestID := r.Context().Value("request_id").(string)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(requestID))
	})

	// Create request ID middleware
	handler := RequestID()(testHandler)

	// Test with request ID in header
	req1 := httptest.NewRequest("GET", "/", nil)
	req1.Header.Set("X-Request-ID", "test-id")
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	assert.Equal(t, http.StatusOK, rec1.Code)
	assert.Equal(t, "test-id", rec1.Body.String())
	assert.Equal(t, "test-id", rec1.Header().Get("X-Request-ID"))

	// Test without request ID in header
	req2 := httptest.NewRequest("GET", "/", nil)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusOK, rec2.Code)
	assert.NotEmpty(t, rec2.Body.String())
	assert.NotEmpty(t, rec2.Header().Get("X-Request-ID"))
}

func TestGetClientIP(t *testing.T) {
	// Test with X-Forwarded-For header
	req1 := httptest.NewRequest("GET", "/", nil)
	req1.Header.Set("X-Forwarded-For", "192.168.1.1, 10.0.0.1")
	assert.Equal(t, "192.168.1.1", getClientIP(req1))

	// Test with X-Real-IP header
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.Header.Set("X-Real-IP", "192.168.1.2")
	assert.Equal(t, "192.168.1.2", getClientIP(req2))

	// Test with remote address
	req3 := httptest.NewRequest("GET", "/", nil)
	req3.RemoteAddr = "192.168.1.3:1234"
	assert.Equal(t, "192.168.1.3:1234", getClientIP(req3))
}
