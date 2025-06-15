package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/ibrahmsql/spiderjs/internal/config"
	"github.com/ibrahmsql/spiderjs/internal/scanner"
	"github.com/ibrahmsql/spiderjs/internal/utils/logger"
	"github.com/ibrahmsql/spiderjs/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockAnalyzer is a mock implementation of the analyzer.Analyzer interface
type MockAnalyzer struct {
	mock.Mock
}

// Analyze mocks the Analyze method
func (m *MockAnalyzer) Analyze(ctx context.Context, target *models.Target) (*models.AnalysisResult, error) {
	args := m.Called(ctx, target)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AnalysisResult), args.Error(1)
}

// MockScanner is a mock implementation of the scanner.ScannerInterface interface
type MockScanner struct {
	mock.Mock
}

// Scan mocks the Scan method
func (m *MockScanner) Scan(ctx context.Context) (*scanner.ScanResult, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*scanner.ScanResult), args.Error(1)
}

// NewMockScanner creates a mock scanner that implements scanner.ScannerInterface
func NewMockScanner() scanner.ScannerInterface {
	return new(MockScanner)
}

// setupHandler creates a new handler with mocked dependencies
func setupHandler() (*Handler, *MockAnalyzer, *MockScanner) {
	cfg := &config.Config{}
	log := logger.NewLogger()
	mockAnalyzer := new(MockAnalyzer)
	mockScanner := new(MockScanner)

	handler, _ := NewHandler(cfg, log, mockAnalyzer, mockScanner)

	return handler, mockAnalyzer, mockScanner
}

func TestNewHandler(t *testing.T) {
	cfg := &config.Config{}
	log := logger.NewLogger()
	mockAnalyzer := new(MockAnalyzer)
	mockScanner := new(MockScanner)

	// Test with valid parameters
	handler, err := NewHandler(cfg, log, mockAnalyzer, mockScanner)
	assert.NoError(t, err)
	assert.NotNil(t, handler)

	// Test with nil config
	handler, err = NewHandler(nil, log, mockAnalyzer, mockScanner)
	assert.Error(t, err)
	assert.Nil(t, handler)

	// Test with nil logger
	handler, err = NewHandler(cfg, nil, mockAnalyzer, mockScanner)
	assert.Error(t, err)
	assert.Nil(t, handler)

	// Test with nil analyzer
	handler, err = NewHandler(cfg, log, nil, mockScanner)
	assert.Error(t, err)
	assert.Nil(t, handler)

	// Test with nil scanner
	handler, err = NewHandler(cfg, log, mockAnalyzer, nil)
	assert.Error(t, err)
	assert.Nil(t, handler)
}

func TestHealthCheck(t *testing.T) {
	handler, _, _ := setupHandler()

	// Create request
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	rec := httptest.NewRecorder()

	// Call handler
	handler.HealthCheck(rec, req)

	// Check response
	assert.Equal(t, http.StatusOK, rec.Code)

	var response map[string]string
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "ok", response["status"])
	assert.NotEmpty(t, response["time"])
}

func TestVersion(t *testing.T) {
	handler, _, _ := setupHandler()

	// Create request
	req := httptest.NewRequest(http.MethodGet, "/api/version", nil)
	rec := httptest.NewRecorder()

	// Call handler
	handler.Version(rec, req)

	// Check response
	assert.Equal(t, http.StatusOK, rec.Code)

	var response map[string]string
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.NotEmpty(t, response["version"])
}

func TestScan(t *testing.T) {
	handler, _, mockScanner := setupHandler()

	// Set up mock expectations
	mockResult := &scanner.ScanResult{
		Findings: []*models.Finding{},
		URL:      "https://example.com",
	}
	mockScanner.On("Scan", mock.Anything).Return(mockResult, nil)

	// Test with valid request
	reqBody := `{"url": "https://example.com", "options": {"include_xss": true}}`
	req := httptest.NewRequest(http.MethodPost, "/api/scan", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	// Call handler
	handler.Scan(rec, req)

	// Check response
	assert.Equal(t, http.StatusAccepted, rec.Code)

	var response ScanResponse
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.NotEmpty(t, response.ID)
	assert.Equal(t, "pending", response.Status)

	// Test with invalid JSON
	req = httptest.NewRequest(http.MethodPost, "/api/scan", bytes.NewBufferString("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()

	// Call handler
	handler.Scan(rec, req)

	// Check response
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	// Test with empty URL
	reqBody = `{"url": "", "options": {"include_xss": true}}`
	req = httptest.NewRequest(http.MethodPost, "/api/scan", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()

	// Call handler
	handler.Scan(rec, req)

	// Check response
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestScanStatus(t *testing.T) {
	handler, _, _ := setupHandler()

	// Add a test job
	jobID := "test-job"
	job := &JobStatus{
		ID:        jobID,
		Status:    "completed",
		Progress:  100,
		URL:       "https://example.com",
		StartTime: time.Now(),
		EndTime:   time.Now(),
	}
	handler.jobs[jobID] = job

	// Test with valid job ID
	req := httptest.NewRequest(http.MethodGet, "/api/scan/"+jobID, nil)
	rec := httptest.NewRecorder()

	// Set up router to extract URL parameters
	router := mux.NewRouter()
	router.HandleFunc("/api/scan/{id}", handler.ScanStatus).Methods(http.MethodGet)
	router.ServeHTTP(rec, req)

	// Check response
	assert.Equal(t, http.StatusOK, rec.Code)

	var response JobStatus
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, jobID, response.ID)
	assert.Equal(t, "completed", response.Status)

	// Test with invalid job ID
	req = httptest.NewRequest(http.MethodGet, "/api/scan/invalid-job", nil)
	rec = httptest.NewRecorder()

	// Set up router to extract URL parameters
	router = mux.NewRouter()
	router.HandleFunc("/api/scan/{id}", handler.ScanStatus).Methods(http.MethodGet)
	router.ServeHTTP(rec, req)

	// Check response
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestCancelScan(t *testing.T) {
	handler, _, _ := setupHandler()

	// Add a test job
	jobID := "test-job"
	job := &JobStatus{
		ID:        jobID,
		Status:    "running",
		Progress:  50,
		URL:       "https://example.com",
		StartTime: time.Now(),
	}
	handler.jobs[jobID] = job

	// Test with valid job ID
	req := httptest.NewRequest(http.MethodPost, "/api/scan/"+jobID+"/cancel", nil)
	rec := httptest.NewRecorder()

	// Set up router to extract URL parameters
	router := mux.NewRouter()
	router.HandleFunc("/api/scan/{id}/cancel", handler.CancelScan).Methods(http.MethodPost)
	router.ServeHTTP(rec, req)

	// Check response
	assert.Equal(t, http.StatusOK, rec.Code)

	var response JobStatus
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, jobID, response.ID)
	assert.Equal(t, "cancelled", response.Status)

	// Test with invalid job ID
	req = httptest.NewRequest(http.MethodPost, "/api/scan/invalid-job/cancel", nil)
	rec = httptest.NewRecorder()

	// Set up router to extract URL parameters
	router = mux.NewRouter()
	router.HandleFunc("/api/scan/{id}/cancel", handler.CancelScan).Methods(http.MethodPost)
	router.ServeHTTP(rec, req)

	// Check response
	assert.Equal(t, http.StatusNotFound, rec.Code)

	// Test with job that cannot be cancelled
	jobID = "completed-job"
	job = &JobStatus{
		ID:        jobID,
		Status:    "completed",
		Progress:  100,
		URL:       "https://example.com",
		StartTime: time.Now(),
		EndTime:   time.Now(),
	}
	handler.jobs[jobID] = job

	req = httptest.NewRequest(http.MethodPost, "/api/scan/"+jobID+"/cancel", nil)
	rec = httptest.NewRecorder()

	// Set up router to extract URL parameters
	router = mux.NewRouter()
	router.HandleFunc("/api/scan/{id}/cancel", handler.CancelScan).Methods(http.MethodPost)
	router.ServeHTTP(rec, req)

	// Check response
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestAnalyze(t *testing.T) {
	handler, mockAnalyzer, _ := setupHandler()

	// Mock analyzer response
	target := &models.Target{
		URL:     "https://example.com",
		Scripts: []string{"console.log('test')"},
	}
	result := &models.AnalysisResult{
		Target: target,
	}
	mockAnalyzer.On("Analyze", mock.Anything, mock.MatchedBy(func(t *models.Target) bool {
		return t.URL == "https://example.com"
	})).Return(result, nil)

	// Test with valid request
	reqBody := `{"url": "https://example.com", "content": "console.log('test')"}`
	req := httptest.NewRequest(http.MethodPost, "/api/analyze", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	// Call handler
	handler.Analyze(rec, req)

	// Check response
	assert.Equal(t, http.StatusOK, rec.Code)

	// Test with invalid JSON
	req = httptest.NewRequest(http.MethodPost, "/api/analyze", bytes.NewBufferString("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()

	// Call handler
	handler.Analyze(rec, req)

	// Check response
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	// Test with empty URL and content
	reqBody = `{"url": "", "content": ""}`
	req = httptest.NewRequest(http.MethodPost, "/api/analyze", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()

	// Call handler
	handler.Analyze(rec, req)

	// Check response
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestDetectFramework(t *testing.T) {
	handler, mockAnalyzer, _ := setupHandler()

	// Mock analyzer response
	target := &models.Target{
		URL:     "https://example.com",
		Scripts: []string{"console.log('test')"},
	}
	frameworks := []*models.Framework{
		{Name: "React", Version: "16.8.0"},
	}
	result := &models.AnalysisResult{
		Target:     target,
		Frameworks: frameworks,
	}
	mockAnalyzer.On("Analyze", mock.Anything, mock.MatchedBy(func(t *models.Target) bool {
		return t.URL == "https://example.com"
	})).Return(result, nil)

	// Test with valid request
	reqBody := `{"url": "https://example.com", "content": "console.log('test')"}`
	req := httptest.NewRequest(http.MethodPost, "/api/detect/framework", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	// Call handler
	handler.DetectFramework(rec, req)

	// Check response
	assert.Equal(t, http.StatusOK, rec.Code)

	// Test with invalid JSON
	req = httptest.NewRequest(http.MethodPost, "/api/detect/framework", bytes.NewBufferString("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()

	// Call handler
	handler.DetectFramework(rec, req)

	// Check response
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	// Test with empty URL and content
	reqBody = `{"url": "", "content": ""}`
	req = httptest.NewRequest(http.MethodPost, "/api/detect/framework", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()

	// Call handler
	handler.DetectFramework(rec, req)

	// Check response
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestDiscoverAPI(t *testing.T) {
	handler, mockAnalyzer, _ := setupHandler()

	// Mock analyzer response
	target := &models.Target{
		URL:  "https://example.com",
		APIs: []string{"/api/users", "/api/products"},
	}
	result := &models.AnalysisResult{
		Target: target,
	}
	mockAnalyzer.On("Analyze", mock.Anything, mock.MatchedBy(func(t *models.Target) bool {
		return t.URL == "https://example.com"
	})).Return(result, nil)

	// Test with valid request
	reqBody := `{"url": "https://example.com", "content": "<html>...</html>"}`
	req := httptest.NewRequest(http.MethodPost, "/api/discover/api", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	// Call handler
	handler.DiscoverAPI(rec, req)

	// Check response
	assert.Equal(t, http.StatusOK, rec.Code)

	// Test with invalid JSON
	req = httptest.NewRequest(http.MethodPost, "/api/discover/api", bytes.NewBufferString("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()

	// Call handler
	handler.DiscoverAPI(rec, req)

	// Check response
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	// Test with empty URL
	reqBody = `{"url": "", "content": "<html>...</html>"}`
	req = httptest.NewRequest(http.MethodPost, "/api/discover/api", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()

	// Call handler
	handler.DiscoverAPI(rec, req)

	// Check response
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestSecurityScan(t *testing.T) {
	handler, _, mockScanner := setupHandler()

	// Mock scanner response
	findings := []*models.Finding{
		{
			Type:        "XSS",
			Severity:    "High",
			Description: "Cross-site scripting vulnerability",
			URL:         "https://example.com/search?q=test",
		},
	}
	result := &scanner.ScanResult{
		Findings: findings,
		URL:      "https://example.com",
	}
	mockScanner.On("Scan", mock.Anything).Return(result, nil)

	// Test with valid request
	reqBody := `{"url": "https://example.com", "options": {"include_xss": true}}`
	req := httptest.NewRequest(http.MethodPost, "/api/security", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	// Call handler
	handler.SecurityScan(rec, req)

	// Check response
	assert.Equal(t, http.StatusOK, rec.Code)

	// Test with invalid JSON
	req = httptest.NewRequest(http.MethodPost, "/api/security", bytes.NewBufferString("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()

	// Call handler
	handler.SecurityScan(rec, req)

	// Check response
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	// Test with empty URL
	reqBody = `{"url": "", "options": {"include_xss": true}}`
	req = httptest.NewRequest(http.MethodPost, "/api/security", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()

	// Call handler
	handler.SecurityScan(rec, req)

	// Check response
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestPredict(t *testing.T) {
	handler, _, _ := setupHandler()

	// Create request
	req := httptest.NewRequest(http.MethodPost, "/api/predict", nil)
	rec := httptest.NewRecorder()

	// Call handler
	handler.Predict(rec, req)

	// Check response
	assert.Equal(t, http.StatusNotImplemented, rec.Code)

	var response map[string]string
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "ML prediction not implemented yet", response["message"])
}

func TestSendError(t *testing.T) {
	handler, _, _ := setupHandler()

	// Test with error
	rec := httptest.NewRecorder()
	testErr := fmt.Errorf("test error details")
	handler.sendError(rec, http.StatusBadRequest, "Test error", testErr)

	// Check response
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var response map[string]string
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "Test error", response["error"])
	assert.Equal(t, testErr.Error(), response["details"])

	// Test without error
	rec = httptest.NewRecorder()
	handler.sendError(rec, http.StatusBadRequest, "Test error", nil)

	// Check response
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	response = make(map[string]string)
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "Test error", response["error"])

	// Check if "details" key exists in the response
	_, detailsExists := response["details"]
	assert.False(t, detailsExists, "details field should not exist when error is nil")
}
