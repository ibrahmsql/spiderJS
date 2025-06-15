package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/ibrahmsql/spiderjs/internal/analyzer"
	"github.com/ibrahmsql/spiderjs/internal/config"
	"github.com/ibrahmsql/spiderjs/internal/scanner"
	"github.com/ibrahmsql/spiderjs/internal/utils/logger"
	"github.com/ibrahmsql/spiderjs/pkg/models"
	"github.com/ibrahmsql/spiderjs/pkg/version"
)

// Handler contains the HTTP handlers for the API
type Handler struct {
	config   *config.Config
	log      *logger.Logger
	analyzer analyzer.Analyzer
	scanner  scanner.ScannerInterface
	jobs     map[string]*JobStatus
	jobsMux  http.Handler
}

// JobStatus represents the status of a scan job
type JobStatus struct {
	ID        string      `json:"id"`
	Status    string      `json:"status"`
	Progress  int         `json:"progress"`
	URL       string      `json:"url"`
	StartTime time.Time   `json:"start_time"`
	EndTime   time.Time   `json:"end_time,omitempty"`
	Result    interface{} `json:"result,omitempty"`
	Error     string      `json:"error,omitempty"`
}

// ScanRequest represents a scan request
type ScanRequest struct {
	URL     string            `json:"url" validate:"required,url"`
	Options map[string]bool   `json:"options"`
	Headers map[string]string `json:"headers"`
	Cookies map[string]string `json:"cookies"`
	Timeout int               `json:"timeout"`
}

// ScanResponse represents a scan response
type ScanResponse struct {
	ID              string                 `json:"id"`
	Status          string                 `json:"status"`
	Frameworks      []models.Framework     `json:"frameworks,omitempty"`
	APIs            []string               `json:"apis,omitempty"`
	Vulnerabilities []models.Vulnerability `json:"vulnerabilities,omitempty"`
}

// NewHandler creates a new handler
func NewHandler(cfg *config.Config, log *logger.Logger, analyzer analyzer.Analyzer, scanner scanner.ScannerInterface) (*Handler, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	if log == nil {
		return nil, fmt.Errorf("logger cannot be nil")
	}

	// Check if analyzer is nil
	if analyzer == nil {
		return nil, fmt.Errorf("analyzer cannot be nil")
	}

	// Check if scanner is nil
	if scanner == nil {
		return nil, fmt.Errorf("scanner cannot be nil")
	}

	return &Handler{
		config:   cfg,
		log:      log,
		analyzer: analyzer,
		scanner:  scanner,
		jobs:     make(map[string]*JobStatus),
	}, nil
}

// RegisterRoutes registers the API routes
func (h *Handler) RegisterRoutes(r *mux.Router) {
	// API routes
	api := r.PathPrefix("/api").Subrouter()

	// Health check
	api.HandleFunc("/health", h.HealthCheck).Methods(http.MethodGet)

	// Version
	api.HandleFunc("/version", h.Version).Methods(http.MethodGet)

	// Scan
	api.HandleFunc("/scan", h.Scan).Methods(http.MethodPost)
	api.HandleFunc("/scan/{id}", h.ScanStatus).Methods(http.MethodGet)
	api.HandleFunc("/scan/{id}/cancel", h.CancelScan).Methods(http.MethodPost)

	// Analyze
	api.HandleFunc("/analyze", h.Analyze).Methods(http.MethodPost)

	// Framework detection
	api.HandleFunc("/detect/framework", h.DetectFramework).Methods(http.MethodPost)

	// API discovery
	api.HandleFunc("/discover/api", h.DiscoverAPI).Methods(http.MethodPost)

	// Security scan
	api.HandleFunc("/security", h.SecurityScan).Methods(http.MethodPost)

	// ML prediction
	api.HandleFunc("/predict", h.Predict).Methods(http.MethodPost)
}

// HealthCheck handles health check requests
func (h *Handler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	response := map[string]string{
		"status": "ok",
		"time":   time.Now().Format(time.RFC3339),
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// Version handles version requests
func (h *Handler) Version(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	response := map[string]string{
		"version": version.GetVersion(),
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// Scan handles scan requests
func (h *Handler) Scan(w http.ResponseWriter, r *http.Request) {
	// Parse request
	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendError(w, http.StatusBadRequest, "Invalid request format", err)
		return
	}

	// Validate URL
	if req.URL == "" {
		h.sendError(w, http.StatusBadRequest, "URL is required", nil)
		return
	}

	// Generate job ID
	jobID := uuid.New().String()

	// Create job status
	job := &JobStatus{
		ID:        jobID,
		Status:    "pending",
		Progress:  0,
		URL:       req.URL,
		StartTime: time.Now(),
	}

	// Store job status
	h.jobs[jobID] = job

	// Start scan in background
	go func() {
		// Update status
		job.Status = "running"

		// Create context with timeout
		timeout := 5 * time.Minute
		if req.Timeout > 0 {
			timeout = time.Duration(req.Timeout) * time.Second
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		// Update config with request parameters
		cfg := *h.config
		cfg.URL = req.URL

		// Apply options
		for k, v := range req.Options {
			switch k {
			case "include_xss":
				cfg.ScanOptions.IncludeXSS = v
			case "include_injection":
				cfg.ScanOptions.IncludeInjection = v
			case "include_csrf":
				cfg.ScanOptions.IncludeCSRF = v
			case "include_cors":
				cfg.ScanOptions.IncludeCORS = v
			case "include_headers":
				cfg.ScanOptions.IncludeHeaders = v
			case "include_cookies":
				cfg.ScanOptions.IncludeCookies = v
			case "include_supply_chain":
				cfg.ScanOptions.IncludeSupplyChain = v
			case "include_prototype":
				cfg.ScanOptions.IncludePrototype = v
			case "active_scan":
				cfg.ScanOptions.ActiveScan = v
			}
		}

		// Perform scan
		result, err := h.scanner.Scan(ctx)
		if err != nil {
			job.Status = "failed"
			job.Error = fmt.Sprintf("Scan failed: %v", err)
			return
		}

		// Update job status
		job.Status = "completed"
		job.Progress = 100
		job.EndTime = time.Now()
		job.Result = result
	}()

	// Return job ID
	response := ScanResponse{
		ID:     jobID,
		Status: job.Status,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(response)
}

// ScanStatus handles scan status requests
func (h *Handler) ScanStatus(w http.ResponseWriter, r *http.Request) {
	// Get job ID from URL
	vars := mux.Vars(r)
	jobID := vars["id"]

	// Get job status
	job, ok := h.jobs[jobID]
	if !ok {
		h.sendError(w, http.StatusNotFound, "Job not found", nil)
		return
	}

	// Return job status
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(job)
}

// CancelScan handles scan cancellation requests
func (h *Handler) CancelScan(w http.ResponseWriter, r *http.Request) {
	// Get job ID from URL
	vars := mux.Vars(r)
	jobID := vars["id"]

	// Get job status
	job, ok := h.jobs[jobID]
	if !ok {
		h.sendError(w, http.StatusNotFound, "Job not found", nil)
		return
	}

	// Check if job can be cancelled
	if job.Status != "running" && job.Status != "pending" {
		h.sendError(w, http.StatusBadRequest, "Job cannot be cancelled", nil)
		return
	}

	// Update job status
	job.Status = "cancelled"
	job.EndTime = time.Now()

	// Return job status
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(job)
}

// Analyze handles analyze requests
func (h *Handler) Analyze(w http.ResponseWriter, r *http.Request) {
	// Parse request
	var req struct {
		URL     string          `json:"url"`
		Content string          `json:"content"`
		Options map[string]bool `json:"options"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendError(w, http.StatusBadRequest, "Invalid request format", err)
		return
	}

	// Validate input
	if req.URL == "" && req.Content == "" {
		h.sendError(w, http.StatusBadRequest, "Either URL or content is required", nil)
		return
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Create target
	target := &models.Target{
		URL: req.URL,
	}

	// If content is provided, add it as a script
	if req.Content != "" {
		target.Scripts = []string{req.Content}
	}

	// Perform analysis
	result, err := h.analyzer.Analyze(ctx, target)
	if err != nil {
		h.sendError(w, http.StatusInternalServerError, "Analysis failed", err)
		return
	}

	// Return result
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}

// DetectFramework handles framework detection requests
func (h *Handler) DetectFramework(w http.ResponseWriter, r *http.Request) {
	// Parse request
	var req struct {
		URL     string `json:"url"`
		Content string `json:"content"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendError(w, http.StatusBadRequest, "Invalid request format", err)
		return
	}

	// Validate input
	if req.URL == "" && req.Content == "" {
		h.sendError(w, http.StatusBadRequest, "Either URL or content is required", nil)
		return
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	// Create target
	target := &models.Target{
		URL: req.URL,
	}

	// If content is provided, add it as a script
	if req.Content != "" {
		target.Scripts = []string{req.Content}
	}

	// Perform analysis
	result, err := h.analyzer.Analyze(ctx, target)
	if err != nil {
		h.sendError(w, http.StatusInternalServerError, "Framework detection failed", err)
		return
	}

	// Return frameworks only
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result.Frameworks)
}

// DiscoverAPI handles API discovery requests
func (h *Handler) DiscoverAPI(w http.ResponseWriter, r *http.Request) {
	// Parse request
	var req struct {
		URL     string `json:"url"`
		Content string `json:"content"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendError(w, http.StatusBadRequest, "Invalid request format", err)
		return
	}

	// Validate input
	if req.URL == "" {
		h.sendError(w, http.StatusBadRequest, "URL is required", nil)
		return
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Create target
	target := &models.Target{
		URL: req.URL,
	}

	// If content is provided, add it as HTML
	if req.Content != "" {
		target.HTML = req.Content
	}

	// Perform analysis to discover APIs
	result, err := h.analyzer.Analyze(ctx, target)
	if err != nil {
		h.sendError(w, http.StatusInternalServerError, "API discovery failed", err)
		return
	}

	// Return discovered API endpoints
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"apis": result.Target.APIs,
	})
}

// SecurityScan handles security scan requests
func (h *Handler) SecurityScan(w http.ResponseWriter, r *http.Request) {
	// Parse request
	var req struct {
		URL     string          `json:"url"`
		Options map[string]bool `json:"options"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendError(w, http.StatusBadRequest, "Invalid request format", err)
		return
	}

	// Validate input
	if req.URL == "" {
		h.sendError(w, http.StatusBadRequest, "URL is required", nil)
		return
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Set the URL in the config
	h.config.URL = req.URL

	// Apply scan options
	for k, v := range req.Options {
		switch k {
		case "include_xss":
			h.config.ScanOptions.IncludeXSS = v
		case "include_injection":
			h.config.ScanOptions.IncludeInjection = v
		case "include_csrf":
			h.config.ScanOptions.IncludeCSRF = v
		case "include_cors":
			h.config.ScanOptions.IncludeCORS = v
		case "include_headers":
			h.config.ScanOptions.IncludeHeaders = v
		case "include_cookies":
			h.config.ScanOptions.IncludeCookies = v
		case "include_supply_chain":
			h.config.ScanOptions.IncludeSupplyChain = v
		case "include_prototype":
			h.config.ScanOptions.IncludePrototype = v
		case "active_scan":
			h.config.ScanOptions.ActiveScan = v
		}
	}

	// Perform scan
	result, err := h.scanner.Scan(ctx)
	if err != nil {
		h.sendError(w, http.StatusInternalServerError, "Security scan failed", err)
		return
	}

	// Return findings only
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result.Findings)
}

// Predict handles ML prediction requests
func (h *Handler) Predict(w http.ResponseWriter, r *http.Request) {
	// This is a placeholder for the ML prediction endpoint
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "ML prediction not implemented yet",
	})
}

// sendError sends an error response
func (h *Handler) sendError(w http.ResponseWriter, status int, message string, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	response := map[string]string{
		"error": message,
	}

	if err != nil {
		h.log.ErrorMsg("%s: %v", message, err)
		response["details"] = err.Error()
	} else {
		h.log.ErrorMsg("%s", message)
	}

	json.NewEncoder(w).Encode(response)
}
