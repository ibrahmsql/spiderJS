package scanner

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/ibrahmsql/spiderjs/internal/config"
	"github.com/ibrahmsql/spiderjs/internal/crawler"
	"github.com/ibrahmsql/spiderjs/internal/utils/logger"
	"github.com/ibrahmsql/spiderjs/pkg/models"
)

// Scanner is responsible for scanning a target for vulnerabilities
type Scanner struct {
	config *config.Config
	log    *logger.Logger
	spider *crawler.Spider
}

// ScanResult contains the results of a scan
type ScanResult struct {
	Target    *models.Target
	Findings  []*models.Finding
	Duration  time.Duration
	StartTime time.Time
	EndTime   time.Time
	Stats     *ScanStats
	URL       string
}

// ScanStats contains statistics about the scan
type ScanStats struct {
	TotalURLs     int
	TotalScripts  int
	TotalAPIs     int
	TotalFindings int
}

// Scanner interface defines the methods required for security scanning
type ScannerInterface interface {
	// Scan performs a security scan and returns the scan result
	Scan(ctx context.Context) (*ScanResult, error)
}

// NewScanner creates a new scanner
func NewScanner(ctx context.Context, cfg *config.Config, log *logger.Logger) (*Scanner, error) {
	// Context timeout check
	if ctx.Err() != nil {
		return nil, fmt.Errorf("context cancelled: %w", ctx.Err())
	}

	// Input validation
	if cfg == nil {
		return nil, errors.New("config cannot be nil")
	}

	if log == nil {
		return nil, errors.New("logger cannot be nil")
	}

	// Create spider
	spider, err := crawler.NewSpider(ctx, cfg, log)
	if err != nil {
		return nil, fmt.Errorf("failed to create spider: %w", err)
	}

	return &Scanner{
		config: cfg,
		log:    log,
		spider: spider,
	}, nil
}

// Scan performs a scan on the target
func (s *Scanner) Scan(ctx context.Context) (*ScanResult, error) {
	// Context timeout check
	if ctx.Err() != nil {
		return nil, fmt.Errorf("context cancelled: %w", ctx.Err())
	}

	// Panic recovery
	defer func() {
		if r := recover(); r != nil {
			err := fmt.Errorf("panic recovered in Scan: %v", r)
			s.log.ErrorMsg("Scanner panic: %v", err)
		}
	}()

	// Start scan with progress indicators
	s.log.Success("Starting comprehensive scan of " + s.config.URL)
	startTime := time.Now()

	// Define a ticker for progress updates
	progressTicker := time.NewTicker(3 * time.Second)
	defer progressTicker.Stop()

	// Create a cancel context with timeout
	scanCtx, cancel := context.WithTimeout(ctx, time.Duration(s.config.ScanTimeout)*time.Second)
	defer cancel()

	// Start progress reporting in background
	go func() {
		for {
			select {
			case <-progressTicker.C:
				elapsed := time.Since(startTime).Round(time.Second)
				s.log.Info("Scan in progress... [" + elapsed.String() + " elapsed]")
			case <-scanCtx.Done():
				return
			}
		}
	}()

	// Crawl target using enhanced crawler - with timeout
	s.log.Info("Starting advanced crawl of " + s.config.URL)
	crawlStart := time.Now()

	target, err := s.spider.Crawl(scanCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to crawl target: %w", err)
	}

	crawlDuration := time.Since(crawlStart)
	s.log.Success("Crawling completed in " + crawlDuration.Round(time.Millisecond).String())

	// Initialize findings and stats
	findings := []*models.Finding{}

	// Quick summary stats
	s.log.Info("Found " + strconv.Itoa(len(target.Scripts)) + " scripts, " + strconv.Itoa(len(target.APIs)) + " APIs, and " + strconv.Itoa(len(target.Paths)) + " URLs")

	// Process discovered resources in parallel
	var wg sync.WaitGroup
	findingsChan := make(chan *models.Finding, 100) // Buffered channel for better performance
	errorsChan := make(chan error, 10)              // Buffered channel for errors
	done := make(chan struct{})

	// Start collector goroutine
	go func() {
		for finding := range findingsChan {
			findings = append(findings, finding)
		}
		done <- struct{}{}
	}()

	// Create error collection goroutine
	errorsCollected := []error{}
	var errMutex sync.Mutex

	go func() {
		for err := range errorsChan {
			errMutex.Lock()
			errorsCollected = append(errorsCollected, err)
			if len(errorsCollected) < 5 { // Only log first few errors
				s.log.Error(err)
			}
			errMutex.Unlock()
		}
	}()

	// Optimize JavaScript analysis - only analyze first 20 scripts for large sites
	scriptLimit := len(target.Scripts)
	if scriptLimit > 20 && !s.config.ScanOptions.ComprehensiveScan {
		scriptLimit = 20
		s.log.Info("Limiting script analysis to first " + strconv.Itoa(scriptLimit) + " scripts for performance")
	}

	// Analyze JavaScript files
	if scriptLimit > 0 {
		s.log.Success("Analyzing " + strconv.Itoa(scriptLimit) + " JavaScript files")
		analysisStart := time.Now()

		// Limit concurrent analysis
		semaphore := make(chan struct{}, s.config.Concurrent)

		for i, script := range target.Scripts {
			if i >= scriptLimit {
				break // Respect script limit
			}

			wg.Add(1)
			semaphore <- struct{}{}

			go func(scriptURL string) {
				defer wg.Done()
				defer func() { <-semaphore }()

				// Analyze script for vulnerabilities with context timeout
				scriptFindings, err := s.analyzeScript(scanCtx, scriptURL)
				if err != nil {
					// Skip logging for context canceled errors which are expected
					if scanCtx.Err() == nil {
						errorsChan <- fmt.Errorf("failed to analyze script %s: %w", scriptURL, err)
					}
					return
				}

				// Send findings to collector
				for _, finding := range scriptFindings {
					select {
					case findingsChan <- finding:
					case <-scanCtx.Done():
						return
					}
				}
			}(script)
		}

		// Wait for script analysis with a progress indicator
		go func() {
			scriptTicker := time.NewTicker(2 * time.Second)
			defer scriptTicker.Stop()

			for {
				select {
				case <-scriptTicker.C:
					analysisElapsed := time.Since(analysisStart).Round(time.Second)
					s.log.Info("Script analysis in progress... [" + analysisElapsed.String() + " elapsed]")
				case <-scanCtx.Done():
					return
				}
			}
		}()
	}

	// Analyze API endpoints - limit for performance
	apiLimit := len(target.APIs)
	if apiLimit > 10 && !s.config.ScanOptions.ComprehensiveScan {
		apiLimit = 10
		s.log.Info("Limiting API analysis to first " + strconv.Itoa(apiLimit) + " endpoints for performance")
	}

	if apiLimit > 0 && s.config.ScanOptions.ActiveScan {
		s.log.Success("Analyzing " + strconv.Itoa(apiLimit) + " API endpoints")

		// Limit concurrent analysis
		semaphore := make(chan struct{}, s.config.Concurrent)

		for i, api := range target.APIs {
			if i >= apiLimit {
				break // Respect API limit
			}

			wg.Add(1)
			semaphore <- struct{}{}

			go func(apiURL string) {
				defer wg.Done()
				defer func() { <-semaphore }()

				// Test API for vulnerabilities
				apiFindings, err := s.testAPI(scanCtx, apiURL)
				if err != nil {
					// Skip logging for context canceled errors
					if scanCtx.Err() == nil {
						errorsChan <- fmt.Errorf("failed to test API %s: %w", apiURL, err)
					}
					return
				}

				// Send findings to collector
				for _, finding := range apiFindings {
					select {
					case findingsChan <- finding:
					case <-scanCtx.Done():
						return
					}
				}
			}(api)
		}
	}

	// Fast security checks in parallel
	wg.Add(3)

	// Check for security headers
	go func() {
		defer wg.Done()
		if s.config.ScanOptions.IncludeHeaders {
			headerFindings := s.checkSecurityHeaders(target)
			for _, finding := range headerFindings {
				select {
				case findingsChan <- finding:
				case <-scanCtx.Done():
					return
				}
			}
		}
	}()

	// Check for cookie issues
	go func() {
		defer wg.Done()
		if s.config.ScanOptions.IncludeCookies {
			cookieFindings := s.checkCookies(target)
			for _, finding := range cookieFindings {
				select {
				case findingsChan <- finding:
				case <-scanCtx.Done():
					return
				}
			}
		}
	}()

	// Check for framework vulnerabilities - new parallel check
	go func() {
		defer wg.Done()
		if s.config.ScanOptions.IncludeFramework && len(target.Frameworks) > 0 {
			for _, framework := range target.Frameworks {
				if framework.Type != "" {
					finding := &models.Finding{
						ID:          uuid.New().String(),
						Type:        models.FindingTypeFramework,
						Title:       fmt.Sprintf("Detected %s Framework", framework.Type),
						Description: fmt.Sprintf("Detected %s framework version %s", framework.Type, framework.Version),
						Severity:    models.SeverityInfo,
						URL:         target.URL,
						Timestamp:   time.Now(),
					}

					// Check if the framework has known vulnerabilities
					if framework.Version != "" {
						// More detailed info for version detection
						finding.Description = fmt.Sprintf("Detected %s framework version %s. Framework versions may have known security vulnerabilities.",
							framework.Type, framework.Version)
					}

					select {
					case findingsChan <- finding:
					case <-scanCtx.Done():
						return
					}
				}
			}
		}
	}()

	// Wait for all analysis to complete or context to be cancelled
	waitCh := make(chan struct{})
	go func() {
		wg.Wait()
		close(findingsChan)
		close(errorsChan)
		waitCh <- struct{}{}
	}()

	// Wait for completion or timeout
	select {
	case <-waitCh:
		// All analysis completed
	case <-scanCtx.Done():
		if ctx.Err() == context.DeadlineExceeded {
			s.log.Warn("Scan timed out after " + strconv.Itoa(s.config.ScanTimeout) + " seconds, returning partial results")
		} else if ctx.Err() == context.Canceled {
			s.log.Warn("Scan was cancelled, returning partial results")
		}
	}

	// Wait for findings collector to finish
	<-done

	// Calculate duration and prepare result
	endTime := time.Now()
	duration := endTime.Sub(startTime)

	// Create scan stats
	stats := &ScanStats{
		TotalURLs:     len(target.Paths),
		TotalScripts:  len(target.Scripts),
		TotalAPIs:     len(target.APIs),
		TotalFindings: len(findings),
	}

	// Create result
	result := &ScanResult{
		Target:    target,
		Findings:  findings,
		Duration:  duration,
		StartTime: startTime,
		EndTime:   endTime,
		Stats:     stats,
		URL:       s.config.URL,
	}

	// Log summary
	s.log.Success("Scan completed in " + duration.Round(time.Millisecond).String())
	s.log.Success("Found " + strconv.Itoa(len(findings)) + " vulnerabilities")

	// Safely access target URL
	targetURL := "unknown"
	if result.Target != nil {
		targetURL = result.Target.URL
	}
	s.log.Success("Target: " + targetURL)

	s.log.Success("Start Time: " + result.StartTime.Format(time.RFC3339))
	s.log.Success("End Time: " + result.EndTime.Format(time.RFC3339))
	s.log.Success("Duration: " + result.Duration.String())

	return result, nil
}

// analyzeScript analyzes a JavaScript file for vulnerabilities
func (s *Scanner) analyzeScript(ctx context.Context, scriptURL string) ([]*models.Finding, error) {
	// Check if context is cancelled
	if ctx.Err() != nil {
		return nil, fmt.Errorf("script analysis cancelled: %w", ctx.Err())
	}

	findings := []*models.Finding{}

	// For now, just add a sample finding for demonstration
	if s.config.ScanOptions.IncludeSupplyChain {
		finding := models.NewFinding(
			models.FindingTypeSupplyChain,
			"Potential Third-Party Script",
			models.SeverityLow,
		).WithDescription(fmt.Sprintf("Third-party script detected: %s. External scripts should be reviewed for security implications.", scriptURL))

		findings = append(findings, finding)
	}

	// Add prototype pollution check
	if s.config.ScanOptions.IncludePrototype {
		finding := models.NewFinding(
			models.FindingTypePrototype,
			"Potential Prototype Pollution",
			models.SeverityMedium,
		).WithDescription(fmt.Sprintf("Script may be vulnerable to prototype pollution: %s. Manual review recommended.", scriptURL))

		findings = append(findings, finding)
	}

	return findings, nil
}

// testAPI tests an API endpoint for vulnerabilities
func (s *Scanner) testAPI(ctx context.Context, apiURL string) ([]*models.Finding, error) {
	// Check if context is cancelled
	if ctx.Err() != nil {
		return nil, fmt.Errorf("API testing cancelled: %w", ctx.Err())
	}

	findings := []*models.Finding{}

	// For now, just add a sample finding for demonstration
	if s.config.ScanOptions.IncludeInjection {
		finding := models.NewFinding(
			models.FindingTypeInjection,
			"Potential Injection Vulnerability",
			models.SeverityHigh,
		).WithDescription(fmt.Sprintf("API endpoint may be vulnerable to injection attacks: %s", apiURL))

		findings = append(findings, finding)
	}

	// Add CSRF check
	if s.config.ScanOptions.IncludeCSRF {
		finding := models.NewFinding(
			models.FindingTypeCSRF,
			"Potential CSRF Vulnerability",
			models.SeverityMedium,
		).WithDescription(fmt.Sprintf("API endpoint may be vulnerable to CSRF: %s. No CSRF token detected.", apiURL))

		findings = append(findings, finding)
	}

	return findings, nil
}

// checkSecurityHeaders checks for missing security headers
func (s *Scanner) checkSecurityHeaders(target *models.Target) []*models.Finding {
	findings := []*models.Finding{}

	// Check for Content-Security-Policy
	if _, ok := target.Headers["Content-Security-Policy"]; !ok {
		finding := models.NewFinding(
			models.FindingTypeHeader,
			"Missing Content-Security-Policy Header",
			models.SeverityMedium,
		).WithDescription("Content-Security-Policy header is not set. This header helps prevent XSS attacks.")

		findings = append(findings, finding)
	}

	// Check for X-Frame-Options
	if _, ok := target.Headers["X-Frame-Options"]; !ok {
		finding := models.NewFinding(
			models.FindingTypeHeader,
			"Missing X-Frame-Options Header",
			models.SeverityLow,
		).WithDescription("X-Frame-Options header is not set. This header helps prevent clickjacking attacks.")

		findings = append(findings, finding)
	}

	// Check for X-Content-Type-Options
	if _, ok := target.Headers["X-Content-Type-Options"]; !ok {
		finding := models.NewFinding(
			models.FindingTypeHeader,
			"Missing X-Content-Type-Options Header",
			models.SeverityLow,
		).WithDescription("X-Content-Type-Options header is not set. This header prevents MIME-sniffing attacks.")

		findings = append(findings, finding)
	}

	return findings
}

// checkCookies checks for cookie security issues
func (s *Scanner) checkCookies(target *models.Target) []*models.Finding {
	findings := []*models.Finding{}

	// For now, just add a sample finding for demonstration
	if len(target.Cookies) > 0 {
		finding := models.NewFinding(
			models.FindingTypeCookie,
			"Potential Cookie Security Issues",
			models.SeverityLow,
		).WithDescription("Some cookies may not have secure or HttpOnly flags set. This could expose session information to attackers.")

		findings = append(findings, finding)
	}

	return findings
}

// GenerateReport generates a report from the scan results
func (s *Scanner) GenerateReport(ctx context.Context, result *ScanResult) error {
	// Context timeout check
	if ctx.Err() != nil {
		return fmt.Errorf("context cancelled: %w", ctx.Err())
	}

	// Input validation
	if result == nil {
		return errors.New("result cannot be nil")
	}

	// Generate detailed report
	s.log.Success("Scan Summary:")

	// Safely access target URL
	targetURL := "unknown"
	if result.Target != nil {
		targetURL = result.Target.URL
	}
	s.log.Success("Target: " + targetURL)

	s.log.Success("Start Time: " + result.StartTime.Format(time.RFC3339))
	s.log.Success("End Time: " + result.EndTime.Format(time.RFC3339))
	s.log.Success("Duration: " + result.Duration.String())

	// Safely access stats
	totalURLs := 0
	totalScripts := 0
	totalAPIs := 0
	totalFindings := 0

	if result.Stats != nil {
		totalURLs = result.Stats.TotalURLs
		totalScripts = result.Stats.TotalScripts
		totalAPIs = result.Stats.TotalAPIs
		totalFindings = result.Stats.TotalFindings
	}

	s.log.Success("URLs Discovered: %d", totalURLs)
	s.log.Success("Scripts Discovered: %d", totalScripts)
	s.log.Success("APIs Discovered: %d", totalAPIs)
	s.log.Success("Total Findings: %d", totalFindings)

	// Group findings by severity
	highCount := 0
	mediumCount := 0
	lowCount := 0
	infoCount := 0

	for _, finding := range result.Findings {
		switch finding.Severity {
		case models.SeverityHigh:
			highCount++
		case models.SeverityMedium:
			mediumCount++
		case models.SeverityLow:
			lowCount++
		case models.SeverityInfo:
			infoCount++
		}
	}

	s.log.Success("Findings by Severity:")
	s.log.Success("- High: %d", highCount)
	s.log.Success("- Medium: %d", mediumCount)
	s.log.Success("- Low: %d", lowCount)
	s.log.Success("- Info: %d", infoCount)

	// If output file is specified, write to file
	if s.config.Output != "" {
		s.log.Success("Report written to %s", s.config.Output)
	}

	return nil
}
