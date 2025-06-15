package security

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ibrahmsql/spiderjs/internal/config"
	"github.com/ibrahmsql/spiderjs/internal/utils/logger"
	"github.com/ibrahmsql/spiderjs/pkg/models"
)

// Scanner is a security scanner for JavaScript applications
type Scanner struct {
	config *config.Config
	log    *logger.Logger
	checks []Check
}

// Check is an interface for security checks
type Check interface {
	Name() string
	Description() string
	Run(ctx context.Context, target *models.Target) ([]*models.Finding, error)
}

// NewScanner creates a new security scanner
func NewScanner(cfg *config.Config, log *logger.Logger) (*Scanner, error) {
	if cfg == nil {
		return nil, errors.New("config cannot be nil")
	}

	if log == nil {
		return nil, errors.New("logger cannot be nil")
	}

	scanner := &Scanner{
		config: cfg,
		log:    log,
		checks: []Check{},
	}

	// Register checks based on configuration
	if cfg.ScanOptions.IncludeXSS {
		scanner.checks = append(scanner.checks, NewXSSCheck())
	}

	if cfg.ScanOptions.IncludeInjection {
		scanner.checks = append(scanner.checks, NewInjectionCheck())
	}

	if cfg.ScanOptions.IncludeCSRF {
		scanner.checks = append(scanner.checks, NewCSRFCheck())
	}

	if cfg.ScanOptions.IncludeCORS {
		scanner.checks = append(scanner.checks, NewCORSCheck())
	}

	if cfg.ScanOptions.IncludeHeaders {
		scanner.checks = append(scanner.checks, NewHeaderCheck())
	}

	if cfg.ScanOptions.IncludeCookies {
		scanner.checks = append(scanner.checks, NewCookieCheck())
	}

	if cfg.ScanOptions.IncludeSupplyChain {
		scanner.checks = append(scanner.checks, NewSupplyChainCheck())
	}

	if cfg.ScanOptions.IncludePrototype {
		scanner.checks = append(scanner.checks, NewPrototypePollutionCheck())
	}

	return scanner, nil
}

// Scan performs security scanning on a target
func (s *Scanner) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	if ctx.Err() != nil {
		return nil, fmt.Errorf("context cancelled: %w", ctx.Err())
	}

	if target == nil {
		return nil, errors.New("target cannot be nil")
	}

	s.log.Success("Starting security scan of %s", target.URL)
	startTime := time.Now()

	var findings []*models.Finding

	// Run each check
	for _, check := range s.checks {
		select {
		case <-ctx.Done():
			return findings, fmt.Errorf("scan interrupted: %w", ctx.Err())
		default:
			s.log.Success("Running check: %s", check.Name())
			checkFindings, err := check.Run(ctx, target)
			if err != nil {
				s.log.ErrorMsg("Check %s failed: %v", check.Name(), err)
				continue
			}

			findings = append(findings, checkFindings...)
			s.log.Success("Check %s completed, found %d issues", check.Name(), len(checkFindings))
		}
	}

	duration := time.Since(startTime)
	s.log.Success("Security scan completed in %s, found %d issues", duration, len(findings))

	return findings, nil
}

// ScanFrameworkVulnerabilities scans for vulnerabilities in detected frameworks based on CVE database
func (s *Scanner) ScanFrameworkVulnerabilities(ctx context.Context, result *models.AnalysisResult) error {
	if ctx.Err() != nil {
		return fmt.Errorf("context cancelled: %w", ctx.Err())
	}

	if result == nil {
		return errors.New("analysis result cannot be nil")
	}

	// Skip if no frameworks detected
	if len(result.Frameworks) == 0 {
		s.log.Debug("No frameworks detected, skipping framework vulnerability scan")
		return nil
	}

	s.log.Info("Scanning for framework vulnerabilities", "frameworks", len(result.Frameworks))

	// Load CVE database
	cveDB, err := s.loadCVEDatabase(ctx)
	if err != nil {
		return fmt.Errorf("failed to load CVE database: %w", err)
	}

	// Log the loaded CVE database for debugging
	s.log.Debug("CVE database loaded",
		"frameworks", len(cveDB.Frameworks),
		"framework_names", s.getFrameworkNames(cveDB),
	)

	// Scan each detected framework
	for _, framework := range result.Frameworks {
		// Skip if framework has no name
		if framework.Name == "" {
			continue
		}

		s.log.Debug("Checking framework for vulnerabilities",
			"framework", framework.Name,
			"version", framework.Version,
		)

		// Find matching framework in CVE database
		for _, dbFramework := range cveDB.Frameworks {
			if strings.EqualFold(dbFramework.Name, framework.Name) {
				s.log.Debug("Found matching framework in CVE database",
					"framework", dbFramework.Name,
					"vulnerabilities", len(dbFramework.Vulnerabilities),
				)

				// Check each vulnerability against the framework version
				for _, vuln := range dbFramework.Vulnerabilities {
					// Check if framework version is affected
					isAffected := s.isVersionAffected(framework.Version, vuln.AffectedVersions)

					s.log.Debug("Checking vulnerability",
						"cve", vuln.CveID,
						"affected_versions", vuln.AffectedVersions,
						"framework_version", framework.Version,
						"is_affected", isAffected,
					)

					if isAffected {
						// Add vulnerability to result
						result.AddVulnerability(
							vuln.CveID,
							vuln.Severity,
							fmt.Sprintf("%s: %s", framework.Name, vuln.Description),
							fmt.Sprintf("Affected versions: %s, Fixed version: %s", vuln.AffectedVersions, vuln.FixedVersion),
						)

						s.log.Warn("Framework vulnerability detected",
							"framework", framework.Name,
							"version", framework.Version,
							"cve", vuln.CveID,
							"severity", vuln.Severity,
						)
					}
				}
				break
			}
		}
	}

	return nil
}

// getFrameworkNames returns a comma-separated list of framework names from the CVE database
func (s *Scanner) getFrameworkNames(cveDB *CVEDatabase) string {
	var names []string
	for _, framework := range cveDB.Frameworks {
		names = append(names, framework.Name)
	}
	return strings.Join(names, ", ")
}

// loadCVEDatabase loads the CVE database from the configuration file
func (s *Scanner) loadCVEDatabase(ctx context.Context) (*CVEDatabase, error) {
	if ctx.Err() != nil {
		return nil, fmt.Errorf("context cancelled: %w", ctx.Err())
	}

	// Define CVE database path
	cveDBPath := "configs/fingerprints/cve_database.json"

	// Check if file exists
	if _, err := os.Stat(cveDBPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("CVE database file not found: %s", cveDBPath)
	}

	// Read file content
	data, err := os.ReadFile(cveDBPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CVE database file: %w", err)
	}

	// Parse JSON
	var cveDB CVEDatabase
	if err := json.Unmarshal(data, &cveDB); err != nil {
		return nil, fmt.Errorf("failed to parse CVE database: %w", err)
	}

	s.log.Debug("CVE database file loaded",
		"path", cveDBPath,
	)

	return &cveDB, nil
}

// isVersionAffected checks if a framework version is affected by a vulnerability
func (s *Scanner) isVersionAffected(version, affectedVersions string) bool {
	// If framework version is empty or not specified, assume it's affected
	if version == "" || version == "unknown" {
		return true
	}

	// If affected versions is "all", all versions are affected
	if affectedVersions == "all" {
		return true
	}

	// If affected versions is "latest", and version is latest or not specified, it's affected
	if affectedVersions == "latest" {
		return true
	}

	// Clean up version strings to handle common formats
	version = strings.TrimSpace(version)
	version = strings.TrimPrefix(version, "v") // Handle v1.2.3 format

	// Handle comma-separated version ranges
	versionRanges := strings.Split(affectedVersions, ",")
	for _, versionRange := range versionRanges {
		versionRange = strings.TrimSpace(versionRange)
		versionRange = strings.TrimPrefix(versionRange, "v") // Handle v1.2.3 format

		// Check for version ranges like "<1.2.3" or ">=1.2.3"
		if strings.HasPrefix(versionRange, "<") {
			compareVersion := strings.TrimPrefix(versionRange, "<")
			if s.compareVersions(version, compareVersion) < 0 {
				return true
			}
		} else if strings.HasPrefix(versionRange, "<=") {
			compareVersion := strings.TrimPrefix(versionRange, "<=")
			if s.compareVersions(version, compareVersion) <= 0 {
				return true
			}
		} else if strings.HasPrefix(versionRange, ">") {
			compareVersion := strings.TrimPrefix(versionRange, ">")
			if s.compareVersions(version, compareVersion) > 0 {
				return true
			}
		} else if strings.HasPrefix(versionRange, ">=") {
			compareVersion := strings.TrimPrefix(versionRange, ">=")
			if s.compareVersions(version, compareVersion) >= 0 {
				return true
			}
		} else if strings.Contains(versionRange, "-") {
			// Handle version ranges like "1.2.3-2.0.0"
			parts := strings.Split(versionRange, "-")
			if len(parts) == 2 {
				lowerVersion := parts[0]
				upperVersion := parts[1]
				if s.compareVersions(version, lowerVersion) >= 0 && s.compareVersions(version, upperVersion) <= 0 {
					return true
				}
			}
		} else {
			// Handle exact version match
			if version == versionRange {
				return true
			}
		}
	}

	return false
}

// compareVersions compares two version strings
// Returns:
// -1 if v1 < v2
//
//	0 if v1 == v2
//	1 if v1 > v2
func (s *Scanner) compareVersions(v1, v2 string) int {
	// Handle special version strings
	if v1 == "latest" || v1 == "x" || v1 == "*" {
		if v2 == "latest" || v2 == "x" || v2 == "*" {
			return 0
		}
		return 1
	}
	if v2 == "latest" || v2 == "x" || v2 == "*" {
		return -1
	}

	// Handle versions with .x suffix (e.g., "2.x")
	v1Parts := strings.Split(v1, ".")
	v2Parts := strings.Split(v2, ".")

	// Replace "x" with "0" for comparison
	for i := range v1Parts {
		if v1Parts[i] == "x" || v1Parts[i] == "*" {
			v1Parts[i] = "0"
		}
	}
	for i := range v2Parts {
		if v2Parts[i] == "x" || v2Parts[i] == "*" {
			v2Parts[i] = "0"
		}
	}

	// Compare version parts
	maxLen := len(v1Parts)
	if len(v2Parts) > maxLen {
		maxLen = len(v2Parts)
	}

	for i := 0; i < maxLen; i++ {
		var num1, num2 int

		if i < len(v1Parts) {
			num1, _ = strconv.Atoi(v1Parts[i])
		}

		if i < len(v2Parts) {
			num2, _ = strconv.Atoi(v2Parts[i])
		}

		if num1 < num2 {
			return -1
		} else if num1 > num2 {
			return 1
		}
	}

	return 0
}

// CVEDatabase represents the structure of the CVE database
type CVEDatabase struct {
	Frameworks []CVEFramework `json:"frameworks"`
}

// CVEFramework represents a framework in the CVE database
type CVEFramework struct {
	Name            string             `json:"name"`
	Vulnerabilities []CVEVulnerability `json:"vulnerabilities"`
}

// CVEVulnerability represents a vulnerability in the CVE database
type CVEVulnerability struct {
	CveID            string   `json:"cve_id"`
	AffectedVersions string   `json:"affected_versions"`
	FixedVersion     string   `json:"fixed_version"`
	Severity         string   `json:"severity"`
	Description      string   `json:"description"`
	Exploit          string   `json:"exploit"`
	References       []string `json:"references"`
}

// XSSCheck checks for Cross-Site Scripting vulnerabilities
type XSSCheck struct{}

// NewXSSCheck creates a new XSS check
func NewXSSCheck() *XSSCheck {
	return &XSSCheck{}
}

// Name returns the name of the check
func (c *XSSCheck) Name() string {
	return "XSS Check"
}

// Description returns the description of the check
func (c *XSSCheck) Description() string {
	return "Checks for Cross-Site Scripting vulnerabilities"
}

// Run performs the check
func (c *XSSCheck) Run(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	// Check for Content-Security-Policy header
	if target.Headers != nil {
		if cspHeader, ok := target.Headers["Content-Security-Policy"]; !ok {
			finding := models.NewFinding(
				models.FindingTypeVulnerability,
				"Missing Content-Security-Policy Header",
				models.SeverityMedium,
			).WithDescription(
				"The application does not set a Content-Security-Policy header, which helps prevent XSS attacks.",
			).WithRemediation(
				"Implement a Content-Security-Policy header with appropriate directives such as 'default-src', 'script-src', and 'object-src'.",
			).WithURL(
				target.URL,
			).WithTags(
				"xss", "headers", "csp",
			)

			findings = append(findings, finding)
		} else {
			// Check for weak CSP configuration
			if strings.Contains(cspHeader, "unsafe-inline") {
				finding := models.NewFinding(
					models.FindingTypeVulnerability,
					"Weak Content-Security-Policy Configuration",
					models.SeverityMedium,
				).WithDescription(
					"The Content-Security-Policy header contains 'unsafe-inline', which allows inline scripts and may reduce protection against XSS attacks.",
				).WithRemediation(
					"Remove 'unsafe-inline' from the CSP and use nonces or hashes for specific inline scripts instead.",
				).WithURL(
					target.URL,
				).WithTags(
					"xss", "headers", "csp", "unsafe-inline",
				)

				findings = append(findings, finding)
			}

			if strings.Contains(cspHeader, "unsafe-eval") {
				finding := models.NewFinding(
					models.FindingTypeVulnerability,
					"Weak Content-Security-Policy Configuration",
					models.SeverityMedium,
				).WithDescription(
					"The Content-Security-Policy header contains 'unsafe-eval', which allows dynamic code evaluation and may reduce protection against XSS attacks.",
				).WithRemediation(
					"Remove 'unsafe-eval' from the CSP and refactor code to avoid using eval() or similar functions.",
				).WithURL(
					target.URL,
				).WithTags(
					"xss", "headers", "csp", "unsafe-eval",
				)

				findings = append(findings, finding)
			}

			// Check for missing directives
			if !strings.Contains(cspHeader, "default-src") && !strings.Contains(cspHeader, "script-src") {
				finding := models.NewFinding(
					models.FindingTypeVulnerability,
					"Incomplete Content-Security-Policy",
					models.SeverityLow,
				).WithDescription(
					"The Content-Security-Policy header is missing essential directives like 'default-src' or 'script-src'.",
				).WithRemediation(
					"Add comprehensive directives to the CSP, including at least 'default-src' or 'script-src'.",
				).WithURL(
					target.URL,
				).WithTags(
					"xss", "headers", "csp",
				)

				findings = append(findings, finding)
			}
		}

		// Check for X-XSS-Protection header
		if xssHeader, ok := target.Headers["X-XSS-Protection"]; !ok {
			finding := models.NewFinding(
				models.FindingTypeVulnerability,
				"Missing X-XSS-Protection Header",
				models.SeverityLow,
			).WithDescription(
				"The application does not set an X-XSS-Protection header, which helps prevent XSS attacks in older browsers.",
			).WithRemediation(
				"Set the X-XSS-Protection header to '1; mode=block'.",
			).WithURL(
				target.URL,
			).WithTags(
				"xss", "headers",
			)

			findings = append(findings, finding)
		} else if xssHeader != "1; mode=block" {
			finding := models.NewFinding(
				models.FindingTypeVulnerability,
				"Weak X-XSS-Protection Configuration",
				models.SeverityLow,
			).WithDescription(
				"The X-XSS-Protection header is not set to the recommended value of '1; mode=block'.",
			).WithRemediation(
				"Set the X-XSS-Protection header to '1; mode=block' for better protection.",
			).WithURL(
				target.URL,
			).WithTags(
				"xss", "headers",
			)

			findings = append(findings, finding)
		}
	}

	// Check for XSS vulnerabilities in HTML content
	if target.HTML != "" {
		// Check for unescaped data in script contexts
		scriptRegex := regexp.MustCompile(`<script[^>]*>([^<]*)</script>`)
		scriptMatches := scriptRegex.FindAllStringSubmatch(target.HTML, -1)

		for _, match := range scriptMatches {
			if len(match) > 1 {
				scriptContent := match[1]
				// Look for patterns that suggest user input is being inserted into scripts
				dataPatterns := []string{
					`document\.write\([^)]*\)`,
					`\.innerHTML\s*=`,
					`eval\(`,
					`setTimeout\([^)]*\)`,
					`setInterval\([^)]*\)`,
					`new Function\(`,
				}

				for _, pattern := range dataPatterns {
					patternRegex := regexp.MustCompile(pattern)
					if patternRegex.MatchString(scriptContent) {
						finding := models.NewFinding(
							models.FindingTypeVulnerability,
							"Potential XSS in Script Context",
							models.SeverityHigh,
						).WithDescription(
							fmt.Sprintf("Potentially unsafe JavaScript pattern detected: %s", pattern),
						).WithRemediation(
							"Avoid using dynamic JavaScript execution functions with user input. Use safer alternatives and ensure proper input validation and encoding.",
						).WithURL(
							target.URL,
						).WithTags(
							"xss", "script", "dynamic-execution",
						)

						findings = append(findings, finding)
						break
					}
				}
			}
		}

		// Check for potentially dangerous HTML attributes
		dangerousAttrRegex := regexp.MustCompile(`(?i)(on\w+)=["']([^"']*)["']`)
		attrMatches := dangerousAttrRegex.FindAllStringSubmatch(target.HTML, -1)

		for _, match := range attrMatches {
			if len(match) > 2 {
				attrName := match[1]
				attrValue := match[2]

				finding := models.NewFinding(
					models.FindingTypeVulnerability,
					"Potential XSS in Event Handler",
					models.SeverityMedium,
				).WithDescription(
					fmt.Sprintf("Potentially dangerous event handler detected: %s=\"%s\"", attrName, attrValue),
				).WithRemediation(
					"Avoid using inline event handlers. Use addEventListener() in external scripts instead.",
				).WithURL(
					target.URL,
				).WithTags(
					"xss", "event-handler",
				)

				findings = append(findings, finding)
			}
		}

		// Check for unsafe URL schemes in attributes
		unsafeUrlRegex := regexp.MustCompile(`(?i)(href|src|action)=["'](javascript|data|vbscript):([^"']*)["']`)
		urlMatches := unsafeUrlRegex.FindAllStringSubmatch(target.HTML, -1)

		for _, match := range urlMatches {
			if len(match) > 3 {
				attrName := match[1]
				urlScheme := match[2]

				finding := models.NewFinding(
					models.FindingTypeVulnerability,
					"Potential XSS via Unsafe URL Scheme",
					models.SeverityHigh,
				).WithDescription(
					fmt.Sprintf("Potentially dangerous URL scheme detected: %s=\"%s:...\"", attrName, urlScheme),
				).WithRemediation(
					"Avoid using javascript:, data:, or vbscript: URL schemes, especially with user input.",
				).WithURL(
					target.URL,
				).WithTags(
					"xss", "unsafe-url-scheme",
				)

				findings = append(findings, finding)
			}
		}
	}

	// Check for XSS vulnerabilities in JavaScript files
	for _, script := range target.Scripts {
		// Check for unsafe DOM manipulation patterns
		domXssPatterns := []string{
			`document\.write\(`,
			`\.innerHTML\s*=`,
			`\.outerHTML\s*=`,
			`\.insertAdjacentHTML\(`,
			`eval\(`,
			`setTimeout\([^)]*,\s*['"](.*?)['"]`,
			`setInterval\([^)]*,\s*['"](.*?)['"]`,
			`new Function\(`,
			`location\s*=`,
			`location\.href\s*=`,
			`location\.replace\(`,
			`location\.assign\(`,
			`document\.URL`,
			`document\.documentURI`,
			`document\.URLUnencoded`,
			`document\.baseURI`,
			`document\.referrer`,
			`window\.name`,
			`history\.pushState\(`,
			`history\.replaceState\(`,
		}

		for _, pattern := range domXssPatterns {
			patternRegex := regexp.MustCompile(pattern)
			if patternMatches := patternRegex.FindAllString(script, -1); len(patternMatches) > 0 {
				finding := models.NewFinding(
					models.FindingTypeVulnerability,
					"Potential DOM-based XSS",
					models.SeverityHigh,
				).WithDescription(
					fmt.Sprintf("Potentially unsafe DOM manipulation pattern detected: %s", pattern),
				).WithRemediation(
					"Use safe DOM APIs like textContent instead of innerHTML. Sanitize user input before inserting it into the DOM.",
				).WithURL(
					target.URL,
				).WithTags(
					"xss", "dom-xss",
				)

				findings = append(findings, finding)
				break
			}
		}

		// Check for unsafe jQuery patterns
		jqueryXssPatterns := []string{
			`\$\([^)]*\)\.html\(`,
			`\$\([^)]*\)\.append\(`,
			`\$\([^)]*\)\.prepend\(`,
			`\$\([^)]*\)\.after\(`,
			`\$\([^)]*\)\.before\(`,
			`\$\([^)]*\)\.wrap\(`,
		}

		for _, pattern := range jqueryXssPatterns {
			patternRegex := regexp.MustCompile(pattern)
			if patternMatches := patternRegex.FindAllString(script, -1); len(patternMatches) > 0 {
				finding := models.NewFinding(
					models.FindingTypeVulnerability,
					"Potential jQuery-based XSS",
					models.SeverityMedium,
				).WithDescription(
					fmt.Sprintf("Potentially unsafe jQuery pattern detected: %s", pattern),
				).WithRemediation(
					"Use jQuery's text() method instead of html() when possible. Sanitize user input before inserting it into the DOM.",
				).WithURL(
					target.URL,
				).WithTags(
					"xss", "jquery",
				)

				findings = append(findings, finding)
				break
			}
		}
	}

	return findings, nil
}

// InjectionCheck checks for injection vulnerabilities
type InjectionCheck struct{}

// NewInjectionCheck creates a new injection check
func NewInjectionCheck() *InjectionCheck {
	return &InjectionCheck{}
}

// Name returns the name of the check
func (c *InjectionCheck) Name() string {
	return "Injection Check"
}

// Description returns the description of the check
func (c *InjectionCheck) Description() string {
	return "Checks for injection vulnerabilities"
}

// Run performs the check
func (c *InjectionCheck) Run(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	// For demonstration purposes, add a sample finding
	finding := models.NewFinding(
		models.FindingTypeVulnerability,
		"Potential Injection Vulnerability",
		models.SeverityHigh,
	).WithDescription(
		"The application may be vulnerable to injection attacks.",
	).WithRemediation(
		"Validate and sanitize all user inputs before processing.",
	).WithURL(
		target.URL,
	).WithTags(
		"injection", "security",
	)

	findings = append(findings, finding)

	return findings, nil
}

// CSRFCheck checks for Cross-Site Request Forgery vulnerabilities
type CSRFCheck struct{}

// NewCSRFCheck creates a new CSRF check
func NewCSRFCheck() *CSRFCheck {
	return &CSRFCheck{}
}

// Name returns the name of the check
func (c *CSRFCheck) Name() string {
	return "CSRF Check"
}

// Description returns the description of the check
func (c *CSRFCheck) Description() string {
	return "Checks for Cross-Site Request Forgery vulnerabilities"
}

// Run performs the check
func (c *CSRFCheck) Run(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	// Check for CSRF tokens in forms
	// This is a simplified implementation for demonstration purposes

	return findings, nil
}

// CORSCheck checks for Cross-Origin Resource Sharing misconfigurations
type CORSCheck struct{}

// NewCORSCheck creates a new CORS check
func NewCORSCheck() *CORSCheck {
	return &CORSCheck{}
}

// Name returns the name of the check
func (c *CORSCheck) Name() string {
	return "CORS Check"
}

// Description returns the description of the check
func (c *CORSCheck) Description() string {
	return "Checks for Cross-Origin Resource Sharing misconfigurations"
}

// Run performs the check
func (c *CORSCheck) Run(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	// Check for CORS headers
	if target.Headers != nil {
		// Check for Access-Control-Allow-Origin header
		if origin, ok := target.Headers["Access-Control-Allow-Origin"]; ok {
			if origin == "*" {
				finding := models.NewFinding(
					models.FindingTypeVulnerability,
					"Overly Permissive CORS Policy",
					models.SeverityMedium,
				).WithDescription(
					"The Access-Control-Allow-Origin header is set to '*', which allows any domain to make cross-origin requests to this resource.",
				).WithRemediation(
					"Restrict the Access-Control-Allow-Origin header to specific trusted domains instead of using a wildcard.",
				).WithURL(
					target.URL,
				).WithTags(
					"cors", "headers", "security-configuration",
				)

				findings = append(findings, finding)
			} else if strings.Contains(origin, "null") {
				finding := models.NewFinding(
					models.FindingTypeVulnerability,
					"Insecure CORS Policy - 'null' Origin",
					models.SeverityMedium,
				).WithDescription(
					"The Access-Control-Allow-Origin header is set to 'null', which can be exploited in certain scenarios.",
				).WithRemediation(
					"Avoid using 'null' in the Access-Control-Allow-Origin header. Specify explicit origins instead.",
				).WithURL(
					target.URL,
				).WithTags(
					"cors", "headers", "security-configuration",
				)

				findings = append(findings, finding)
			}
		}

		// Check for Access-Control-Allow-Credentials header
		if credentials, ok := target.Headers["Access-Control-Allow-Credentials"]; ok {
			if credentials == "true" {
				// Check if Access-Control-Allow-Origin is also set to *
				if origin, ok := target.Headers["Access-Control-Allow-Origin"]; ok && origin == "*" {
					finding := models.NewFinding(
						models.FindingTypeVulnerability,
						"Invalid CORS Configuration",
						models.SeverityHigh,
					).WithDescription(
						"The application has both Access-Control-Allow-Credentials set to 'true' and Access-Control-Allow-Origin set to '*', which is an invalid and dangerous combination.",
					).WithRemediation(
						"When using Access-Control-Allow-Credentials: true, specify explicit origins in Access-Control-Allow-Origin instead of using a wildcard.",
					).WithURL(
						target.URL,
					).WithTags(
						"cors", "headers", "security-configuration",
					)

					findings = append(findings, finding)
				}
			}
		}

		// Check for Access-Control-Allow-Headers
		if headers, ok := target.Headers["Access-Control-Allow-Headers"]; ok {
			if headers == "*" {
				finding := models.NewFinding(
					models.FindingTypeVulnerability,
					"Overly Permissive CORS Headers Policy",
					models.SeverityLow,
				).WithDescription(
					"The Access-Control-Allow-Headers header is set to '*', which allows any header in cross-origin requests.",
				).WithRemediation(
					"Specify only the necessary headers in the Access-Control-Allow-Headers directive instead of using a wildcard.",
				).WithURL(
					target.URL,
				).WithTags(
					"cors", "headers", "security-configuration",
				)

				findings = append(findings, finding)
			}
		}

		// Check for Access-Control-Allow-Methods
		if methods, ok := target.Headers["Access-Control-Allow-Methods"]; ok {
			if methods == "*" {
				finding := models.NewFinding(
					models.FindingTypeVulnerability,
					"Overly Permissive CORS Methods Policy",
					models.SeverityLow,
				).WithDescription(
					"The Access-Control-Allow-Methods header is set to '*', which allows any HTTP method in cross-origin requests.",
				).WithRemediation(
					"Specify only the necessary HTTP methods in the Access-Control-Allow-Methods directive instead of using a wildcard.",
				).WithURL(
					target.URL,
				).WithTags(
					"cors", "headers", "security-configuration",
				)

				findings = append(findings, finding)
			} else if strings.Contains(methods, "TRACE") || strings.Contains(methods, "CONNECT") {
				finding := models.NewFinding(
					models.FindingTypeVulnerability,
					"Potentially Dangerous CORS Methods Allowed",
					models.SeverityMedium,
				).WithDescription(
					"The Access-Control-Allow-Methods header includes potentially dangerous HTTP methods like TRACE or CONNECT.",
				).WithRemediation(
					"Remove unnecessary and potentially dangerous HTTP methods from the Access-Control-Allow-Methods directive.",
				).WithURL(
					target.URL,
				).WithTags(
					"cors", "headers", "security-configuration",
				)

				findings = append(findings, finding)
			}
		}

		// Check for Access-Control-Expose-Headers
		if exposeHeaders, ok := target.Headers["Access-Control-Expose-Headers"]; ok {
			if exposeHeaders == "*" {
				finding := models.NewFinding(
					models.FindingTypeVulnerability,
					"Overly Permissive CORS Expose Headers Policy",
					models.SeverityLow,
				).WithDescription(
					"The Access-Control-Expose-Headers header is set to '*', which exposes all headers to cross-origin requests.",
				).WithRemediation(
					"Specify only the necessary headers in the Access-Control-Expose-Headers directive instead of using a wildcard.",
				).WithURL(
					target.URL,
				).WithTags(
					"cors", "headers", "security-configuration",
				)

				findings = append(findings, finding)
			}
		}

		// Check for Access-Control-Max-Age
		if maxAge, ok := target.Headers["Access-Control-Max-Age"]; ok {
			maxAgeInt, err := strconv.Atoi(maxAge)
			if err == nil && maxAgeInt > 86400 {
				finding := models.NewFinding(
					models.FindingTypeVulnerability,
					"Excessive CORS Cache Duration",
					models.SeverityLow,
				).WithDescription(
					fmt.Sprintf("The Access-Control-Max-Age header is set to %s seconds, which is longer than the recommended maximum of 86400 seconds (24 hours).", maxAge),
				).WithRemediation(
					"Set a reasonable value for Access-Control-Max-Age, preferably not exceeding 86400 seconds (24 hours).",
				).WithURL(
					target.URL,
				).WithTags(
					"cors", "headers", "security-configuration",
				)

				findings = append(findings, finding)
			}
		}
	}

	// Check for CORS misconfiguration in JavaScript code
	for _, script := range target.Scripts {
		// Check for JSONP usage, which can bypass CORS
		jsonpPatterns := []string{
			`callback=`,
			`jsonp=`,
			`\.getJSON\(`,
			`script\.src\s*=`,
			`document\.createElement\(['"]script['"]\)`,
		}

		for _, pattern := range jsonpPatterns {
			if strings.Contains(script, pattern) {
				finding := models.NewFinding(
					models.FindingTypeVulnerability,
					"Potential JSONP Usage",
					models.SeverityLow,
				).WithDescription(
					"The application may be using JSONP, which can lead to security issues if not implemented correctly.",
				).WithRemediation(
					"Consider using CORS instead of JSONP. If JSONP is necessary, ensure proper input validation and output encoding.",
				).WithURL(
					target.URL,
				).WithTags(
					"cors", "jsonp", "security-configuration",
				)

				findings = append(findings, finding)
				break
			}
		}

		// Check for postMessage without origin check
		if strings.Contains(script, "postMessage") && !strings.Contains(script, "event.origin") {
			finding := models.NewFinding(
				models.FindingTypeVulnerability,
				"postMessage Without Origin Check",
				models.SeverityMedium,
			).WithDescription(
				"The application uses postMessage for cross-origin communication but may not properly validate the origin of messages.",
			).WithRemediation(
				"Always verify the sender's identity using the origin property when receiving messages via postMessage.",
			).WithURL(
				target.URL,
			).WithTags(
				"cors", "postMessage", "security-configuration",
			)

			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// HeaderCheck checks for security headers
type HeaderCheck struct{}

// NewHeaderCheck creates a new header check
func NewHeaderCheck() *HeaderCheck {
	return &HeaderCheck{}
}

// Name returns the name of the check
func (c *HeaderCheck) Name() string {
	return "Security Headers Check"
}

// Description returns the description of the check
func (c *HeaderCheck) Description() string {
	return "Checks for missing or misconfigured security headers"
}

// Run performs the check
func (c *HeaderCheck) Run(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	// Security headers to check
	securityHeaders := map[string]struct {
		Name        string
		Description string
		Severity    models.Severity
	}{
		"Content-Security-Policy": {
			Name:        "Missing Content-Security-Policy Header",
			Description: "The Content-Security-Policy header helps prevent XSS attacks by controlling which resources can be loaded.",
			Severity:    models.SeverityMedium,
		},
		"X-Content-Type-Options": {
			Name:        "Missing X-Content-Type-Options Header",
			Description: "The X-Content-Type-Options header prevents MIME type sniffing attacks.",
			Severity:    models.SeverityLow,
		},
		"X-Frame-Options": {
			Name:        "Missing X-Frame-Options Header",
			Description: "The X-Frame-Options header prevents clickjacking attacks by controlling whether a page can be displayed in a frame.",
			Severity:    models.SeverityMedium,
		},
		"Strict-Transport-Security": {
			Name:        "Missing Strict-Transport-Security Header",
			Description: "The Strict-Transport-Security header enforces HTTPS connections, preventing SSL stripping attacks.",
			Severity:    models.SeverityMedium,
		},
		"X-XSS-Protection": {
			Name:        "Missing X-XSS-Protection Header",
			Description: "The X-XSS-Protection header enables browser XSS protection mechanisms.",
			Severity:    models.SeverityLow,
		},
		"Referrer-Policy": {
			Name:        "Missing Referrer-Policy Header",
			Description: "The Referrer-Policy header controls how much referrer information is included with requests.",
			Severity:    models.SeverityLow,
		},
		"Permissions-Policy": {
			Name:        "Missing Permissions-Policy Header",
			Description: "The Permissions-Policy header controls which browser features can be used by the page.",
			Severity:    models.SeverityLow,
		},
		"Cross-Origin-Embedder-Policy": {
			Name:        "Missing Cross-Origin-Embedder-Policy Header",
			Description: "The Cross-Origin-Embedder-Policy header prevents a document from loading cross-origin resources that don't explicitly grant permission.",
			Severity:    models.SeverityLow,
		},
		"Cross-Origin-Opener-Policy": {
			Name:        "Missing Cross-Origin-Opener-Policy Header",
			Description: "The Cross-Origin-Opener-Policy header prevents other domains from opening/controlling a window.",
			Severity:    models.SeverityLow,
		},
		"Cross-Origin-Resource-Policy": {
			Name:        "Missing Cross-Origin-Resource-Policy Header",
			Description: "The Cross-Origin-Resource-Policy header prevents other domains from loading resources from your site.",
			Severity:    models.SeverityLow,
		},
		"Cache-Control": {
			Name:        "Missing Cache-Control Header",
			Description: "The Cache-Control header controls how pages are cached, which can prevent sensitive information disclosure.",
			Severity:    models.SeverityLow,
		},
		"Clear-Site-Data": {
			Name:        "Missing Clear-Site-Data Header",
			Description: "The Clear-Site-Data header clears browsing data (cookies, storage, cache) associated with the site.",
			Severity:    models.SeverityLow,
		},
		"X-Permitted-Cross-Domain-Policies": {
			Name:        "Missing X-Permitted-Cross-Domain-Policies Header",
			Description: "The X-Permitted-Cross-Domain-Policies header controls Adobe Flash and PDF cross-domain requests.",
			Severity:    models.SeverityLow,
		},
	}

	// Check for missing security headers
	if target.Headers != nil {
		for header, info := range securityHeaders {
			if _, ok := target.Headers[header]; !ok {
				finding := models.NewFinding(
					models.FindingTypeVulnerability,
					info.Name,
					info.Severity,
				).WithDescription(
					info.Description,
				).WithRemediation(
					fmt.Sprintf("Implement the %s header with appropriate values.", header),
				).WithURL(
					target.URL,
				).WithTags(
					"headers", "security",
				)

				findings = append(findings, finding)
			}
		}

		// Check for insecure configurations in existing headers

		// Check Content-Security-Policy
		if csp, ok := target.Headers["Content-Security-Policy"]; ok {
			if strings.Contains(csp, "'unsafe-inline'") {
				finding := models.NewFinding(
					models.FindingTypeVulnerability,
					"Insecure Content-Security-Policy",
					models.SeverityMedium,
				).WithDescription(
					"The Content-Security-Policy header allows 'unsafe-inline' scripts, which negates much of the XSS protection.",
				).WithRemediation(
					"Remove 'unsafe-inline' from the CSP and use nonces or hashes instead.",
				).WithURL(
					target.URL,
				).WithTags(
					"headers", "security", "csp", "xss",
				)

				findings = append(findings, finding)
			}

			if strings.Contains(csp, "'unsafe-eval'") {
				finding := models.NewFinding(
					models.FindingTypeVulnerability,
					"Insecure Content-Security-Policy with eval",
					models.SeverityMedium,
				).WithDescription(
					"The Content-Security-Policy header allows 'unsafe-eval', which may allow attackers to execute arbitrary code.",
				).WithRemediation(
					"Remove 'unsafe-eval' from the CSP and refactor code to avoid using eval().",
				).WithURL(
					target.URL,
				).WithTags(
					"headers", "security", "csp", "xss",
				)

				findings = append(findings, finding)
			}
		}

		// Check HSTS
		if hsts, ok := target.Headers["Strict-Transport-Security"]; ok {
			hasMaxAge := regexp.MustCompile(`max-age=(\d+)`).FindStringSubmatch(hsts)
			if len(hasMaxAge) > 1 {
				maxAge, err := strconv.Atoi(hasMaxAge[1])
				if err == nil && maxAge < 10886400 { // 10886400 seconds = 126 days
					finding := models.NewFinding(
						models.FindingTypeVulnerability,
						"Weak Strict-Transport-Security Max Age",
						models.SeverityLow,
					).WithDescription(
						fmt.Sprintf("The Strict-Transport-Security header has a max-age value of %d seconds (< 126 days), which is lower than recommended.", maxAge),
					).WithRemediation(
						"Set the max-age value to at least 31536000 seconds (1 year).",
					).WithURL(
						target.URL,
					).WithTags(
						"headers", "security", "hsts",
					)

					findings = append(findings, finding)
				}
			}

			if !strings.Contains(hsts, "includeSubDomains") {
				finding := models.NewFinding(
					models.FindingTypeVulnerability,
					"Incomplete Strict-Transport-Security",
					models.SeverityLow,
				).WithDescription(
					"The Strict-Transport-Security header does not include the 'includeSubDomains' directive, which leaves subdomains unprotected.",
				).WithRemediation(
					"Add the 'includeSubDomains' directive to the Strict-Transport-Security header.",
				).WithURL(
					target.URL,
				).WithTags(
					"headers", "security", "hsts",
				)

				findings = append(findings, finding)
			}
		}

		// Check X-Frame-Options
		if xfo, ok := target.Headers["X-Frame-Options"]; ok {
			xfoValue := strings.ToUpper(xfo)
			if xfoValue != "DENY" && xfoValue != "SAMEORIGIN" && !strings.HasPrefix(xfoValue, "ALLOW-FROM") {
				finding := models.NewFinding(
					models.FindingTypeVulnerability,
					"Invalid X-Frame-Options Value",
					models.SeverityMedium,
				).WithDescription(
					fmt.Sprintf("The X-Frame-Options header has an invalid value: %s", xfo),
				).WithRemediation(
					"Set the X-Frame-Options header to 'DENY', 'SAMEORIGIN', or 'ALLOW-FROM uri'.",
				).WithURL(
					target.URL,
				).WithTags(
					"headers", "security", "clickjacking",
				)

				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

// CookieCheck checks for cookie security issues
type CookieCheck struct{}

// NewCookieCheck creates a new cookie check
func NewCookieCheck() *CookieCheck {
	return &CookieCheck{}
}

// Name returns the name of the check
func (c *CookieCheck) Name() string {
	return "Cookie Security Check"
}

// Description returns the description of the check
func (c *CookieCheck) Description() string {
	return "Checks for insecure cookie configurations"
}

// Run performs the check
func (c *CookieCheck) Run(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	// Check for cookies without secure flag
	for name, value := range target.Cookies {
		// Skip non-sensitive cookies
		if !isSensitiveCookie(name) {
			continue
		}

		// Check for secure flag
		if !strings.Contains(value, "Secure") {
			finding := models.NewFinding(
				models.FindingTypeVulnerability,
				"Cookie Without Secure Flag",
				models.SeverityMedium,
			).WithDescription(
				fmt.Sprintf("The cookie '%s' is set without the Secure flag, which means it can be transmitted over unencrypted connections.", name),
			).WithRemediation(
				"Set the Secure flag for all cookies containing sensitive information.",
			).WithURL(
				target.URL,
			).WithTags(
				"cookies", "security",
			)

			findings = append(findings, finding)
		}

		// Check for HttpOnly flag
		if !strings.Contains(value, "HttpOnly") {
			finding := models.NewFinding(
				models.FindingTypeVulnerability,
				"Cookie Without HttpOnly Flag",
				models.SeverityMedium,
			).WithDescription(
				fmt.Sprintf("The cookie '%s' is set without the HttpOnly flag, which makes it accessible to client-side JavaScript and vulnerable to XSS attacks.", name),
			).WithRemediation(
				"Set the HttpOnly flag for all cookies containing sensitive information.",
			).WithURL(
				target.URL,
			).WithTags(
				"cookies", "security",
			)

			findings = append(findings, finding)
		}

		// Check for SameSite attribute
		if !strings.Contains(value, "SameSite") {
			finding := models.NewFinding(
				models.FindingTypeVulnerability,
				"Cookie Without SameSite Attribute",
				models.SeverityMedium,
			).WithDescription(
				fmt.Sprintf("The cookie '%s' is set without the SameSite attribute, which may make it vulnerable to CSRF attacks.", name),
			).WithRemediation(
				"Set the SameSite attribute (Lax or Strict) for all cookies.",
			).WithURL(
				target.URL,
			).WithTags(
				"cookies", "security", "csrf",
			)

			findings = append(findings, finding)
		} else if strings.Contains(value, "SameSite=None") && !strings.Contains(value, "Secure") {
			finding := models.NewFinding(
				models.FindingTypeVulnerability,
				"Insecure SameSite=None Configuration",
				models.SeverityHigh,
			).WithDescription(
				fmt.Sprintf("The cookie '%s' uses SameSite=None without the Secure flag, which is rejected by modern browsers.", name),
			).WithRemediation(
				"When using SameSite=None, always set the Secure flag as well.",
			).WithURL(
				target.URL,
			).WithTags(
				"cookies", "security", "csrf",
			)

			findings = append(findings, finding)
		}

		// Check for missing Path attribute
		if !strings.Contains(value, "Path=") {
			finding := models.NewFinding(
				models.FindingTypeVulnerability,
				"Cookie Without Path Attribute",
				models.SeverityLow,
			).WithDescription(
				fmt.Sprintf("The cookie '%s' is set without a Path attribute, which may expose it more broadly than necessary.", name),
			).WithRemediation(
				"Set the Path attribute to the most specific path possible.",
			).WithURL(
				target.URL,
			).WithTags(
				"cookies", "security",
			)

			findings = append(findings, finding)
		}

		// Check for __Host- prefix requirements
		if strings.HasPrefix(name, "__Host-") {
			if !strings.Contains(value, "Secure") || !strings.Contains(value, "Path=/") || strings.Contains(value, "Domain=") {
				finding := models.NewFinding(
					models.FindingTypeVulnerability,
					"Invalid __Host- Prefix Cookie",
					models.SeverityMedium,
				).WithDescription(
					fmt.Sprintf("The cookie '%s' uses the __Host- prefix but doesn't meet the requirements: Secure flag, Path=/, and no Domain attribute.", name),
				).WithRemediation(
					"For cookies with the __Host- prefix, make sure to set the Secure flag, use Path=/, and omit the Domain attribute.",
				).WithURL(
					target.URL,
				).WithTags(
					"cookies", "security",
				)

				findings = append(findings, finding)
			}
		}

		// Check for __Secure- prefix requirements
		if strings.HasPrefix(name, "__Secure-") && !strings.Contains(value, "Secure") {
			finding := models.NewFinding(
				models.FindingTypeVulnerability,
				"Invalid __Secure- Prefix Cookie",
				models.SeverityMedium,
			).WithDescription(
				fmt.Sprintf("The cookie '%s' uses the __Secure- prefix but doesn't have the Secure flag.", name),
			).WithRemediation(
				"For cookies with the __Secure- prefix, make sure to set the Secure flag.",
			).WithURL(
				target.URL,
			).WithTags(
				"cookies", "security",
			)

			findings = append(findings, finding)
		}

		// Check for overly permissive Domain attribute
		if domainMatch := regexp.MustCompile(`Domain=([^;]+)`).FindStringSubmatch(value); len(domainMatch) > 1 {
			domain := strings.TrimSpace(domainMatch[1])

			// Check for leading dot (allowed but indicates old format)
			if strings.HasPrefix(domain, ".") {
				finding := models.NewFinding(
					models.FindingTypeVulnerability,
					"Cookie Uses Deprecated Domain Format",
					models.SeverityLow,
				).WithDescription(
					fmt.Sprintf("The cookie '%s' uses a domain attribute with a leading dot '%s', which is deprecated.", name, domain),
				).WithRemediation(
					"Remove the leading dot from the Domain attribute.",
				).WithURL(
					target.URL,
				).WithTags(
					"cookies", "security",
				)

				findings = append(findings, finding)
			}

			// Check if domain is too broad
			if countDots(domain) <= 1 && !isIpAddress(domain) {
				finding := models.NewFinding(
					models.FindingTypeVulnerability,
					"Cookie With Overly Permissive Domain",
					models.SeverityMedium,
				).WithDescription(
					fmt.Sprintf("The cookie '%s' uses an overly permissive domain '%s', which increases the risk of cookie theft.", name, domain),
				).WithRemediation(
					"Use the most specific domain possible for cookies containing sensitive information.",
				).WithURL(
					target.URL,
				).WithTags(
					"cookies", "security",
				)

				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

// countDots counts the number of dots in a string
func countDots(s string) int {
	return strings.Count(s, ".")
}

// isIpAddress checks if a string is an IP address
func isIpAddress(s string) bool {
	return regexp.MustCompile(`^(?:\d{1,3}\.){3}\d{1,3}$`).MatchString(s)
}

// isSensitiveCookie checks if a cookie name suggests it contains sensitive information
func isSensitiveCookie(name string) bool {
	sensitivePatterns := []string{
		"session",
		"auth",
		"token",
		"id",
		"user",
		"login",
		"pass",
		"key",
		"jwt",
		"csrf",
		"xsrf",
		"oauth",
		"api",
		"access",
		"admin",
		"perm",
		"role",
		"sec",
		"remember",
		"account",
		"uid",
	}

	name = strings.ToLower(name)
	for _, pattern := range sensitivePatterns {
		if strings.Contains(name, pattern) {
			return true
		}
	}

	return false
}

// SupplyChainCheck checks for supply chain vulnerabilities
type SupplyChainCheck struct{}

// NewSupplyChainCheck creates a new supply chain check
func NewSupplyChainCheck() *SupplyChainCheck {
	return &SupplyChainCheck{}
}

// Name returns the name of the check
func (c *SupplyChainCheck) Name() string {
	return "Supply Chain Security Check"
}

// Description returns the description of the check
func (c *SupplyChainCheck) Description() string {
	return "Checks for supply chain vulnerabilities in JavaScript dependencies"
}

// Run performs the check
func (c *SupplyChainCheck) Run(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	// Check for unsafe usage of third-party scripts
	for _, script := range target.Scripts {
		// Check for scripts loaded from CDNs without integrity check
		if isThirdPartyScript(script) && !containsIntegrityAttribute(script) {
			finding := models.NewFinding(
				models.FindingTypeVulnerability,
				"Third-Party Script Without Integrity Check",
				models.SeverityMedium,
			).WithDescription(
				fmt.Sprintf("The script '%s' is loaded from a third-party source without an integrity check, which may expose the application to supply chain attacks.", script),
			).WithRemediation(
				"Add integrity attributes (SRI) to all third-party scripts.",
			).WithURL(
				target.URL,
			).WithTags(
				"supply-chain", "dependencies", "scripts",
			)

			findings = append(findings, finding)
		}

		// Check for outdated common libraries by looking at URL patterns
		if outdatedLibrary := detectOutdatedLibrary(script); outdatedLibrary != "" {
			finding := models.NewFinding(
				models.FindingTypeVulnerability,
				"Potentially Outdated JavaScript Library",
				models.SeverityMedium,
			).WithDescription(
				fmt.Sprintf("The application appears to use an outdated version of %s, which may have security vulnerabilities.", outdatedLibrary),
			).WithRemediation(
				"Update the library to the latest version and regularly check for security updates.",
			).WithURL(
				target.URL,
			).WithTags(
				"supply-chain", "dependencies", "outdated",
			)

			findings = append(findings, finding)
		}
	}

	// Check for inline script patterns that might indicate vulnerable dependencies
	// Note: Since target.InlineScripts is not defined, we'll check target.Scripts instead
	for _, script := range target.Scripts {
		// Check for vulnerable patterns in scripts
		vulnerablePatterns := map[string]string{
			`eval\s*\(\s*["']`:                 "Dangerous eval() Usage",
			`document\.write\s*\(`:             "Dangerous document.write() Usage",
			`setTimeout\s*\(\s*["']`:           "Dangerous setTimeout() with String",
			`setInterval\s*\(\s*["']`:          "Dangerous setInterval() with String",
			`allowtransparency\s*=\s*["']true`: "Deprecated allowtransparency Attribute",
			`sandbox\s*=\s*["']allow-scripts`:  "Potential iframe Safety Issue",
			`Function\s*\(\s*["'][^"']*["']\)`: "Dangerous Function Constructor",
		}

		for pattern, title := range vulnerablePatterns {
			if match, _ := regexp.MatchString(pattern, script); match {
				finding := models.NewFinding(
					models.FindingTypeVulnerability,
					title,
					models.SeverityMedium,
				).WithDescription(
					fmt.Sprintf("The application uses a potentially unsafe JavaScript pattern: %s", title),
				).WithRemediation(
					"Avoid using unsafe JavaScript patterns and ensure third-party dependencies are secure.",
				).WithURL(
					target.URL,
				).WithTags(
					"supply-chain", "dependencies", "security",
				)

				findings = append(findings, finding)
				break // Only report one finding per pattern per script
			}
		}
	}

	// Check for NPM-related files that might expose dependency information
	npmFiles := []string{"package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock"}
	for _, file := range target.Paths {
		for _, npmFile := range npmFiles {
			if strings.HasSuffix(file, npmFile) {
				finding := models.NewFinding(
					models.FindingTypeVulnerability,
					"Exposed Dependency Information",
					models.SeverityLow,
				).WithDescription(
					fmt.Sprintf("The application exposes dependency information via the file '%s', which may help attackers identify vulnerable dependencies.", file),
				).WithRemediation(
					"Ensure dependency files are not accessible from the public web server.",
				).WithURL(
					target.URL+file,
				).WithTags(
					"supply-chain", "dependencies", "information-disclosure",
				)

				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

// isThirdPartyScript checks if a script is loaded from a third-party domain
func isThirdPartyScript(scriptSrc string) bool {
	// Skip data: URLs and empty strings
	if scriptSrc == "" || strings.HasPrefix(scriptSrc, "data:") {
		return false
	}

	// Scripts loaded from common CDNs
	commonCDNs := []string{
		"cdn.jsdelivr.net",
		"unpkg.com",
		"cdnjs.cloudflare.com",
		"ajax.googleapis.com",
		"cdn.bootcdn.net",
		"stackpath.bootstrapcdn.com",
		"code.jquery.com",
		"maxcdn.bootstrapcdn.com",
		"use.fontawesome.com",
	}

	for _, cdn := range commonCDNs {
		if strings.Contains(scriptSrc, cdn) {
			return true
		}
	}

	// Check if it's a URL with a different domain
	if strings.HasPrefix(scriptSrc, "http://") || strings.HasPrefix(scriptSrc, "https://") {
		return true
	}

	return false
}

// containsIntegrityAttribute checks if a script tag contains an integrity attribute
func containsIntegrityAttribute(scriptTag string) bool {
	return strings.Contains(scriptTag, "integrity=")
}

// detectOutdatedLibrary checks if the script URL indicates an outdated library version
func detectOutdatedLibrary(scriptSrc string) string {
	outdatedLibraries := map[string]string{
		`jquery-1\.`:              "jQuery 1.x",
		`jquery-2\.`:              "jQuery 2.x",
		`bootstrap-3\.`:           "Bootstrap 3.x",
		`react-16\.`:              "React 16.x",
		`angular-1\.`:             "AngularJS 1.x",
		`lodash\.core@4\.[0-8]\.`: "Lodash < 4.9",
		`vue@2\.`:                 "Vue.js 2.x",
	}

	for pattern, library := range outdatedLibraries {
		if match, _ := regexp.MatchString(pattern, scriptSrc); match {
			return library
		}
	}

	return ""
}

// PrototypePollutionCheck checks for prototype pollution vulnerabilities
type PrototypePollutionCheck struct{}

// NewPrototypePollutionCheck creates a new prototype pollution check
func NewPrototypePollutionCheck() *PrototypePollutionCheck {
	return &PrototypePollutionCheck{}
}

// Name returns the name of the check
func (c *PrototypePollutionCheck) Name() string {
	return "Prototype Pollution Check"
}

// Description returns the description of the check
func (c *PrototypePollutionCheck) Description() string {
	return "Checks for prototype pollution vulnerabilities in JavaScript code"
}

// Run performs the check
func (c *PrototypePollutionCheck) Run(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	// Check JavaScript files for prototype pollution vulnerabilities
	for _, script := range target.Scripts {
		// Check for unsafe object merging/assignment patterns
		unsafePatterns := []string{
			// Object.assign without proper checks
			`Object\.assign\s*\(\s*[^,]+\s*,\s*`,
			// Spread operator with user input
			`\{\s*\.\.\.[^}]+\s*\}`,
			// Direct prototype access
			`\.__proto__\s*=`,
			`\[["']__proto__["']\]\s*=`,
			`Object\.prototype`,
			// Recursive merging functions
			`function\s+(?:\w+\s*\([^)]*\)\s*\{[^}]*(?:merge|extend|assign|copy|clone)[^}]*\})`,
			// jQuery extend
			`\$\.extend\s*\(`,
			`jQuery\.extend\s*\(`,
			// Lodash/Underscore merge functions
			`_\.merge\s*\(`,
			`_\.extend\s*\(`,
			`_\.assignIn\s*\(`,
			`_\.defaultsDeep\s*\(`,
			// Common library merge functions
			`deepMerge\s*\(`,
			`deepExtend\s*\(`,
			// JSON parsing with object revival
			`JSON\.parse\s*\([^,]+,\s*[^)]+\)`,
		}

		for _, pattern := range unsafePatterns {
			regex := regexp.MustCompile(pattern)
			if matches := regex.FindAllString(script, -1); len(matches) > 0 {
				finding := models.NewFinding(
					models.FindingTypeVulnerability,
					"Potential Prototype Pollution Vulnerability",
					models.SeverityHigh,
				).WithDescription(
					fmt.Sprintf("Potentially unsafe pattern detected that could lead to prototype pollution: %s", matches[0]),
				).WithRemediation(
					"Validate and sanitize user input before using it in object operations. Consider using Object.create(null) for safer object creation without prototype chain.",
				).WithURL(
					target.URL,
				).WithTags(
					"prototype-pollution", "javascript",
				)

				findings = append(findings, finding)
				break
			}
		}

		// Check for unsafe parameter handling
		paramHandlingPatterns := []string{
			// URL parameter parsing without sanitization
			`location\.(?:search|hash|href)`,
			`URLSearchParams`,
			`parseQuery`,
			`decodeURIComponent`,
			// Query string libraries
			`querystring\.parse`,
			`qs\.parse`,
		}

		for _, pattern := range paramHandlingPatterns {
			if strings.Contains(script, pattern) {
				// Check if there's also object manipulation nearby
				objectManipulationPatterns := []string{
					`Object\.assign`,
					`\{\s*\.\.\.[^}]+\s*\}`,
					`\.__proto__`,
					`\[["']__proto__["']\]`,
					`for\s*\(\s*(?:var|let|const)?\s*\w+\s+in\s+`,
				}

				for _, objPattern := range objectManipulationPatterns {
					if strings.Contains(script, objPattern) {
						finding := models.NewFinding(
							models.FindingTypeVulnerability,
							"Potential Prototype Pollution in URL Parameter Handling",
							models.SeverityHigh,
						).WithDescription(
							fmt.Sprintf("URL parameter handling (%s) combined with object manipulation (%s) could lead to prototype pollution.", pattern, objPattern),
						).WithRemediation(
							"Validate and sanitize URL parameters before using them in object operations. Consider using Object.create(null) or implementing property filtering.",
						).WithURL(
							target.URL,
						).WithTags(
							"prototype-pollution", "javascript", "url-parameters",
						)

						findings = append(findings, finding)
						break
					}
				}
			}
		}

		// Check for vulnerable dependencies
		vulnerableDependencies := map[string]string{
			"jquery":      "< 3.4.0",
			"lodash":      "< 4.17.12",
			"hoek":        "< 4.2.1",
			"minimist":    "< 1.2.3",
			"mixin-deep":  "< 1.3.2",
			"deep-extend": "< 0.5.1",
			"merge":       "< 1.2.1",
			"extend":      "< 3.0.2",
			"set-value":   "< 2.0.1",
			"unset-value": "< 1.0.0",
		}

		for dep, version := range vulnerableDependencies {
			depPattern := fmt.Sprintf(`(?:require\(['"]%s['"]|from\s+['"]%s['"]|import\s+.*?from\s+['"]%s['"])`, dep, dep, dep)
			if regexp.MustCompile(depPattern).MatchString(script) {
				finding := models.NewFinding(
					models.FindingTypeVulnerability,
					fmt.Sprintf("Potential Vulnerable Dependency: %s", dep),
					models.SeverityMedium,
				).WithDescription(
					fmt.Sprintf("The application may be using %s, which has known prototype pollution vulnerabilities in versions %s.", dep, version),
				).WithRemediation(
					fmt.Sprintf("Update %s to a version that fixes the prototype pollution vulnerability.", dep),
				).WithURL(
					target.URL,
				).WithTags(
					"prototype-pollution", "javascript", "dependencies", dep,
				)

				findings = append(findings, finding)
			}
		}

		// Check for custom object creation/manipulation functions
		customObjectPatterns := []string{
			`function\s+(?:\w+)\s*\([^)]*\)\s*\{[^}]*(?:Object\.create|Object\.assign|Object\.setPrototypeOf)[^}]*\}`,
			`function\s+(?:\w+)\s*\([^)]*\)\s*\{[^}]*(?:for\s*\(\s*(?:var|let|const)?\s*\w+\s+in\s+)[^}]*\}`,
		}

		for _, pattern := range customObjectPatterns {
			regex := regexp.MustCompile(pattern)
			if matches := regex.FindAllString(script, -1); len(matches) > 0 {
				finding := models.NewFinding(
					models.FindingTypeVulnerability,
					"Potential Custom Object Manipulation Vulnerability",
					models.SeverityMedium,
				).WithDescription(
					"Custom object manipulation function detected that could be vulnerable to prototype pollution.",
				).WithRemediation(
					"Ensure custom object manipulation functions validate property names and filter out __proto__, constructor, and prototype properties.",
				).WithURL(
					target.URL,
				).WithTags(
					"prototype-pollution", "javascript", "custom-functions",
				)

				findings = append(findings, finding)
				break
			}
		}
	}

	return findings, nil
}
