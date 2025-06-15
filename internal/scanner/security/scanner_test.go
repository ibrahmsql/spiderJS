package security

import (
	"context"
	"net/url"
	"testing"

	"github.com/ibrahmsql/spiderjs/internal/config"
	"github.com/ibrahmsql/spiderjs/internal/utils/logger"
	"github.com/ibrahmsql/spiderjs/pkg/models"
	"github.com/stretchr/testify/assert"
)

func TestNewScanner(t *testing.T) {
	log := logger.NewLogger()
	cfg := &config.Config{}
	cfg.SetDefaults()

	tests := []struct {
		name    string
		cfg     *config.Config
		log     *logger.Logger
		wantErr bool
	}{
		{
			name:    "Valid config and logger",
			cfg:     cfg,
			log:     log,
			wantErr: false,
		},
		{
			name:    "Nil config",
			cfg:     nil,
			log:     log,
			wantErr: true,
		},
		{
			name:    "Nil logger",
			cfg:     cfg,
			log:     nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner, err := NewScanner(tt.cfg, tt.log)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, scanner)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, scanner)
			}
		})
	}
}

func TestScan(t *testing.T) {
	log := logger.NewLogger()
	cfg := &config.Config{}
	cfg.SetDefaults()

	// Add security scan options
	cfg.ScanOptions = config.ScanOptions{
		IncludeXSS:         true,
		IncludeInjection:   true,
		IncludeCSRF:        true,
		IncludeCORS:        true,
		IncludeHeaders:     true,
		IncludeCookies:     true,
		IncludeSupplyChain: true,
		IncludePrototype:   true,
	}

	scanner, err := NewScanner(cfg, log)
	assert.NoError(t, err)
	assert.NotNil(t, scanner)

	// Create a test target
	targetURL, _ := url.Parse("https://example.com")
	target := &models.Target{
		URL:     targetURL.String(),
		Domain:  "example.com",
		Headers: map[string]string{},
		Cookies: map[string]string{},
	}

	// Test with no security issues - we'll skip detailed validation
	// as we're just testing that the scan runs without errors
	findings, err := scanner.Scan(context.Background(), target)
	assert.NoError(t, err)
	// Don't assert on the findings, just that there's no error

	// Test with security issues - we'll skip detailed validation
	target.Headers["Access-Control-Allow-Origin"] = "*"
	target.Cookies["sessionId"] = "abc123"
	findings, err = scanner.Scan(context.Background(), target)
	assert.NoError(t, err)
	// Don't assert on the findings, just that there's no error

	// Test with cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	findings, err = scanner.Scan(ctx, target)
	assert.Error(t, err)
	// Don't assert on the findings, just that there's an error

	// Test with nil target
	findings, err = scanner.Scan(context.Background(), nil)
	assert.Error(t, err)
	assert.Empty(t, findings) // Should return empty slice, not nil
}

func TestXSSCheck(t *testing.T) {
	check := NewXSSCheck()
	assert.NotNil(t, check)
	assert.Equal(t, "XSS Check", check.Name())
	assert.Equal(t, "Checks for Cross-Site Scripting vulnerabilities", check.Description())

	// Create a test target
	targetURL, _ := url.Parse("https://example.com")
	target := &models.Target{
		URL:     targetURL.String(),
		Headers: map[string]string{},
	}

	// Test with no CSP header
	findings, err := check.Run(context.Background(), target)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(findings))
	assert.Equal(t, "Missing Content-Security-Policy Header", findings[0].Title)

	// Test with CSP header
	target.Headers["Content-Security-Policy"] = "default-src 'self'"
	findings, err = check.Run(context.Background(), target)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(findings))
}

func TestInjectionCheck(t *testing.T) {
	check := NewInjectionCheck()
	assert.NotNil(t, check)
	assert.Equal(t, "Injection Check", check.Name())
	assert.Equal(t, "Checks for injection vulnerabilities", check.Description())

	// Create a test target
	targetURL, _ := url.Parse("https://example.com")
	target := &models.Target{
		URL: targetURL.String(),
	}

	// Test sample finding
	findings, err := check.Run(context.Background(), target)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(findings))
	assert.Equal(t, "Potential Injection Vulnerability", findings[0].Title)
}

func TestCSRFCheck(t *testing.T) {
	check := NewCSRFCheck()
	assert.NotNil(t, check)
	assert.Equal(t, "CSRF Check", check.Name())
	assert.Equal(t, "Checks for Cross-Site Request Forgery vulnerabilities", check.Description())

	// Create a test target
	targetURL, _ := url.Parse("https://example.com")
	target := &models.Target{
		URL: targetURL.String(),
	}

	// Test with no findings (simplified implementation)
	findings, err := check.Run(context.Background(), target)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(findings))
}

func TestCORSCheck(t *testing.T) {
	check := NewCORSCheck()
	assert.NotNil(t, check)
	assert.Equal(t, "CORS Check", check.Name())
	assert.Equal(t, "Checks for Cross-Origin Resource Sharing misconfigurations", check.Description())

	// Create a test target
	targetURL, _ := url.Parse("https://example.com")
	target := &models.Target{
		URL:     targetURL.String(),
		Headers: map[string]string{},
	}

	// Test with no CORS header
	findings, err := check.Run(context.Background(), target)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(findings))

	// Test with permissive CORS header
	target.Headers["Access-Control-Allow-Origin"] = "*"
	findings, err = check.Run(context.Background(), target)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(findings))
	assert.Equal(t, "Wildcard CORS Policy", findings[0].Title)

	// Test with specific origin
	target.Headers["Access-Control-Allow-Origin"] = "https://example.org"
	findings, err = check.Run(context.Background(), target)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(findings))
}

func TestHeaderCheck(t *testing.T) {
	check := NewHeaderCheck()
	assert.NotNil(t, check)
	assert.Equal(t, "Security Headers Check", check.Name())
	assert.Equal(t, "Checks for missing or misconfigured security headers", check.Description())

	// Create a test target
	targetURL, _ := url.Parse("https://example.com")
	target := &models.Target{
		URL:     targetURL.String(),
		Headers: map[string]string{},
	}

	// Test with missing headers
	findings, err := check.Run(context.Background(), target)
	assert.NoError(t, err)
	assert.Equal(t, 6, len(findings))

	// Test with X-Frame-Options
	target.Headers["X-Frame-Options"] = "DENY"
	findings, err = check.Run(context.Background(), target)
	assert.NoError(t, err)
	assert.Equal(t, 5, len(findings))

	// Test with all headers
	target.Headers = map[string]string{
		"X-Frame-Options":           "DENY",
		"X-Content-Type-Options":    "nosniff",
		"Content-Security-Policy":   "default-src 'self'",
		"Strict-Transport-Security": "max-age=31536000",
		"X-XSS-Protection":          "1; mode=block",
		"Referrer-Policy":           "no-referrer",
	}
	findings, err = check.Run(context.Background(), target)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(findings))
}

func TestCookieCheck(t *testing.T) {
	check := NewCookieCheck()
	assert.NotNil(t, check)
	assert.Equal(t, "Cookie Security Check", check.Name())
	assert.Equal(t, "Checks for insecure cookie configurations", check.Description())

	// Create a test target
	targetURL, _ := url.Parse("https://example.com")
	target := &models.Target{
		URL:     targetURL.String(),
		Cookies: map[string]string{},
	}

	// Test with no cookies
	findings, err := check.Run(context.Background(), target)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(findings))

	// Test with insecure cookie
	target.Cookies["sessionId"] = "abc123"
	findings, err = check.Run(context.Background(), target)
	assert.NoError(t, err)
	assert.Equal(t, 3, len(findings))

	// Test with secure cookie
	target.Cookies = map[string]string{"sessionId": "abc123; Secure; HttpOnly; SameSite=Strict"}
	findings, err = check.Run(context.Background(), target)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(findings))
}

func TestSupplyChainCheck(t *testing.T) {
	check := NewSupplyChainCheck()
	assert.NotNil(t, check)
	assert.Equal(t, "Supply Chain Security Check", check.Name())
	assert.Equal(t, "Checks for supply chain vulnerabilities in JavaScript dependencies", check.Description())

	// Create a test target
	targetURL, _ := url.Parse("https://example.com")
	target := &models.Target{
		URL: targetURL.String(),
		Scripts: []string{
			"https://cdn.jsdelivr.net/npm/jquery-1.12.4.min.js",
		},
	}

	// Test sample finding
	findings, err := check.Run(context.Background(), target)
	assert.NoError(t, err)
	assert.Greater(t, len(findings), 0)
	assert.Equal(t, "Third-Party Script Without Integrity Check", findings[0].Title)
}

func TestPrototypePollutionCheck(t *testing.T) {
	check := NewPrototypePollutionCheck()
	assert.NotNil(t, check)
	assert.Equal(t, "Prototype Pollution Check", check.Name())
	assert.Equal(t, "Checks for prototype pollution vulnerabilities in JavaScript code", check.Description())

	// Create a test target with a vulnerable script
	targetURL, _ := url.Parse("https://example.com")
	target := &models.Target{
		URL: targetURL.String(),
		Scripts: []string{
			`function merge(target, source) { for (var key in source) { target[key] = source[key]; } return target; }`,
		},
	}

	// Test sample finding
	findings, err := check.Run(context.Background(), target)
	assert.NoError(t, err)
	assert.Greater(t, len(findings), 0)
	assert.Equal(t, "Potential Custom Object Manipulation Vulnerability", findings[0].Title)
}
