package analyzer

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/ibrahmsql/spiderjs/internal/analyzer/bundle"
	"github.com/ibrahmsql/spiderjs/internal/config"
	"github.com/ibrahmsql/spiderjs/internal/scanner/security"
	"github.com/ibrahmsql/spiderjs/internal/utils/logger"
	"github.com/ibrahmsql/spiderjs/pkg/models"
)

// Analyzer defines the interface for JavaScript analysis
type Analyzer interface {
	// Analyze analyzes a target and returns the analysis result
	Analyze(ctx context.Context, target *models.Target) (*models.AnalysisResult, error)
}

// Analyzer is responsible for analyzing JavaScript code
type AnalyzerImpl struct {
	config *config.Config
	log    *logger.Logger
	bundle *bundle.Analyzer
}

// NewAnalyzer creates a new analyzer
func NewAnalyzer(ctx context.Context, cfg *config.Config, log *logger.Logger) (*AnalyzerImpl, error) {
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

	// Create bundle analyzer
	bundleAnalyzer, err := bundle.NewAnalyzer(log)
	if err != nil {
		return nil, fmt.Errorf("failed to create bundle analyzer: %w", err)
	}

	return &AnalyzerImpl{
		config: cfg,
		log:    log,
		bundle: bundleAnalyzer,
	}, nil
}

// Analyze analyzes a JavaScript target
func (a *AnalyzerImpl) Analyze(ctx context.Context, target *models.Target) (*models.AnalysisResult, error) {
	// Context timeout check
	if ctx.Err() != nil {
		return nil, fmt.Errorf("context cancelled: %w", ctx.Err())
	}

	// Input validation
	if target == nil {
		return nil, errors.New("target cannot be nil")
	}

	// Start analysis
	a.log.Info("Starting analysis", "target", target.URL)
	startTime := time.Now()

	// Create result
	result := models.NewAnalysisResult(target)

	// Extract actual file path for local files
	filePath := target.URL
	if strings.HasPrefix(filePath, "http://") || strings.HasPrefix(filePath, "https://") {
		// This is a URL, but it might be a local file path that was converted to URL
		// Try to convert back to a local path by stripping the scheme
		if strings.HasPrefix(filePath, "https://") && !strings.Contains(filePath, "://www.") {
			filePath = strings.TrimPrefix(filePath, "https://")
		} else if strings.HasPrefix(filePath, "http://") && !strings.Contains(filePath, "://www.") {
			filePath = strings.TrimPrefix(filePath, "http://")
		}
	}

	// Check if target is a file
	fileInfo, err := os.Stat(filePath)
	if err == nil && !fileInfo.IsDir() {
		// Load file content
		content, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read file: %w", err)
		}

		// Set file size
		result.SetFileSize(fileInfo.Size())

		// Add script to target
		target.Scripts = []string{string(content)}

		// Debug logging
		a.log.Info("File content loaded",
			"size", len(content),
			"script_count", len(target.Scripts),
			"first_chars", string(content[:min(100, len(content))]),
		)
	} else {
		a.log.Warn("Target is not a file or file not found",
			"url", target.URL,
			"filePath", filePath,
			"error", err,
		)
	}

	// Analyze bundle if scripts are available
	if len(target.Scripts) > 0 {
		bundleInfos, err := a.bundle.Analyze(ctx, target)
		if err != nil {
			a.log.Warn("Bundle analysis failed", "error", err)
		} else {
			// Process bundle information
			for _, info := range bundleInfos {
				// Set bundle type if found
				if info.Type != bundle.Unknown && result.BundleType == "" {
					result.SetBundleType(string(info.Type))
				}

				// Set minified flag if detected
				if info.IsMinified {
					result.SetIsMinified(true)
				}

				// Add dependencies
				for _, dep := range info.Dependencies {
					// Extract name and version (if available)
					parts := splitDependency(dep)
					if len(parts) > 1 {
						result.AddDependency(parts[0], parts[1])
					} else {
						result.AddDependency(parts[0], "")
					}
				}
			}
		}
	}

	// Detect frameworks
	a.detectFrameworks(result)

	// Check for vulnerabilities
	a.scanVulnerabilities(result)

	// Scan for framework-specific vulnerabilities if frameworks were detected
	if len(result.Frameworks) > 0 {
		// Import scanner package
		secScanner, err := security.NewScanner(a.config, a.log)
		if err != nil {
			a.log.Warn("Failed to initialize security scanner for framework vulnerability check", "error", err)
		} else {
			if err := secScanner.ScanFrameworkVulnerabilities(ctx, result); err != nil {
				a.log.Warn("Framework vulnerability scan failed", "error", err)
			}
		}
	}

	// Set duration
	duration := time.Since(startTime)
	result.SetDuration(duration.String())
	result.SetScriptCount(len(target.Scripts))

	// Log analysis completion
	a.log.Success("Analysis completed", "duration", duration.String())
	return result, nil
}

// detectFrameworks detects JavaScript frameworks in the analysis result
func (a *AnalyzerImpl) detectFrameworks(result *models.AnalysisResult) {
	// Simple framework detection based on dependencies
	frameworkPatterns := map[string]string{
		"react":             "React",
		"angular":           "Angular",
		"vue":               "Vue.js",
		"ember":             "Ember.js",
		"backbone":          "Backbone.js",
		"jquery":            "jQuery",
		"lodash":            "Lodash",
		"underscore":        "Underscore.js",
		"moment":            "Moment.js",
		"axios":             "Axios",
		"express":           "Express.js",
		"koa":               "Koa",
		"nextjs":            "Next.js",
		"next":              "Next.js",
		"gatsby":            "Gatsby",
		"nuxt":              "Nuxt.js",
		"svelte":            "Svelte",
		"preact":            "Preact",
		"redux":             "Redux",
		"mobx":              "MobX",
		"styled-components": "Styled Components",
		"tailwindcss":       "Tailwind CSS",
		"bootstrap":         "Bootstrap",
		"material-ui":       "Material-UI",
		"ant-design":        "Ant Design",
		"chakra-ui":         "Chakra UI",
		"graphql":           "GraphQL",
		"apollo":            "Apollo",
		"typescript":        "TypeScript",
		"webpack":           "Webpack",
		"rollup":            "Rollup",
		"vite":              "Vite",
		"parcel":            "Parcel",
		"babel":             "Babel",
		"eslint":            "ESLint",
		"jest":              "Jest",
		"mocha":             "Mocha",
		"chai":              "Chai",
		"cypress":           "Cypress",
	}

	// Check dependencies for known frameworks
	for _, dep := range result.Dependencies {
		for pattern, framework := range frameworkPatterns {
			if contains(dep.Name, pattern) {
				// Check if framework is already added
				alreadyAdded := false
				for _, fw := range result.Frameworks {
					if fw.Name == framework {
						alreadyAdded = true
						break
					}
				}

				if !alreadyAdded {
					result.AddFramework(framework, dep.Version)
				}
			}
		}
	}

	// Also check scripts for import statements and framework signatures
	for _, script := range result.Target.Scripts {
		// Check for import statements (ES modules)
		importRegex := regexp.MustCompile(`import\s+(?:{[^}]*}|[^{}\n;]+)\s+from\s+['"]([@\w\-/.]+)['"]`)
		matches := importRegex.FindAllStringSubmatch(script, -1)

		for _, match := range matches {
			if len(match) >= 2 {
				importName := match[1]

				// Extract package name (handle scoped packages like @angular/core)
				packageName := importName
				if strings.Contains(packageName, "/") {
					parts := strings.Split(packageName, "/")
					if strings.HasPrefix(parts[0], "@") && len(parts) > 1 {
						packageName = parts[0] + "/" + parts[1] // Keep the scope
					} else {
						packageName = parts[0]
					}
				}

				// Detect framework from package name
				for pattern, framework := range frameworkPatterns {
					if contains(packageName, pattern) {
						// Check if framework is already added
						alreadyAdded := false
						for _, fw := range result.Frameworks {
							if fw.Name == framework {
								alreadyAdded = true
								break
							}
						}

						if !alreadyAdded {
							// Try to extract version
							versionRegex := regexp.MustCompile(`(const|let|var)\s+\w*VERSION\w*\s*=\s*['"]([0-9.]+)['"]`)
							versionMatches := versionRegex.FindAllStringSubmatch(script, -1)
							version := ""

							if len(versionMatches) > 0 && len(versionMatches[0]) >= 3 {
								version = versionMatches[0][2]
							}

							// Try specific framework version patterns if no version found
							if version == "" && framework == "Vue.js" {
								vueVersionRegex := regexp.MustCompile(`(const|let|var)\s+VUE_VERSION\s*=\s*['"]([0-9.]+)['"]`)
								vueVersionMatches := vueVersionRegex.FindAllStringSubmatch(script, -1)
								if len(vueVersionMatches) > 0 && len(vueVersionMatches[0]) >= 3 {
									version = vueVersionMatches[0][2]
								}
							}

							result.AddFramework(framework, version)
							a.log.Info("Framework detected from imports", "framework", framework, "package", packageName)
						}
					}
				}
			}
		}

		// Check for require statements (CommonJS)
		requireRegex := regexp.MustCompile(`require\s*\(\s*['"]([^'"]+)['"]\s*\)`)
		requireMatches := requireRegex.FindAllStringSubmatch(script, -1)

		for _, match := range requireMatches {
			if len(match) >= 2 {
				requireName := match[1]

				// Extract package name
				packageName := requireName
				if strings.Contains(packageName, "/") {
					parts := strings.Split(packageName, "/")
					if strings.HasPrefix(parts[0], "@") && len(parts) > 1 {
						packageName = parts[0] + "/" + parts[1] // Keep the scope
					} else {
						packageName = parts[0]
					}
				}

				// Detect framework from package name
				for pattern, framework := range frameworkPatterns {
					if contains(packageName, pattern) {
						// Check if framework is already added
						alreadyAdded := false
						for _, fw := range result.Frameworks {
							if fw.Name == framework {
								alreadyAdded = true
								break
							}
						}

						if !alreadyAdded {
							result.AddFramework(framework, "")
							a.log.Info("Framework detected from requires", "framework", framework, "package", packageName)
						}
					}
				}
			}
		}

		// Check for jQuery specific patterns
		jqueryPatterns := []string{
			`\$\s*\(`,         // $(
			`jQuery\s*\(`,     // jQuery(
			`\$\.ajax`,        // $.ajax
			`jQuery\.ajax`,    // jQuery.ajax
			`\$\.[a-zA-Z]+\(`, // $.methodName(
		}

		for _, pattern := range jqueryPatterns {
			regex := regexp.MustCompile(pattern)
			if regex.MatchString(script) {
				// Check if jQuery is already added
				alreadyAdded := false
				for _, fw := range result.Frameworks {
					if fw.Name == "jQuery" {
						alreadyAdded = true
						break
					}
				}

				if !alreadyAdded {
					// Try to extract version
					versionRegex := regexp.MustCompile(`(const|let|var)\s+\w*JQUERY_VERSION\w*\s*=\s*['"]([0-9.]+)['"]`)
					versionMatches := versionRegex.FindAllStringSubmatch(script, -1)
					version := ""

					if len(versionMatches) > 0 && len(versionMatches[0]) >= 3 {
						version = versionMatches[0][2]
					}

					result.AddFramework("jQuery", version)
					a.log.Info("Framework detected from patterns", "framework", "jQuery")
				}

				break
			}
		}

		// Check for Express.js specific patterns
		expressPatterns := []string{
			`app\s*=\s*express\(\)`, // app = express()
			`app\.use\(`,            // app.use(
			`app\.get\(`,            // app.get(
			`app\.post\(`,           // app.post(
			`app\.listen\(`,         // app.listen(
		}

		for _, pattern := range expressPatterns {
			regex := regexp.MustCompile(pattern)
			if regex.MatchString(script) {
				// Check if Express.js is already added
				alreadyAdded := false
				for _, fw := range result.Frameworks {
					if fw.Name == "Express.js" {
						alreadyAdded = true
						break
					}
				}

				if !alreadyAdded {
					// Try to extract version
					versionRegex := regexp.MustCompile(`(const|let|var)\s+\w*EXPRESS_VERSION\w*\s*=\s*['"]([0-9.]+)['"]`)
					versionMatches := versionRegex.FindAllStringSubmatch(script, -1)
					version := ""

					if len(versionMatches) > 0 && len(versionMatches[0]) >= 3 {
						version = versionMatches[0][2]
					}

					result.AddFramework("Express.js", version)
					a.log.Info("Framework detected from patterns", "framework", "Express.js")
				}

				break
			}
		}
	}
}

// scanVulnerabilities scans for vulnerabilities in the JavaScript code
func (a *AnalyzerImpl) scanVulnerabilities(result *models.AnalysisResult) {
	// Check for common JavaScript vulnerabilities in the scripts
	vulnerabilityPatterns := map[string]struct {
		pattern  string
		severity string
		desc     string
	}{
		"eval": {
			pattern:  "eval\\(",
			severity: "High",
			desc:     "Use of eval() can lead to code injection vulnerabilities",
		},
		"document.write": {
			pattern:  "document\\.write\\(",
			severity: "Medium",
			desc:     "Use of document.write() can lead to XSS vulnerabilities",
		},
		"innerHTML": {
			pattern:  "\\.innerHTML\\s*=",
			severity: "Medium",
			desc:     "Assignment to innerHTML can lead to XSS vulnerabilities",
		},
		"Function constructor": {
			pattern:  "new\\s+Function\\(",
			severity: "High",
			desc:     "Use of Function constructor can lead to code injection vulnerabilities",
		},
		"setTimeout string": {
			pattern:  "setTimeout\\(\\s*['\"]",
			severity: "Medium",
			desc:     "Using strings with setTimeout() can lead to code injection",
		},
		"setInterval string": {
			pattern:  "setInterval\\(\\s*['\"]",
			severity: "Medium",
			desc:     "Using strings with setInterval() can lead to code injection",
		},
		"Insecure postMessage": {
			pattern:  "postMessage\\([^,]+,\\s*['\"]\\*['\"]\\)",
			severity: "Medium",
			desc:     "Insecure use of postMessage with wildcard origin",
		},
		"localStorage clear": {
			pattern:  "localStorage\\.clear\\(\\)",
			severity: "Low",
			desc:     "Clearing localStorage can lead to data loss",
		},
		"Hardcoded credentials": {
			pattern:  "(password|token|key|secret|credential)\\s*=\\s*['\"][^'\"]+['\"]",
			severity: "High",
			desc:     "Hardcoded credentials detected",
		},
		"Console logging": {
			pattern:  "console\\.(log|warn|error)\\(",
			severity: "Low",
			desc:     "Console logging found in production code",
		},
	}

	// Scan scripts for vulnerability patterns
	for _, script := range result.Target.Scripts {
		// Skip empty scripts
		if len(script) == 0 {
			continue
		}

		// Check for vulnerabilities
		for vulnType, vulnInfo := range vulnerabilityPatterns {
			locations := findPattern(script, vulnInfo.pattern)
			for _, loc := range locations {
				result.AddVulnerability(vulnType, vulnInfo.severity, vulnInfo.desc, loc)
			}
		}
	}
}

// Helper functions

// splitDependency splits a dependency string into name and version
func splitDependency(dep string) []string {
	// Common patterns: name@version, name:version, name version
	for _, sep := range []string{"@", ":", " "} {
		parts := split(dep, sep)
		if len(parts) > 1 {
			return parts
		}
	}
	return []string{dep}
}

// split splits a string by a separator and returns a slice of the parts
func split(s, sep string) []string {
	return strings.Split(s, sep)
}

// contains checks if a string contains a substring
func contains(s, substr string) bool {
	return s == substr || len(s) >= len(substr) && s[:len(substr)] == substr || len(s) >= len(substr) && s[len(s)-len(substr):] == substr || len(s) >= len(substr) && contains(s[1:], substr)
}

// findPattern finds a pattern in a string and returns the locations
func findPattern(s, pattern string) []string {
	// Use regex to find all matches
	re, err := regexp.Compile(pattern)
	if err != nil {
		// If pattern is invalid, fall back to simple contains check
		if strings.Contains(s, pattern) {
			return []string{"found"}
		}
		return []string{"unknown"}
	}

	// Find all matches
	matches := re.FindAllStringIndex(s, -1)
	if len(matches) == 0 {
		return []string{"unknown"}
	}

	// Convert matches to location strings
	locations := make([]string, len(matches))
	for i, match := range matches {
		locations[i] = fmt.Sprintf("pos %d-%d", match[0], match[1])
	}
	return locations
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
