package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/ibrahmsql/spiderjs/internal/utils/logger"
	"github.com/ibrahmsql/spiderjs/pkg/models"
)

// EndpointType represents the type of API endpoint
type EndpointType string

const (
	// EndpointTypeREST represents a REST API endpoint
	EndpointTypeREST EndpointType = "rest"
	// EndpointTypeGraphQL represents a GraphQL API endpoint
	EndpointTypeGraphQL EndpointType = "graphql"
	// EndpointTypeWebSocket represents a WebSocket API endpoint
	EndpointTypeWebSocket EndpointType = "websocket"
	// EndpointTypeSSE represents a Server-Sent Events API endpoint
	EndpointTypeSSE EndpointType = "sse"
)

// Endpoint represents an API endpoint
type Endpoint struct {
	URL         string       `json:"url"`
	Type        EndpointType `json:"type"`
	Method      string       `json:"method,omitempty"`
	Description string       `json:"description,omitempty"`
	Parameters  []string     `json:"parameters,omitempty"`
	Headers     []string     `json:"headers,omitempty"`
	Score       int          `json:"score"`
}

// Discoverer discovers API endpoints in web applications
type Discoverer struct {
	log *logger.Logger
}

// NewDiscoverer creates a new API discoverer
func NewDiscoverer(log *logger.Logger) (*Discoverer, error) {
	if log == nil {
		return nil, errors.New("logger cannot be nil")
	}

	return &Discoverer{
		log: log,
	}, nil
}

// Discover discovers API endpoints from an HTTP response
func (d *Discoverer) Discover(ctx context.Context, resp *http.Response, baseURL string) ([]*Endpoint, error) {
	if ctx.Err() != nil {
		return nil, fmt.Errorf("context cancelled: %w", ctx.Err())
	}

	if resp == nil {
		return nil, errors.New("response cannot be nil")
	}

	if baseURL == "" {
		return nil, errors.New("base URL cannot be empty")
	}

	var endpoints []*Endpoint

	// Parse the base URL
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse base URL: %w", err)
	}

	// Check for GraphQL endpoints
	graphQLEndpoints, err := d.discoverGraphQL(resp, base)
	if err != nil {
		return nil, fmt.Errorf("failed to discover GraphQL endpoints: %w", err)
	}
	endpoints = append(endpoints, graphQLEndpoints...)

	// Parse HTML
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTML: %w", err)
	}

	// Discover REST endpoints from script tags
	restEndpoints, err := d.discoverRESTFromScripts(doc, base)
	if err != nil {
		return nil, fmt.Errorf("failed to discover REST endpoints from scripts: %w", err)
	}
	endpoints = append(endpoints, restEndpoints...)

	// Discover WebSocket endpoints
	wsEndpoints, err := d.discoverWebSockets(doc, base)
	if err != nil {
		return nil, fmt.Errorf("failed to discover WebSocket endpoints: %w", err)
	}
	endpoints = append(endpoints, wsEndpoints...)

	// Discover Server-Sent Events endpoints
	sseEndpoints, err := d.discoverSSE(doc, base)
	if err != nil {
		return nil, fmt.Errorf("failed to discover SSE endpoints: %w", err)
	}
	endpoints = append(endpoints, sseEndpoints...)

	// Deduplicate endpoints
	endpoints = d.deduplicateEndpoints(endpoints)

	return endpoints, nil
}

// DiscoverFromTarget discovers API endpoints from a target
func (d *Discoverer) DiscoverFromTarget(ctx context.Context, target *models.Target) ([]*Endpoint, error) {
	if ctx.Err() != nil {
		return nil, fmt.Errorf("context cancelled: %w", ctx.Err())
	}

	if target == nil {
		return nil, errors.New("target cannot be nil")
	}

	var endpoints []*Endpoint

	// Parse the base URL for resolving relative URLs
	baseURL, err := url.Parse(target.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse base URL: %w", err)
	}

	// Check for API paths
	for _, path := range target.Paths {
		pathURL := d.resolveURL(baseURL, path)

		// Check for REST API patterns
		if d.isRESTPath(path) {
			// Try to determine the appropriate HTTP method based on the path
			method := "GET" // Default method

			pathLower := strings.ToLower(path)
			if strings.Contains(pathLower, "/post") || strings.Contains(pathLower, "/create") || strings.Contains(pathLower, "/add") {
				method = "POST"
			} else if strings.Contains(pathLower, "/put") || strings.Contains(pathLower, "/update") || strings.Contains(pathLower, "/modify") {
				method = "PUT"
			} else if strings.Contains(pathLower, "/delete") || strings.Contains(pathLower, "/remove") {
				method = "DELETE"
			} else if strings.Contains(pathLower, "/patch") {
				method = "PATCH"
			}

			endpoint := &Endpoint{
				URL:    pathURL,
				Type:   EndpointTypeREST,
				Method: method,
				Score:  70,
			}
			endpoints = append(endpoints, endpoint)
		}

		// Check for GraphQL endpoints
		if d.isGraphQLPath(path) {
			endpoint := &Endpoint{
				URL:    pathURL,
				Type:   EndpointTypeGraphQL,
				Method: "POST",
				Score:  90,
			}
			endpoints = append(endpoints, endpoint)
		}

		// Check for WebSocket endpoints
		if strings.Contains(path, "/ws") || strings.Contains(path, "/websocket") ||
			strings.Contains(path, "/socket") || strings.Contains(path, "/socketio") ||
			strings.Contains(path, "/sock") {
			// Convert http/https scheme to ws/wss if needed
			wsURL := pathURL
			if strings.HasPrefix(wsURL, "http:") {
				wsURL = "ws:" + pathURL[5:]
			} else if strings.HasPrefix(wsURL, "https:") {
				wsURL = "wss:" + pathURL[6:]
			}

			endpoint := &Endpoint{
				URL:   wsURL,
				Type:  EndpointTypeWebSocket,
				Score: 80,
			}
			endpoints = append(endpoints, endpoint)
		}

		// Check for SSE endpoints
		if strings.Contains(path, "/events") || strings.Contains(path, "/stream") ||
			strings.Contains(path, "/sse") || strings.Contains(path, "/push") {
			endpoint := &Endpoint{
				URL:   pathURL,
				Type:  EndpointTypeSSE,
				Score: 80,
			}
			endpoints = append(endpoints, endpoint)
		}
	}

	// Deduplicate endpoints
	endpoints = d.deduplicateEndpoints(endpoints)

	return endpoints, nil
}

// discoverGraphQL discovers GraphQL endpoints
func (d *Discoverer) discoverGraphQL(resp *http.Response, baseURL *url.URL) ([]*Endpoint, error) {
	var endpoints []*Endpoint

	// Check for GraphQL in response headers
	if strings.Contains(resp.Header.Get("Content-Type"), "application/graphql") {
		endpoint := &Endpoint{
			URL:    resp.Request.URL.String(),
			Type:   EndpointTypeGraphQL,
			Method: "POST",
			Score:  100,
		}
		endpoints = append(endpoints, endpoint)
	}

	// Look for GraphQL schema introspection response
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") {
		// We would parse the body here to check for GraphQL schema,
		// but this would require keeping the body in memory and affecting other readers
		// So we'll just rely on other detection methods
	}

	// Check common header patterns that might indicate GraphQL
	for key, values := range resp.Header {
		for _, value := range values {
			if strings.Contains(strings.ToLower(key), "graphql") ||
				strings.Contains(strings.ToLower(value), "graphql") {
				endpoint := &Endpoint{
					URL:    resp.Request.URL.String(),
					Type:   EndpointTypeGraphQL,
					Method: "POST",
					Score:  90,
				}
				endpoints = append(endpoints, endpoint)
				break
			}
		}
	}

	return endpoints, nil
}

// discoverRESTFromScripts discovers REST API endpoints from script tags
func (d *Discoverer) discoverRESTFromScripts(doc *goquery.Document, baseURL *url.URL) ([]*Endpoint, error) {
	var endpoints []*Endpoint

	// Process all script tags
	doc.Find("script").Each(func(i int, s *goquery.Selection) {
		scriptContent, _ := s.Html()

		// Extract potential API URLs from fetch calls
		fetchRegexPatterns := []string{
			`fetch\(['"]([^'"]+)['"]\)`,
			`fetch\(['"]([^'"]+)['"],\s*\{[^}]*\}\)`,
			`fetch\(([^)]+),\s*\{[^}]*method:\s*['"]([A-Z]+)['"]\s*[^}]*\}\)`,
			`axios\.([a-z]+)\(['"]([^'"]+)['"]\)`,
			`axios\(['"]([^'"]+)['"](?:,\s*\{[^}]*\})?\)`,
			`\$\.ajax\(\{[^}]*url:\s*['"]([^'"]+)['"]`,
			`\$\.([a-z]+)\(['"]([^'"]+)['"]`,
			`http\.([a-z]+)\(['"]([^'"]+)['"]`,
			`\.([a-z]+)\(['"]([^'"]+)['"](?:,\s*\{[^}]*\})?\)\.then\(`,
		}

		for _, pattern := range fetchRegexPatterns {
			regex := regexp.MustCompile(pattern)
			matches := regex.FindAllStringSubmatch(scriptContent, -1)

			for _, match := range matches {
				var url, method string

				// Handle different regex patterns
				if len(match) == 2 {
					// Simple fetch/axios call with just URL
					url = match[1]
					method = "GET" // Default method
				} else if len(match) == 3 {
					// Method + URL pattern (like axios.get(url) or $.ajax)
					if match[1] == "ajax" {
						url = match[2]
						method = "GET" // Default for ajax
					} else {
						method = strings.ToUpper(match[1])
						url = match[2]
					}
				}

				// Clean up URL - remove template literals and variables
				url = d.cleanupURL(url)

				// Skip if URL is empty or not valid after cleanup
				if url == "" || !d.isValidAPIURL(url) {
					continue
				}

				// Resolve relative URLs
				resolvedURL := d.resolveURL(baseURL, url)

				// Skip if not a REST-like URL
				if !d.isRESTPath(resolvedURL) {
					continue
				}

				// Create endpoint
				endpoint := &Endpoint{
					URL:    resolvedURL,
					Type:   EndpointTypeREST,
					Method: method,
					Score:  80,
				}

				// Try to extract parameters from URL
				params := d.extractURLParameters(url)
				if len(params) > 0 {
					endpoint.Parameters = params
				}

				endpoints = append(endpoints, endpoint)
			}
		}

		// Extract API endpoints from route definitions
		routePatterns := []string{
			`\.route\(['"]([^'"]+)['"],\s*([^)]+)\)`,
			`\.([a-z]+)\(['"]([^'"]+)['"]`,
			`app\.([a-z]+)\(['"]([^'"]+)['"]`,
			`router\.([a-z]+)\(['"]([^'"]+)['"]`,
			`routes\s*\[\s*['"]([^'"]+)['"]\s*\]\s*=`,
			`path:\s*['"]([^'"]+)['"]`,
			`@RequestMapping\(['"]([^'"]+)['"]\)`,
		}

		for _, pattern := range routePatterns {
			regex := regexp.MustCompile(pattern)
			matches := regex.FindAllStringSubmatch(scriptContent, -1)

			for _, match := range matches {
				var path, method string

				if len(match) >= 2 {
					if match[1] == "route" && len(match) >= 3 {
						path = match[1]
						// Try to extract method from the handler
						if strings.Contains(match[2], "GET") || strings.Contains(match[2], "get") {
							method = "GET"
						} else if strings.Contains(match[2], "POST") || strings.Contains(match[2], "post") {
							method = "POST"
						} else if strings.Contains(match[2], "PUT") || strings.Contains(match[2], "put") {
							method = "PUT"
						} else if strings.Contains(match[2], "DELETE") || strings.Contains(match[2], "delete") {
							method = "DELETE"
						} else if strings.Contains(match[2], "PATCH") || strings.Contains(match[2], "patch") {
							method = "PATCH"
						} else {
							method = "GET" // Default
						}
					} else if len(match) >= 3 {
						method = strings.ToUpper(match[1])
						path = match[2]
					} else {
						path = match[1]
						method = "GET" // Default
					}

					// Clean up path
					path = d.cleanupURL(path)

					// Skip if path is empty or not valid after cleanup
					if path == "" || !d.isValidAPIURL(path) {
						continue
					}

					// Resolve relative URLs
					resolvedURL := d.resolveURL(baseURL, path)

					// Create endpoint
					endpoint := &Endpoint{
						URL:    resolvedURL,
						Type:   EndpointTypeREST,
						Method: method,
						Score:  75,
					}

					// Try to extract parameters from URL
					params := d.extractURLParameters(path)
					if len(params) > 0 {
						endpoint.Parameters = params
					}

					endpoints = append(endpoints, endpoint)
				}
			}
		}

		// Look for GraphQL endpoints
		graphQLPatterns := []string{
			"graphql",
			"gql",
			"ApolloClient",
			"apolloClient",
			"useQuery",
			"useMutation",
			"mutation\\s*\\{",
			"query\\s*\\{",
			"graphQLClient",
		}

		for _, pattern := range graphQLPatterns {
			if strings.Contains(scriptContent, pattern) {
				// Look for potential GraphQL endpoint URLs
				graphQLURLPatterns := []string{
					`uri:\s*['"]([^'"]+)['"]`,
					`url:\s*['"]([^'"]+)['"]`,
					`endpoint:\s*['"]([^'"]+)['"]`,
					`graphQLURL:\s*['"]([^'"]+)['"]`,
					`fetch\(['"]([^'"]+/graphql[^'"]*)['"]\)`,
					`fetch\(['"]([^'"]+/gql[^'"]*)['"]\)`,
				}

				for _, urlPattern := range graphQLURLPatterns {
					regex := regexp.MustCompile(urlPattern)
					matches := regex.FindAllStringSubmatch(scriptContent, -1)

					for _, match := range matches {
						if len(match) >= 2 {
							url := match[1]

							// Clean up URL
							url = d.cleanupURL(url)

							// Skip if URL is empty or not valid after cleanup
							if url == "" || !d.isValidAPIURL(url) {
								continue
							}

							// Resolve relative URLs
							resolvedURL := d.resolveURL(baseURL, url)

							// Create endpoint
							endpoint := &Endpoint{
								URL:    resolvedURL,
								Type:   EndpointTypeGraphQL,
								Method: "POST", // GraphQL typically uses POST
								Score:  90,
							}

							endpoints = append(endpoints, endpoint)
						}
					}
				}

				// If no specific GraphQL URL found but GraphQL is used,
				// check for common GraphQL endpoint paths
				if len(endpoints) == 0 {
					commonGraphQLPaths := []string{
						"/graphql",
						"/api/graphql",
						"/gql",
						"/api/gql",
						"/v1/graphql",
						"/query",
					}

					for _, path := range commonGraphQLPaths {
						resolvedURL := d.resolveURL(baseURL, path)

						endpoint := &Endpoint{
							URL:    resolvedURL,
							Type:   EndpointTypeGraphQL,
							Method: "POST",
							Score:  70, // Lower score since it's a guess
						}

						endpoints = append(endpoints, endpoint)
					}
				}

				break // Found GraphQL usage, no need to check other patterns
			}
		}
	})

	return d.deduplicateEndpoints(endpoints), nil
}

// cleanupURL cleans up a URL string by removing template literals and variables
func (d *Discoverer) cleanupURL(url string) string {
	// Remove template literals ${...}
	templateLiteralRegex := regexp.MustCompile(`\${[^}]+}`)
	url = templateLiteralRegex.ReplaceAllString(url, "")

	// Remove variable interpolation
	variableRegex := regexp.MustCompile(`\$[a-zA-Z0-9_]+`)
	url = variableRegex.ReplaceAllString(url, "")

	// Remove concatenation
	url = strings.ReplaceAll(url, "' + '", "")
	url = strings.ReplaceAll(url, "\" + \"", "")

	// Remove backticks
	url = strings.ReplaceAll(url, "`", "")

	// Remove any remaining JavaScript expressions
	if strings.Contains(url, "+") || strings.Contains(url, "${") {
		parts := strings.Split(url, "+")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "'") || strings.HasPrefix(part, "\"") {
				// Extract the string literal
				stringLiteralRegex := regexp.MustCompile(`['"]([^'"]+)['"]`)
				if match := stringLiteralRegex.FindStringSubmatch(part); len(match) > 1 {
					return match[1]
				}
			}
		}
		return ""
	}

	return url
}

// isValidAPIURL checks if a URL string is valid for an API endpoint
func (d *Discoverer) isValidAPIURL(url string) bool {
	// Skip empty URLs
	if url == "" {
		return false
	}

	// Skip URLs with JavaScript variables or expressions
	if strings.Contains(url, "${") || strings.Contains(url, "$(") ||
		strings.Contains(url, "+") || strings.Contains(url, "?") {
		return false
	}

	// Skip data URLs, blob URLs, and about: URLs
	if strings.HasPrefix(url, "data:") || strings.HasPrefix(url, "blob:") ||
		strings.HasPrefix(url, "about:") || strings.HasPrefix(url, "javascript:") {
		return false
	}

	// Skip common non-API URLs
	nonAPIPatterns := []string{
		`\.(jpg|jpeg|png|gif|svg|webp|ico|css|js|woff|ttf|eot)$`,
		`\.(html|htm|xml|json|txt|md|pdf|zip|tar|gz)$`,
		`(google-analytics|googletagmanager|facebook|twitter|linkedin)\.com`,
		`(youtube|vimeo|dailymotion|tiktok)\.com`,
		`(cdn|static|assets|media|img|images|fonts|scripts|styles)\.`,
	}

	for _, pattern := range nonAPIPatterns {
		if regexp.MustCompile(pattern).MatchString(url) {
			return false
		}
	}

	return true
}

// extractURLParameters extracts parameters from a URL path
func (d *Discoverer) extractURLParameters(url string) []string {
	var params []string

	// Extract path parameters like :id, {id}, [id]
	pathParamPatterns := []string{
		`:([a-zA-Z0-9_]+)`,    // Express-style :id
		`\{([a-zA-Z0-9_]+)\}`, // Spring/JAX-RS style {id}
		`\[([a-zA-Z0-9_]+)\]`, // Some frameworks use [id]
		`<([a-zA-Z0-9_]+)>`,   // Angular Router <id>
		`\$([a-zA-Z0-9_]+)`,   // PHP style $id
	}

	for _, pattern := range pathParamPatterns {
		regex := regexp.MustCompile(pattern)
		matches := regex.FindAllStringSubmatch(url, -1)

		for _, match := range matches {
			if len(match) > 1 {
				params = append(params, match[1])
			}
		}
	}

	// Extract query parameters
	if strings.Contains(url, "?") {
		parts := strings.Split(url, "?")
		if len(parts) > 1 {
			queryPart := parts[1]
			queryParams := strings.Split(queryPart, "&")

			for _, param := range queryParams {
				paramParts := strings.Split(param, "=")
				if len(paramParts) > 0 {
					params = append(params, paramParts[0])
				}
			}
		}
	}

	return params
}

// isRESTPath checks if a path looks like a REST API endpoint
func (d *Discoverer) isRESTPath(path string) bool {
	// Common REST API path patterns
	restPatterns := []string{
		`/api/`,
		`/v[0-9]+/`,
		`/rest/`,
		`/service/`,
		`/services/`,
		`/resources/`,
		`/data/`,
		`/json/`,
		`/ajax/`,
		`/public/api/`,
		`/private/api/`,
		`/endpoints/`,
		`/gateway/`,
		`/api-gateway/`,
		`/webservice/`,
	}

	for _, pattern := range restPatterns {
		if strings.Contains(path, pattern) {
			return true
		}
	}

	// Check for RESTful resource patterns
	resourcePatterns := []string{
		`/users/?([0-9]+)?$`,
		`/products/?([0-9]+)?$`,
		`/orders/?([0-9]+)?$`,
		`/customers/?([0-9]+)?$`,
		`/items/?([0-9]+)?$`,
		`/accounts/?([0-9]+)?$`,
		`/transactions/?([0-9]+)?$`,
		`/posts/?([0-9]+)?$`,
		`/comments/?([0-9]+)?$`,
		`/articles/?([0-9]+)?$`,
	}

	for _, pattern := range resourcePatterns {
		if regexp.MustCompile(pattern).MatchString(path) {
			return true
		}
	}

	// Check for common HTTP verbs in the path
	verbPatterns := []string{
		`/get[A-Z]`,
		`/post[A-Z]`,
		`/put[A-Z]`,
		`/delete[A-Z]`,
		`/update[A-Z]`,
		`/create[A-Z]`,
		`/fetch[A-Z]`,
		`/retrieve[A-Z]`,
		`/search[A-Z]`,
		`/find[A-Z]`,
	}

	for _, pattern := range verbPatterns {
		if regexp.MustCompile(pattern).MatchString(path) {
			return true
		}
	}

	// Check for path parameters
	paramPatterns := []string{
		`:[a-zA-Z0-9_]+`,    // Express-style :id
		`\{[a-zA-Z0-9_]+\}`, // Spring/JAX-RS style {id}
		`\[[a-zA-Z0-9_]+\]`, // Some frameworks use [id]
		`<[a-zA-Z0-9_]+>`,   // Angular Router <id>
	}

	for _, pattern := range paramPatterns {
		if regexp.MustCompile(pattern).MatchString(path) {
			return true
		}
	}

	return false
}

// isGraphQLPath checks if a path looks like a GraphQL endpoint
func (d *Discoverer) isGraphQLPath(path string) bool {
	// Common GraphQL endpoint patterns
	graphQLPatterns := []string{
		`/graphql`,
		`/gql`,
		`/graphiql`,
		`/graphql/console`,
		`/api/graphql`,
		`/query`,
		`/graphql-api`,
		`/v[0-9]+/graphql`,
		`/hasura`,
		`/prisma`,
		`/apollo`,
	}

	for _, pattern := range graphQLPatterns {
		if strings.Contains(path, pattern) {
			return true
		}
	}

	return false
}

// discoverWebSockets discovers WebSocket endpoints
func (d *Discoverer) discoverWebSockets(doc *goquery.Document, baseURL *url.URL) ([]*Endpoint, error) {
	var endpoints []*Endpoint

	// Look for WebSocket connections in script tags
	doc.Find("script").Each(func(i int, s *goquery.Selection) {
		html, err := s.Html()
		if err != nil {
			return
		}

		// Look for WebSocket constructor calls
		wsRegex := regexp.MustCompile(`new\s+WebSocket\s*\(\s*["']([^"']+)["']`)
		wsMatches := wsRegex.FindAllStringSubmatch(html, -1)
		for _, match := range wsMatches {
			if len(match) > 1 {
				url := match[1]
				if d.isValidURL(url) {
					// Convert http/https to ws/wss if necessary
					if strings.HasPrefix(url, "http:") {
						url = "ws:" + url[5:]
					} else if strings.HasPrefix(url, "https:") {
						url = "wss:" + url[6:]
					}

					endpoint := &Endpoint{
						URL:   url,
						Type:  EndpointTypeWebSocket,
						Score: 100,
					}
					endpoints = append(endpoints, endpoint)
				}
			}
		}

		// Look for Socket.io connections
		socketioRegex := regexp.MustCompile(`io\s*\(\s*["']([^"']+)["']`)
		socketioMatches := socketioRegex.FindAllStringSubmatch(html, -1)
		for _, match := range socketioMatches {
			if len(match) > 1 {
				url := match[1]
				if d.isValidURL(url) {
					endpoint := &Endpoint{
						URL:         d.resolveURL(baseURL, url),
						Type:        EndpointTypeWebSocket,
						Score:       90,
						Description: "Socket.io endpoint",
					}
					endpoints = append(endpoints, endpoint)
				}
			}
		}

		// Look for SockJS connections
		sockjsRegex := regexp.MustCompile(`new\s+SockJS\s*\(\s*["']([^"']+)["']`)
		sockjsMatches := sockjsRegex.FindAllStringSubmatch(html, -1)
		for _, match := range sockjsMatches {
			if len(match) > 1 {
				url := match[1]
				if d.isValidURL(url) {
					endpoint := &Endpoint{
						URL:         d.resolveURL(baseURL, url),
						Type:        EndpointTypeWebSocket,
						Score:       90,
						Description: "SockJS endpoint",
					}
					endpoints = append(endpoints, endpoint)
				}
			}
		}
	})

	return endpoints, nil
}

// discoverSSE discovers Server-Sent Events endpoints
func (d *Discoverer) discoverSSE(doc *goquery.Document, baseURL *url.URL) ([]*Endpoint, error) {
	var endpoints []*Endpoint

	// Look for EventSource in script tags
	doc.Find("script").Each(func(i int, s *goquery.Selection) {
		html, err := s.Html()
		if err != nil {
			return
		}

		// Look for EventSource constructor
		sseRegex := regexp.MustCompile(`new\s+EventSource\s*\(\s*["']([^"']+)["']`)
		sseMatches := sseRegex.FindAllStringSubmatch(html, -1)
		for _, match := range sseMatches {
			if len(match) > 1 {
				url := match[1]
				if d.isValidURL(url) {
					endpoint := &Endpoint{
						URL:   d.resolveURL(baseURL, url),
						Type:  EndpointTypeSSE,
						Score: 100,
					}
					endpoints = append(endpoints, endpoint)
				}
			}
		}
	})

	return endpoints, nil
}

// deduplicateEndpoints removes duplicate endpoints
func (d *Discoverer) deduplicateEndpoints(endpoints []*Endpoint) []*Endpoint {
	seen := make(map[string]bool)
	var result []*Endpoint

	for _, endpoint := range endpoints {
		// Use URL+Type+Method as a unique key
		key := endpoint.URL + "|" + string(endpoint.Type)
		if endpoint.Method != "" {
			key += "|" + endpoint.Method
		}

		if !seen[key] {
			seen[key] = true
			result = append(result, endpoint)
		}
	}

	return result
}

// isValidURL checks if a URL is valid
func (d *Discoverer) isValidURL(urlStr string) bool {
	// Skip empty URLs
	if urlStr == "" {
		return false
	}

	// Skip URLs with placeholders
	placeholders := []string{
		"{",
		"}",
		"${",
		"<%=",
		"<#",
		"[[",
		"]]",
		"{{",
		"}}",
		"${",
		"}",
		"<$",
		"$>",
		"##",
		":#",
		"%{",
		"@{",
		"__", // Double underscore often used as placeholder
	}

	for _, placeholder := range placeholders {
		if strings.Contains(urlStr, placeholder) {
			return false
		}
	}

	// Skip data URLs
	if strings.HasPrefix(urlStr, "data:") {
		return false
	}

	// Skip blob URLs
	if strings.HasPrefix(urlStr, "blob:") {
		return false
	}

	// Skip file URLs
	if strings.HasPrefix(urlStr, "file:") {
		return false
	}

	// Skip about URLs
	if strings.HasPrefix(urlStr, "about:") {
		return false
	}

	// Skip mailto URLs
	if strings.HasPrefix(urlStr, "mailto:") {
		return false
	}

	// Skip javascript URLs
	if strings.HasPrefix(urlStr, "javascript:") {
		return false
	}

	// Check if it's a valid relative or absolute URL
	if strings.HasPrefix(urlStr, "/") {
		return true // Relative URL is valid
	}

	// Check if it's a valid HTTP URL
	if strings.HasPrefix(urlStr, "http://") || strings.HasPrefix(urlStr, "https://") {
		_, err := url.Parse(urlStr)
		return err == nil
	}

	// Check for path-relative URLs
	if !strings.Contains(urlStr, "://") && !strings.HasPrefix(urlStr, "/") {
		// Could be a path-relative URL like "api/users"
		if strings.Contains(urlStr, "/") || strings.Contains(urlStr, ".") {
			return true
		}
	}

	return false
}

// resolveURL resolves a URL against a base URL
func (d *Discoverer) resolveURL(base *url.URL, urlStr string) string {
	// Handle absolute URLs
	if strings.HasPrefix(urlStr, "http://") || strings.HasPrefix(urlStr, "https://") {
		return urlStr
	}

	// Handle protocol-relative URLs
	if strings.HasPrefix(urlStr, "//") {
		return base.Scheme + ":" + urlStr
	}

	// Handle specific URL formatting issues
	urlStr = strings.TrimSpace(urlStr)

	// Remove URL fragments
	if idx := strings.Index(urlStr, "#"); idx != -1 {
		urlStr = urlStr[:idx]
	}

	// Ensure relative URLs start with /
	if !strings.HasPrefix(urlStr, "/") && !strings.HasPrefix(urlStr, ".") {
		// If it's not a path-relative URL (like ./api or ../api)
		if !strings.Contains(urlStr, "://") {
			urlStr = "/" + urlStr
		}
	}

	// Parse the URL
	rel, err := url.Parse(urlStr)
	if err != nil {
		return urlStr
	}

	// Resolve against base URL
	abs := base.ResolveReference(rel)

	// Normalize the URL
	abs.Path = d.normalizePath(abs.Path)

	return abs.String()
}

// normalizePath normalizes a URL path
func (d *Discoverer) normalizePath(path string) string {
	// Replace multiple slashes with a single slash
	for strings.Contains(path, "//") {
		path = strings.Replace(path, "//", "/", -1)
	}

	// Handle ./ and ../ in paths
	parts := strings.Split(path, "/")
	var result []string

	for _, part := range parts {
		if part == "." {
			// Skip this segment
			continue
		} else if part == ".." && len(result) > 0 {
			// Remove the last segment
			result = result[:len(result)-1]
		} else if part != "" {
			// Add this segment
			result = append(result, part)
		}
	}

	// Reconstruct the path
	path = "/" + strings.Join(result, "/")

	return path
}
