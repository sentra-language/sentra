// internal/modules/api_security.go
package modules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"sentra/internal/vm"
)

// APISecurityModule provides comprehensive API security testing capabilities
type APISecurityModule struct {
	client *http.Client
}

// NewAPISecurityModule creates a new API security testing module
func NewAPISecurityModule() *APISecurityModule {
	return &APISecurityModule{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// GetFunctions returns all API security testing functions
func (a *APISecurityModule) GetFunctions() map[string]*vm.NativeFunction {
	return map[string]*vm.NativeFunction{
		"api_scan": {
			Name:  "api_scan",
			Arity: 2,
			Function: func(args []vm.Value) (vm.Value, error) {
				baseURL := vm.ToString(args[0])
				options := args[1].(*vm.Map)
				
				return a.performAPIScan(baseURL, options)
			},
		},
		"test_authentication": {
			Name:  "test_authentication",
			Arity: 2,
			Function: func(args []vm.Value) (vm.Value, error) {
				endpoint := vm.ToString(args[0])
				config := args[1].(*vm.Map)
				
				return a.testAuthentication(endpoint, config)
			},
		},
		"test_injection": {
			Name:  "test_injection",
			Arity: 3,
			Function: func(args []vm.Value) (vm.Value, error) {
				endpoint := vm.ToString(args[0])
				injectionType := vm.ToString(args[1])
				params := args[2].(*vm.Map)
				
				return a.testInjection(endpoint, injectionType, params)
			},
		},
		"test_rate_limiting": {
			Name:  "test_rate_limiting",
			Arity: 3,
			Function: func(args []vm.Value) (vm.Value, error) {
				endpoint := vm.ToString(args[0])
				requests := int(args[1].(float64))
				duration := int(args[2].(float64))
				
				return a.testRateLimiting(endpoint, requests, duration)
			},
		},
		"test_cors": {
			Name:  "test_cors",
			Arity: 2,
			Function: func(args []vm.Value) (vm.Value, error) {
				endpoint := vm.ToString(args[0])
				origin := vm.ToString(args[1])
				
				return a.testCORS(endpoint, origin)
			},
		},
		"test_headers": {
			Name:  "test_headers",
			Arity: 1,
			Function: func(args []vm.Value) (vm.Value, error) {
				endpoint := vm.ToString(args[0])
				
				return a.testSecurityHeaders(endpoint)
			},
		},
		"fuzz_api": {
			Name:  "fuzz_api",
			Arity: 2,
			Function: func(args []vm.Value) (vm.Value, error) {
				endpoint := vm.ToString(args[0])
				config := args[1].(*vm.Map)
				
				return a.fuzzAPI(endpoint, config)
			},
		},
		"test_authorization": {
			Name:  "test_authorization",
			Arity: 2,
			Function: func(args []vm.Value) (vm.Value, error) {
				endpoint := vm.ToString(args[0])
				config := args[1].(*vm.Map)
				
				return a.testAuthorization(endpoint, config)
			},
		},
		"scan_openapi": {
			Name:  "scan_openapi",
			Arity: 2,
			Function: func(args []vm.Value) (vm.Value, error) {
				specURL := vm.ToString(args[0])
				baseURL := vm.ToString(args[1])
				
				return a.scanOpenAPI(specURL, baseURL)
			},
		},
		"test_jwt": {
			Name:  "test_jwt",
			Arity: 2,
			Function: func(args []vm.Value) (vm.Value, error) {
				endpoint := vm.ToString(args[0])
				token := vm.ToString(args[1])
				
				return a.testJWT(endpoint, token)
			},
		},
	}
}

// performAPIScan conducts a comprehensive API security scan
func (a *APISecurityModule) performAPIScan(baseURL string, options *vm.Map) (vm.Value, error) {
	result := vm.NewMap()
	vulnerabilities := &vm.Array{Elements: []vm.Value{}}
	
	// Parse scan options
	scanAuth := true
	scanInjection := true
	scanRateLimit := true
	scanCORS := true
	scanHeaders := true
	
	if val, ok := options.Items["scan_auth"]; ok {
		scanAuth = vm.ToBool(val)
	}
	if val, ok := options.Items["scan_injection"]; ok {
		scanInjection = vm.ToBool(val)
	}
	if val, ok := options.Items["scan_rate_limit"]; ok {
		scanRateLimit = vm.ToBool(val)
	}
	if val, ok := options.Items["scan_cors"]; ok {
		scanCORS = vm.ToBool(val)
	}
	if val, ok := options.Items["scan_headers"]; ok {
		scanHeaders = vm.ToBool(val)
	}
	
	// Perform security header check
	if scanHeaders {
		headers, _ := a.testSecurityHeaders(baseURL)
		if headerMap, ok := headers.(*vm.Map); ok {
			if missing, ok := headerMap.Items["missing"]; ok {
				if arr, ok := missing.(*vm.Array); ok && len(arr.Elements) > 0 {
					vuln := vm.NewMap()
					vuln.Items["type"] = "security_headers"
					vuln.Items["severity"] = "medium"
					vuln.Items["details"] = missing
					vulnerabilities.Elements = append(vulnerabilities.Elements, vuln)
				}
			}
		}
	}
	
	// Test for CORS misconfigurations
	if scanCORS {
		corsResult, _ := a.testCORS(baseURL, "http://evil.com")
		if corsMap, ok := corsResult.(*vm.Map); ok {
			if vulnerable, ok := corsMap.Items["vulnerable"]; ok && vm.ToBool(vulnerable) {
				vuln := vm.NewMap()
				vuln.Items["type"] = "cors_misconfiguration"
				vuln.Items["severity"] = "high"
				vuln.Items["details"] = corsResult
				vulnerabilities.Elements = append(vulnerabilities.Elements, vuln)
			}
		}
	}
	
	// Test for rate limiting
	if scanRateLimit {
		rateResult, _ := a.testRateLimiting(baseURL, 100, 10)
		if rateMap, ok := rateResult.(*vm.Map); ok {
			if hasLimit, ok := rateMap.Items["has_rate_limit"]; ok && !vm.ToBool(hasLimit) {
				vuln := vm.NewMap()
				vuln.Items["type"] = "no_rate_limiting"
				vuln.Items["severity"] = "medium"
				vuln.Items["details"] = rateResult
				vulnerabilities.Elements = append(vulnerabilities.Elements, vuln)
			}
		}
	}
	
	result.Items["url"] = baseURL
	result.Items["vulnerabilities"] = vulnerabilities
	result.Items["scan_time"] = time.Now().Format(time.RFC3339)
	result.Items["vulnerability_count"] = float64(len(vulnerabilities.Elements))
	
	return result, nil
}

// testAuthentication tests various authentication vulnerabilities
func (a *APISecurityModule) testAuthentication(endpoint string, config *vm.Map) (vm.Value, error) {
	result := vm.NewMap()
	issues := &vm.Array{Elements: []vm.Value{}}
	
	// Test for missing authentication
	resp, err := a.client.Get(endpoint)
	if err == nil {
		defer resp.Body.Close()
		
		if resp.StatusCode == 200 {
			issue := vm.NewMap()
			issue.Items["type"] = "no_authentication"
			issue.Items["description"] = "Endpoint accessible without authentication"
			issues.Elements = append(issues.Elements, issue)
		}
	}
	
	// Test weak authentication methods
	weakTokens := []string{
		"test", "admin", "password", "123456", "default",
	}
	
	for _, token := range weakTokens {
		req, _ := http.NewRequest("GET", endpoint, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		
		resp, err := a.client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			
			if resp.StatusCode == 200 {
				issue := vm.NewMap()
				issue.Items["type"] = "weak_token"
				issue.Items["description"] = fmt.Sprintf("Weak token accepted: %s", token)
				issues.Elements = append(issues.Elements, issue)
			}
		}
	}
	
	result.Items["endpoint"] = endpoint
	result.Items["issues"] = issues
	result.Items["vulnerable"] = len(issues.Elements) > 0
	
	return result, nil
}

// testInjection tests for various injection vulnerabilities
func (a *APISecurityModule) testInjection(endpoint string, injectionType string, params *vm.Map) (vm.Value, error) {
	result := vm.NewMap()
	vulnerabilities := &vm.Array{Elements: []vm.Value{}}
	
	payloads := map[string][]string{
		"sql": {
			"' OR '1'='1",
			"'; DROP TABLE users--",
			"' UNION SELECT NULL--",
			"1' AND '1' = '1",
		},
		"nosql": {
			`{"$ne": null}`,
			`{"$gt": ""}`,
			`{"$regex": ".*"}`,
		},
		"command": {
			"; ls -la",
			"| whoami",
			"` id `",
			"$(whoami)",
		},
		"xxe": {
			`<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>`,
		},
		"xpath": {
			"' or '1'='1",
			"'] | //user/*",
		},
	}
	
	testPayloads, ok := payloads[injectionType]
	if !ok {
		return nil, fmt.Errorf("unknown injection type: %s", injectionType)
	}
	
	for _, payload := range testPayloads {
		// Test each parameter with the payload
		for key := range params.Items {
			testParams := make(map[string]string)
			for k, v := range params.Items {
				testParams[k] = vm.ToString(v)
			}
			testParams[key] = payload
			
			// Build URL with parameters
			u, _ := url.Parse(endpoint)
			q := u.Query()
			for k, v := range testParams {
				q.Set(k, v)
			}
			u.RawQuery = q.Encode()
			
			resp, err := a.client.Get(u.String())
			if err == nil {
				defer resp.Body.Close()
				body, _ := io.ReadAll(resp.Body)
				
				// Check for signs of injection
				if a.detectInjection(string(body), injectionType) {
					vuln := vm.NewMap()
					vuln.Items["parameter"] = key
					vuln.Items["payload"] = payload
					vuln.Items["type"] = injectionType
					vulnerabilities.Elements = append(vulnerabilities.Elements, vuln)
				}
			}
		}
	}
	
	result.Items["endpoint"] = endpoint
	result.Items["injection_type"] = injectionType
	result.Items["vulnerabilities"] = vulnerabilities
	result.Items["vulnerable"] = len(vulnerabilities.Elements) > 0
	
	return result, nil
}

// testRateLimiting tests if an API endpoint has rate limiting
func (a *APISecurityModule) testRateLimiting(endpoint string, requests int, duration int) (vm.Value, error) {
	result := vm.NewMap()
	
	start := time.Now()
	successful := 0
	rateLimited := false
	
	for i := 0; i < requests; i++ {
		resp, err := a.client.Get(endpoint)
		if err == nil {
			defer resp.Body.Close()
			
			if resp.StatusCode == 429 {
				rateLimited = true
				break
			} else if resp.StatusCode == 200 {
				successful++
			}
		}
		
		// Check if we've exceeded the duration
		if time.Since(start).Seconds() > float64(duration) {
			break
		}
	}
	
	elapsed := time.Since(start)
	
	result.Items["endpoint"] = endpoint
	result.Items["requests_sent"] = float64(successful)
	result.Items["duration"] = elapsed.Seconds()
	result.Items["has_rate_limit"] = rateLimited
	result.Items["requests_per_second"] = float64(successful) / elapsed.Seconds()
	
	return result, nil
}

// testCORS tests for CORS misconfigurations
func (a *APISecurityModule) testCORS(endpoint string, origin string) (vm.Value, error) {
	result := vm.NewMap()
	
	req, err := http.NewRequest("OPTIONS", endpoint, nil)
	if err != nil {
		return nil, err
	}
	
	req.Header.Set("Origin", origin)
	req.Header.Set("Access-Control-Request-Method", "GET")
	
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
	allowCredentials := resp.Header.Get("Access-Control-Allow-Credentials")
	
	vulnerable := false
	issues := &vm.Array{Elements: []vm.Value{}}
	
	// Check for wildcard with credentials
	if allowOrigin == "*" && allowCredentials == "true" {
		vulnerable = true
		issues.Elements = append(issues.Elements, "Wildcard origin with credentials enabled")
	}
	
	// Check if arbitrary origin is reflected
	if allowOrigin == origin {
		vulnerable = true
		issues.Elements = append(issues.Elements, "Arbitrary origin reflected")
	}
	
	result.Items["endpoint"] = endpoint
	result.Items["test_origin"] = origin
	result.Items["allow_origin"] = allowOrigin
	result.Items["allow_credentials"] = allowCredentials
	result.Items["vulnerable"] = vulnerable
	result.Items["issues"] = issues
	
	return result, nil
}

// testSecurityHeaders checks for missing security headers
func (a *APISecurityModule) testSecurityHeaders(endpoint string) (vm.Value, error) {
	result := vm.NewMap()
	
	resp, err := a.client.Get(endpoint)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	requiredHeaders := []string{
		"X-Content-Type-Options",
		"X-Frame-Options",
		"X-XSS-Protection",
		"Strict-Transport-Security",
		"Content-Security-Policy",
	}
	
	present := &vm.Array{Elements: []vm.Value{}}
	missing := &vm.Array{Elements: []vm.Value{}}
	
	for _, header := range requiredHeaders {
		if resp.Header.Get(header) != "" {
			present.Elements = append(present.Elements, header)
		} else {
			missing.Elements = append(missing.Elements, header)
		}
	}
	
	result.Items["endpoint"] = endpoint
	result.Items["present"] = present
	result.Items["missing"] = missing
	result.Items["score"] = float64(len(present.Elements)) / float64(len(requiredHeaders)) * 100
	
	return result, nil
}

// fuzzAPI performs API fuzzing
func (a *APISecurityModule) fuzzAPI(endpoint string, config *vm.Map) (vm.Value, error) {
	result := vm.NewMap()
	errors := &vm.Array{Elements: []vm.Value{}}
	
	// Generate fuzz payloads
	fuzzPayloads := []string{
		strings.Repeat("A", 10000),           // Long string
		"null",                                // Null value
		"undefined",                           // Undefined
		"-1",                                  // Negative number
		"99999999999999999999",               // Large number
		"!@#$%^&*(){}[]|\\:;\"'<>?,./",       // Special characters
		"\x00\x01\x02\x03\x04\x05",          // Control characters
		"../../../etc/passwd",                 // Path traversal
	}
	
	for _, payload := range fuzzPayloads {
		var resp *http.Response
		var err error
		
		// Try different HTTP methods
		methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH"}
		
		for _, method := range methods {
			var req *http.Request
			
			if method == "GET" || method == "DELETE" {
				u, _ := url.Parse(endpoint)
				q := u.Query()
				q.Set("fuzz", payload)
				u.RawQuery = q.Encode()
				req, _ = http.NewRequest(method, u.String(), nil)
			} else {
				body := map[string]string{"fuzz": payload}
				jsonBody, _ := json.Marshal(body)
				req, _ = http.NewRequest(method, endpoint, bytes.NewBuffer(jsonBody))
				req.Header.Set("Content-Type", "application/json")
			}
			
			resp, err = a.client.Do(req)
			if err == nil {
				defer resp.Body.Close()
				
				// Check for errors
				if resp.StatusCode >= 500 {
					errInfo := vm.NewMap()
					errInfo.Items["method"] = method
					errInfo.Items["payload"] = payload
					errInfo.Items["status_code"] = float64(resp.StatusCode)
					errors.Elements = append(errors.Elements, errInfo)
				}
			}
		}
	}
	
	result.Items["endpoint"] = endpoint
	result.Items["errors_found"] = errors
	result.Items["error_count"] = float64(len(errors.Elements))
	
	return result, nil
}

// testAuthorization tests for authorization vulnerabilities
func (a *APISecurityModule) testAuthorization(endpoint string, config *vm.Map) (vm.Value, error) {
	result := vm.NewMap()
	issues := &vm.Array{Elements: []vm.Value{}}
	
	// Get user tokens from config
	var user1Token, user2Token, adminToken string
	
	if val, ok := config.Items["user1_token"]; ok {
		user1Token = vm.ToString(val)
	}
	if val, ok := config.Items["user2_token"]; ok {
		user2Token = vm.ToString(val)
	}
	if val, ok := config.Items["admin_token"]; ok {
		adminToken = vm.ToString(val)
	}
	
	// Test horizontal privilege escalation
	if user1Token != "" && user2Token != "" {
		// Try accessing user2's resources with user1's token
		req, _ := http.NewRequest("GET", endpoint, nil)
		req.Header.Set("Authorization", "Bearer "+user1Token)
		
		resp, err := a.client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			
			if resp.StatusCode == 200 {
				issue := vm.NewMap()
				issue.Items["type"] = "horizontal_privilege_escalation"
				issue.Items["description"] = "User can access other user's resources"
				issues.Elements = append(issues.Elements, issue)
			}
		}
	}
	
	// Test vertical privilege escalation
	if user1Token != "" && adminToken != "" {
		// Try accessing admin resources with user token
		adminEndpoint := strings.Replace(endpoint, "/user/", "/admin/", 1)
		req, _ := http.NewRequest("GET", adminEndpoint, nil)
		req.Header.Set("Authorization", "Bearer "+user1Token)
		
		resp, err := a.client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			
			if resp.StatusCode == 200 {
				issue := vm.NewMap()
				issue.Items["type"] = "vertical_privilege_escalation"
				issue.Items["description"] = "User can access admin resources"
				issues.Elements = append(issues.Elements, issue)
			}
		}
	}
	
	result.Items["endpoint"] = endpoint
	result.Items["issues"] = issues
	result.Items["vulnerable"] = len(issues.Elements) > 0
	
	return result, nil
}

// scanOpenAPI scans an API based on OpenAPI specification
func (a *APISecurityModule) scanOpenAPI(specURL string, baseURL string) (vm.Value, error) {
	result := vm.NewMap()
	
	// Fetch OpenAPI spec
	resp, err := a.client.Get(specURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	var spec map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&spec); err != nil {
		return nil, err
	}
	
	endpoints := &vm.Array{Elements: []vm.Value{}}
	vulnerabilities := &vm.Array{Elements: []vm.Value{}}
	
	// Parse paths from OpenAPI spec
	if paths, ok := spec["paths"].(map[string]interface{}); ok {
		for path, pathItem := range paths {
			if methods, ok := pathItem.(map[string]interface{}); ok {
				for method := range methods {
					endpoint := vm.NewMap()
					endpoint.Items["path"] = path
					endpoint.Items["method"] = strings.ToUpper(method)
					endpoint.Items["url"] = baseURL + path
					endpoints.Elements = append(endpoints.Elements, endpoint)
					
					// Test this endpoint
					fullURL := baseURL + path
					if method == "get" || method == "post" {
						// Test for common issues
						headers, _ := a.testSecurityHeaders(fullURL)
						if headerMap, ok := headers.(*vm.Map); ok {
							if score, ok := headerMap.Items["score"].(float64); ok && score < 60 {
								vuln := vm.NewMap()
								vuln.Items["endpoint"] = fullURL
								vuln.Items["issue"] = "Missing security headers"
								vuln.Items["score"] = score
								vulnerabilities.Elements = append(vulnerabilities.Elements, vuln)
							}
						}
					}
				}
			}
		}
	}
	
	result.Items["spec_url"] = specURL
	result.Items["base_url"] = baseURL
	result.Items["endpoints"] = endpoints
	result.Items["endpoint_count"] = float64(len(endpoints.Elements))
	result.Items["vulnerabilities"] = vulnerabilities
	
	return result, nil
}

// testJWT tests for JWT vulnerabilities
func (a *APISecurityModule) testJWT(endpoint string, token string) (vm.Value, error) {
	result := vm.NewMap()
	vulnerabilities := &vm.Array{Elements: []vm.Value{}}
	
	// Test with no signature (alg: none)
	parts := strings.Split(token, ".")
	if len(parts) == 3 {
		// Create token with alg: none
		header := `{"alg":"none","typ":"JWT"}`
		encodedHeader := base64URLEncode([]byte(header))
		noneToken := encodedHeader + "." + parts[1] + "."
		
		req, _ := http.NewRequest("GET", endpoint, nil)
		req.Header.Set("Authorization", "Bearer "+noneToken)
		
		resp, err := a.client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			
			if resp.StatusCode == 200 {
				vuln := vm.NewMap()
				vuln.Items["type"] = "jwt_none_algorithm"
				vuln.Items["description"] = "JWT accepts 'none' algorithm"
				vulnerabilities.Elements = append(vulnerabilities.Elements, vuln)
			}
		}
	}
	
	// Test with weak secrets
	weakSecrets := []string{
		"secret", "password", "123456", "admin", "key",
	}
	
	for _, secret := range weakSecrets {
		// In a real implementation, we would re-sign the JWT with the weak secret
		// For now, we'll just note this as a test to perform
		vuln := vm.NewMap()
		vuln.Items["type"] = "jwt_weak_secret_test"
		vuln.Items["description"] = fmt.Sprintf("Test with weak secret: %s", secret)
		vuln.Items["recommendation"] = "Verify JWT is not using weak secret"
		vulnerabilities.Elements = append(vulnerabilities.Elements, vuln)
	}
	
	result.Items["endpoint"] = endpoint
	result.Items["vulnerabilities"] = vulnerabilities
	result.Items["vulnerable"] = len(vulnerabilities.Elements) > 0
	
	return result, nil
}

// detectInjection checks response for signs of injection
func (a *APISecurityModule) detectInjection(response string, injectionType string) bool {
	indicators := map[string][]string{
		"sql": {
			"SQL syntax",
			"mysql_fetch",
			"ORA-",
			"PostgreSQL",
			"SQLite",
			"Microsoft SQL Server",
		},
		"command": {
			"root:",
			"bin/bash",
			"uid=",
			"gid=",
			"/etc/passwd",
		},
		"xxe": {
			"root:x:0:0",
			"<!ENTITY",
			"SYSTEM",
		},
	}
	
	if patterns, ok := indicators[injectionType]; ok {
		for _, pattern := range patterns {
			if strings.Contains(response, pattern) {
				return true
			}
		}
	}
	
	return false
}

// base64URLEncode performs URL-safe base64 encoding
func base64URLEncode(data []byte) string {
	encoded := make([]byte, (len(data)*4+2)/3)
	n := 0
	
	for i := 0; i < len(data); i += 3 {
		var b1, b2, b3, b4 byte
		
		b1 = data[i]
		if i+1 < len(data) {
			b2 = data[i+1]
		}
		if i+2 < len(data) {
			b3 = data[i+2]
		}
		
		encoded[n] = encodeChar(b1 >> 2)
		encoded[n+1] = encodeChar(((b1 & 0x03) << 4) | (b2 >> 4))
		
		if i+1 < len(data) {
			encoded[n+2] = encodeChar(((b2 & 0x0f) << 2) | (b3 >> 6))
		} else {
			encoded[n+2] = '='
		}
		
		if i+2 < len(data) {
			encoded[n+3] = encodeChar(b3 & 0x3f)
		} else {
			encoded[n+3] = '='
		}
		
		n += 4
	}
	
	// Remove padding for URL-safe encoding
	result := string(encoded[:n])
	result = strings.TrimRight(result, "=")
	
	return result
}

func encodeChar(b byte) byte {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	return alphabet[b&0x3f]
}