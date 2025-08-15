// Package webclient provides advanced HTTP client and server capabilities for Sentra
package webclient

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"
)

// WebClientModule provides HTTP client/server functionality
type WebClientModule struct {
	Clients    map[string]*HTTPClient
	Servers    map[string]*HTTPServer
	Sessions   map[string]*Session
	mu         sync.RWMutex
}

// HTTPClient represents an advanced HTTP client
type HTTPClient struct {
	ID           string
	Client       *http.Client
	BaseURL      string
	Headers      map[string]string
	Cookies      *cookiejar.Jar
	Timeout      time.Duration
	UserAgent    string
	ProxyURL     string
	FollowRedirect bool
	TLSVerify    bool
}

// HTTPServer represents an HTTP server
type HTTPServer struct {
	ID       string
	Server   *http.Server
	Handlers map[string]http.HandlerFunc
	Port     int
	TLS      bool
	CertFile string
	KeyFile  string
	Running  bool
}

// Session represents an HTTP session with authentication
type Session struct {
	ID          string
	Client      *HTTPClient
	Authenticated bool
	Username    string
	Token       string
	CSRFToken   string
	Cookies     []*http.Cookie
}

// HTTPRequest represents a detailed HTTP request
type HTTPRequest struct {
	Method      string
	URL         string
	Headers     map[string]string
	Body        string
	Cookies     map[string]string
	Timeout     time.Duration
	FollowRedirect bool
}

// HTTPResponse represents a detailed HTTP response
type HTTPResponse struct {
	StatusCode   int
	Status       string
	Headers      map[string][]string
	Body         string
	Cookies      []*http.Cookie
	ContentType  string
	Length       int64
	ResponseTime time.Duration
	Redirects    []string
	TLSInfo      *TLSInfo
}

// TLSInfo contains SSL/TLS certificate information
type TLSInfo struct {
	Version            string
	CipherSuite        string
	ServerCertificates []CertInfo
	PeerCertificates   []CertInfo
}

// CertInfo contains certificate details
type CertInfo struct {
	Subject       string
	Issuer        string
	SerialNumber  string
	NotBefore     time.Time
	NotAfter      time.Time
	DNSNames      []string
	IPAddresses   []string
	KeyUsage      []string
	IsCA          bool
}

// WebVulnScan represents web vulnerability scan results
type WebVulnScan struct {
	URL          string
	Vulnerabilities []WebVuln
	ScanTime     time.Time
	Duration     time.Duration
}

// WebVuln represents a web vulnerability
type WebVuln struct {
	Type        string // SQL_INJECTION, XSS, CSRF, etc.
	Severity    string // LOW, MEDIUM, HIGH, CRITICAL
	URL         string
	Parameter   string
	Payload     string
	Evidence    string
	Description string
	Solution    string
}

// NewWebClientModule creates a new web client module
func NewWebClientModule() *WebClientModule {
	return &WebClientModule{
		Clients:  make(map[string]*HTTPClient),
		Servers:  make(map[string]*HTTPServer),
		Sessions: make(map[string]*Session),
	}
}

// CreateClient creates a new HTTP client
func (w *WebClientModule) CreateClient(id string, config map[string]interface{}) (*HTTPClient, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Create cookie jar
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	// Configure TLS
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // Default to skip verification for testing
	}

	if verify, ok := config["tls_verify"].(bool); ok {
		tlsConfig.InsecureSkipVerify = !verify
	}

	// Create transport
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	// Configure proxy if provided
	if proxyURL, ok := config["proxy"].(string); ok && proxyURL != "" {
		if parsed, err := url.Parse(proxyURL); err == nil {
			transport.Proxy = http.ProxyURL(parsed)
		}
	}

	// Create HTTP client
	client := &http.Client{
		Jar:       jar,
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	// Configure timeout
	if timeout, ok := config["timeout"].(time.Duration); ok {
		client.Timeout = timeout
	} else if timeoutSec, ok := config["timeout"].(int); ok {
		client.Timeout = time.Duration(timeoutSec) * time.Second
	}

	// Configure redirect policy
	followRedirect := true
	if follow, ok := config["follow_redirect"].(bool); ok {
		followRedirect = follow
	}

	if !followRedirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	httpClient := &HTTPClient{
		ID:             id,
		Client:         client,
		Headers:        make(map[string]string),
		Cookies:        jar,
		Timeout:        client.Timeout,
		UserAgent:      "Sentra Security Scanner 1.0",
		FollowRedirect: followRedirect,
		TLSVerify:      !tlsConfig.InsecureSkipVerify,
	}

	// Set base URL
	if baseURL, ok := config["base_url"].(string); ok {
		httpClient.BaseURL = baseURL
	}

	// Set user agent
	if ua, ok := config["user_agent"].(string); ok {
		httpClient.UserAgent = ua
	}

	// Set default headers
	if headers, ok := config["headers"].(map[string]string); ok {
		for k, v := range headers {
			httpClient.Headers[k] = v
		}
	}

	w.Clients[id] = httpClient
	return httpClient, nil
}

// Request performs an HTTP request
func (w *WebClientModule) Request(clientID string, req *HTTPRequest) (*HTTPResponse, error) {
	w.mu.RLock()
	client, exists := w.Clients[clientID]
	w.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("client not found: %s", clientID)
	}

	startTime := time.Now()

	// Prepare request body
	var body io.Reader
	if req.Body != "" {
		body = strings.NewReader(req.Body)
	}

	// Create HTTP request
	httpReq, err := http.NewRequest(req.Method, req.URL, body)
	if err != nil {
		return nil, err
	}

	// Set headers
	httpReq.Header.Set("User-Agent", client.UserAgent)
	for k, v := range client.Headers {
		httpReq.Header.Set(k, v)
	}
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	// Set cookies
	for name, value := range req.Cookies {
		httpReq.AddCookie(&http.Cookie{Name: name, Value: value})
	}

	// Perform request
	resp, err := client.Client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read response body
	var bodyBytes []byte
	if strings.Contains(resp.Header.Get("Content-Encoding"), "gzip") {
		gzipReader, err := gzip.NewReader(resp.Body)
		if err == nil {
			defer gzipReader.Close()
			bodyBytes, _ = io.ReadAll(gzipReader)
		}
	} else {
		bodyBytes, _ = io.ReadAll(resp.Body)
	}

	// Build response
	response := &HTTPResponse{
		StatusCode:   resp.StatusCode,
		Status:       resp.Status,
		Headers:      resp.Header,
		Body:         string(bodyBytes),
		Cookies:      resp.Cookies(),
		ContentType:  resp.Header.Get("Content-Type"),
		Length:       resp.ContentLength,
		ResponseTime: time.Since(startTime),
	}

	// Extract TLS information
	if resp.TLS != nil {
		response.TLSInfo = w.extractTLSInfo(resp.TLS)
	}

	return response, nil
}

// extractTLSInfo extracts TLS certificate information
func (w *WebClientModule) extractTLSInfo(state *tls.ConnectionState) *TLSInfo {
	tlsInfo := &TLSInfo{
		Version:     w.getTLSVersion(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
	}

	// Extract server certificates
	for _, cert := range state.PeerCertificates {
		certInfo := CertInfo{
			Subject:      cert.Subject.String(),
			Issuer:       cert.Issuer.String(),
			SerialNumber: cert.SerialNumber.String(),
			NotBefore:    cert.NotBefore,
			NotAfter:     cert.NotAfter,
			DNSNames:     cert.DNSNames,
			IsCA:         cert.IsCA,
		}

		// Convert IP addresses
		for _, ip := range cert.IPAddresses {
			certInfo.IPAddresses = append(certInfo.IPAddresses, ip.String())
		}

		tlsInfo.PeerCertificates = append(tlsInfo.PeerCertificates, certInfo)
	}

	return tlsInfo
}

// getTLSVersion converts TLS version number to string
func (w *WebClientModule) getTLSVersion(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

// CreateSession creates an authenticated session
func (w *WebClientModule) CreateSession(sessionID, clientID string) (*Session, error) {
	w.mu.RLock()
	client, exists := w.Clients[clientID]
	w.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("client not found: %s", clientID)
	}

	session := &Session{
		ID:            sessionID,
		Client:        client,
		Authenticated: false,
		Cookies:       make([]*http.Cookie, 0),
	}

	w.mu.Lock()
	w.Sessions[sessionID] = session
	w.mu.Unlock()

	return session, nil
}

// Login performs authentication and establishes a session
func (w *WebClientModule) Login(sessionID, loginURL, username, password string, extraParams map[string]string) error {
	w.mu.RLock()
	session, exists := w.Sessions[sessionID]
	w.mu.RUnlock()

	if !exists {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	// Prepare login data
	data := url.Values{}
	data.Set("username", username)
	data.Set("password", password)

	// Add extra parameters
	for k, v := range extraParams {
		data.Set(k, v)
	}

	// Perform login request
	req := &HTTPRequest{
		Method: "POST",
		URL:    loginURL,
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		},
		Body: data.Encode(),
	}

	resp, err := w.Request(session.Client.ID, req)
	if err != nil {
		return err
	}

	// Check for successful login (customize based on application)
	if resp.StatusCode == 200 || resp.StatusCode == 302 {
		session.Authenticated = true
		session.Username = username
		session.Cookies = resp.Cookies

		// Extract authentication token if present
		for _, cookie := range resp.Cookies {
			if strings.Contains(strings.ToLower(cookie.Name), "token") ||
			   strings.Contains(strings.ToLower(cookie.Name), "session") {
				session.Token = cookie.Value
				break
			}
		}

		return nil
	}

	return fmt.Errorf("login failed with status: %d", resp.StatusCode)
}

// ScanWebVulnerabilities performs web vulnerability scanning
func (w *WebClientModule) ScanWebVulnerabilities(clientID, targetURL string) (*WebVulnScan, error) {
	startTime := time.Now()
	scan := &WebVulnScan{
		URL:             targetURL,
		Vulnerabilities: make([]WebVuln, 0),
		ScanTime:        startTime,
	}

	// Test for SQL Injection
	sqlVulns := w.testSQLInjection(clientID, targetURL)
	scan.Vulnerabilities = append(scan.Vulnerabilities, sqlVulns...)

	// Test for XSS
	xssVulns := w.testXSS(clientID, targetURL)
	scan.Vulnerabilities = append(scan.Vulnerabilities, xssVulns...)

	// Test for directory traversal
	dirVulns := w.testDirectoryTraversal(clientID, targetURL)
	scan.Vulnerabilities = append(scan.Vulnerabilities, dirVulns...)

	// Test for information disclosure
	infoVulns := w.testInformationDisclosure(clientID, targetURL)
	scan.Vulnerabilities = append(scan.Vulnerabilities, infoVulns...)

	scan.Duration = time.Since(startTime)
	return scan, nil
}

// testSQLInjection tests for SQL injection vulnerabilities
func (w *WebClientModule) testSQLInjection(clientID, targetURL string) []WebVuln {
	var vulns []WebVuln

	sqlPayloads := []string{
		"'",
		"' OR '1'='1",
		"' UNION SELECT NULL--",
		"'; DROP TABLE users--",
		"1' AND '1'='2",
	}

	for _, payload := range sqlPayloads {
		// Test in URL parameters
		testURL := targetURL + "?id=" + url.QueryEscape(payload)
		
		req := &HTTPRequest{
			Method: "GET",
			URL:    testURL,
		}

		resp, err := w.Request(clientID, req)
		if err != nil {
			continue
		}

		// Check for SQL error indicators
		body := strings.ToLower(resp.Body)
		sqlErrors := []string{
			"sql syntax", "mysql_fetch", "ora-", "postgresql",
			"sqlite_", "sql server", "syntax error", "mysql error",
		}

		for _, sqlError := range sqlErrors {
			if strings.Contains(body, sqlError) {
				vuln := WebVuln{
					Type:        "SQL_INJECTION",
					Severity:    "HIGH",
					URL:         testURL,
					Parameter:   "id",
					Payload:     payload,
					Evidence:    fmt.Sprintf("SQL error found: %s", sqlError),
					Description: "SQL injection vulnerability detected",
					Solution:    "Use parameterized queries and input validation",
				}
				vulns = append(vulns, vuln)
				break
			}
		}
	}

	return vulns
}

// testXSS tests for Cross-Site Scripting vulnerabilities
func (w *WebClientModule) testXSS(clientID, targetURL string) []WebVuln {
	var vulns []WebVuln

	xssPayloads := []string{
		"<script>alert('XSS')</script>",
		"<img src=x onerror=alert('XSS')>",
		"javascript:alert('XSS')",
		"<svg onload=alert('XSS')>",
	}

	for _, payload := range xssPayloads {
		// Test in URL parameters
		testURL := targetURL + "?search=" + url.QueryEscape(payload)
		
		req := &HTTPRequest{
			Method: "GET",
			URL:    testURL,
		}

		resp, err := w.Request(clientID, req)
		if err != nil {
			continue
		}

		// Check if payload is reflected without encoding
		if strings.Contains(resp.Body, payload) {
			vuln := WebVuln{
				Type:        "XSS",
				Severity:    "MEDIUM",
				URL:         testURL,
				Parameter:   "search",
				Payload:     payload,
				Evidence:    "Payload reflected without encoding",
				Description: "Cross-Site Scripting vulnerability detected",
				Solution:    "Implement proper input validation and output encoding",
			}
			vulns = append(vulns, vuln)
		}
	}

	return vulns
}

// testDirectoryTraversal tests for directory traversal vulnerabilities
func (w *WebClientModule) testDirectoryTraversal(clientID, targetURL string) []WebVuln {
	var vulns []WebVuln

	traversalPayloads := []string{
		"../../../etc/passwd",
		"..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
		"....//....//....//etc/passwd",
		"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
	}

	for _, payload := range traversalPayloads {
		testURL := targetURL + "?file=" + url.QueryEscape(payload)
		
		req := &HTTPRequest{
			Method: "GET",
			URL:    testURL,
		}

		resp, err := w.Request(clientID, req)
		if err != nil {
			continue
		}

		// Check for file content indicators
		body := strings.ToLower(resp.Body)
		if strings.Contains(body, "root:") || 
		   strings.Contains(body, "localhost") ||
		   strings.Contains(body, "[boot loader]") {
			vuln := WebVuln{
				Type:        "DIRECTORY_TRAVERSAL",
				Severity:    "HIGH",
				URL:         testURL,
				Parameter:   "file",
				Payload:     payload,
				Evidence:    "System file content detected",
				Description: "Directory traversal vulnerability detected",
				Solution:    "Implement proper file path validation and access controls",
			}
			vulns = append(vulns, vuln)
		}
	}

	return vulns
}

// testInformationDisclosure tests for information disclosure
func (w *WebClientModule) testInformationDisclosure(clientID, targetURL string) []WebVuln {
	var vulns []WebVuln

	// Test common sensitive files
	sensitiveFiles := []string{
		"/.env",
		"/config.php",
		"/web.config",
		"/.git/config",
		"/backup.sql",
		"/phpinfo.php",
	}

	for _, file := range sensitiveFiles {
		testURL := targetURL + file
		
		req := &HTTPRequest{
			Method: "GET",
			URL:    testURL,
		}

		resp, err := w.Request(clientID, req)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			vuln := WebVuln{
				Type:        "INFORMATION_DISCLOSURE",
				Severity:    "MEDIUM",
				URL:         testURL,
				Parameter:   "",
				Payload:     file,
				Evidence:    fmt.Sprintf("Sensitive file accessible (Status: %d)", resp.StatusCode),
				Description: "Sensitive file disclosure detected",
				Solution:    "Remove or restrict access to sensitive files",
			}
			vulns = append(vulns, vuln)
		}
	}

	return vulns
}

// CreateServer creates an HTTP server
func (w *WebClientModule) CreateServer(serverID string, port int, tlsConfig map[string]string) (*HTTPServer, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	server := &HTTPServer{
		ID:       serverID,
		Handlers: make(map[string]http.HandlerFunc),
		Port:     port,
		Running:  false,
	}

	// Configure TLS if provided
	if certFile, ok := tlsConfig["cert_file"]; ok {
		if keyFile, ok := tlsConfig["key_file"]; ok {
			server.TLS = true
			server.CertFile = certFile
			server.KeyFile = keyFile
		}
	}

	mux := http.NewServeMux()
	
	// Default handler
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Sentra HTTP Server - %s", time.Now().Format(time.RFC3339))
	})

	server.Server = &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	w.Servers[serverID] = server
	return server, nil
}

// AddHandler adds a custom handler to the server
func (w *WebClientModule) AddHandler(serverID, path string, handler func(method string, headers map[string]string, body string) (int, map[string]string, string)) error {
	w.mu.RLock()
	server, exists := w.Servers[serverID]
	w.mu.RUnlock()

	if !exists {
		return fmt.Errorf("server not found: %s", serverID)
	}

	// Convert Sentra handler to Go HTTP handler
	httpHandler := func(w http.ResponseWriter, r *http.Request) {
		// Read body
		body, _ := io.ReadAll(r.Body)
		
		// Convert headers
		headers := make(map[string]string)
		for k, v := range r.Header {
			if len(v) > 0 {
				headers[k] = v[0]
			}
		}

		// Call Sentra handler
		statusCode, respHeaders, respBody := handler(r.Method, headers, string(body))

		// Set response headers
		for k, v := range respHeaders {
			w.Header().Set(k, v)
		}

		// Write response
		w.WriteHeader(statusCode)
		w.Write([]byte(respBody))
	}

	// Get the mux from the server
	if mux, ok := server.Server.Handler.(*http.ServeMux); ok {
		mux.HandleFunc(path, httpHandler)
		server.Handlers[path] = httpHandler
	}

	return nil
}

// StartServer starts the HTTP server
func (w *WebClientModule) StartServer(serverID string) error {
	w.mu.RLock()
	server, exists := w.Servers[serverID]
	w.mu.RUnlock()

	if !exists {
		return fmt.Errorf("server not found: %s", serverID)
	}

	if server.Running {
		return fmt.Errorf("server already running")
	}

	go func() {
		var err error
		if server.TLS {
			err = server.Server.ListenAndServeTLS(server.CertFile, server.KeyFile)
		} else {
			err = server.Server.ListenAndServe()
		}

		if err != nil && err != http.ErrServerClosed {
			fmt.Printf("Server error: %v\n", err)
		}
	}()

	server.Running = true
	return nil
}

// StopServer stops the HTTP server
func (w *WebClientModule) StopServer(serverID string) error {
	w.mu.RLock()
	server, exists := w.Servers[serverID]
	w.mu.RUnlock()

	if !exists {
		return fmt.Errorf("server not found: %s", serverID)
	}

	if !server.Running {
		return fmt.Errorf("server not running")
	}

	err := server.Server.Close()
	if err == nil {
		server.Running = false
	}

	return err
}

// GetClientInfo returns information about an HTTP client
func (w *WebClientModule) GetClientInfo(clientID string) (map[string]interface{}, error) {
	w.mu.RLock()
	client, exists := w.Clients[clientID]
	w.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("client not found: %s", clientID)
	}

	info := map[string]interface{}{
		"id":              client.ID,
		"base_url":        client.BaseURL,
		"user_agent":      client.UserAgent,
		"timeout":         client.Timeout.Seconds(),
		"follow_redirect": client.FollowRedirect,
		"tls_verify":      client.TLSVerify,
		"headers":         client.Headers,
	}

	return info, nil
}

// ParseJSON parses JSON response body
func (w *WebClientModule) ParseJSON(jsonStr string) (map[string]interface{}, error) {
	var result map[string]interface{}
	err := json.Unmarshal([]byte(jsonStr), &result)
	return result, err
}

// FormatJSON formats data as JSON string
func (w *WebClientModule) FormatJSON(data map[string]interface{}) (string, error) {
	jsonBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", err
	}
	return string(jsonBytes), nil
}

// ExtractForms extracts HTML forms from response body
func (w *WebClientModule) ExtractForms(html string) []map[string]interface{} {
	// Simple form extraction (would need proper HTML parser for production)
	forms := make([]map[string]interface{}, 0)
	
	// This is a simplified implementation
	// Real implementation would use html.Parse or similar
	if strings.Contains(strings.ToLower(html), "<form") {
		form := map[string]interface{}{
			"method": "POST",
			"action": "/",
			"fields": []string{"username", "password"}, // Simplified
		}
		forms = append(forms, form)
	}

	return forms
}

// GetCookies returns cookies for a client
func (w *WebClientModule) GetCookies(clientID string, urlStr string) ([]*http.Cookie, error) {
	w.mu.RLock()
	client, exists := w.Clients[clientID]
	w.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("client not found: %s", clientID)
	}

	if parsedURL, err := url.Parse(urlStr); err == nil {
		return client.Cookies.Cookies(parsedURL), nil
	}

	return nil, fmt.Errorf("invalid URL: %s", urlStr)
}

// PostJSON sends a JSON POST request
func (w *WebClientModule) PostJSON(clientID string, url string, data interface{}) (*HTTPResponse, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	req := &HTTPRequest{
		Method: "POST",
		URL:    url,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: string(jsonData),
	}

	return w.Request(clientID, req)
}

// PostForm sends a form POST request
func (w *WebClientModule) PostForm(clientID string, targetURL string, formData map[string]string) (*HTTPResponse, error) {
	values := make(url.Values)
	for k, v := range formData {
		values.Set(k, v)
	}

	body := bytes.NewBufferString(values.Encode())
	
	req := &HTTPRequest{
		Method: "POST",
		URL:    targetURL,
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		},
		Body: body.String(),
	}

	return w.Request(clientID, req)
}