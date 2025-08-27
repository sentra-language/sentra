// Package network - HTTP server implementation
package network

import (
	"fmt"
	"net/http"
	"sync"
	"time"
	"encoding/json"
	"io/ioutil"
)

// HTTPServer represents an HTTP server
type HTTPServer struct {
	ID       string
	Address  string
	Port     int
	Server   *http.Server
	Mux      *http.ServeMux
	Routes   map[string]HTTPHandler
	Running  bool
	mu       sync.RWMutex
}

// HTTPHandler represents a route handler
type HTTPHandler struct {
	Method   string
	Path     string
	Handler  func(*HTTPServerRequest) *HTTPServerResponse
}

// HTTPServerRequest wraps incoming request
type HTTPServerRequest struct {
	Method  string
	Path    string
	Headers map[string]string
	Query   map[string]string
	Body    string
	Params  map[string]string
}

// HTTPServerResponse for handler responses
type HTTPServerResponse struct {
	StatusCode int
	Headers    map[string]string
	Body       string
}

// CreateHTTPServer creates a new HTTP server
func (n *NetworkModule) CreateHTTPServer(address string, port int) (*HTTPServer, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	
	serverID := fmt.Sprintf("http_server_%d_%d", port, time.Now().Unix())
	
	server := &HTTPServer{
		ID:      serverID,
		Address: address,
		Port:    port,
		Mux:     http.NewServeMux(),
		Routes:  make(map[string]HTTPHandler),
		Running: false,
	}
	
	// Store server reference
	if n.HTTPServers == nil {
		n.HTTPServers = make(map[string]*HTTPServer)
	}
	n.HTTPServers[serverID] = server
	
	return server, nil
}

// AddRoute adds a route to the HTTP server
func (n *NetworkModule) AddRoute(serverID, method, path string, handler func(*HTTPServerRequest) *HTTPServerResponse) error {
	n.mu.RLock()
	server, exists := n.HTTPServers[serverID]
	n.mu.RUnlock()
	
	if !exists {
		return fmt.Errorf("server not found: %s", serverID)
	}
	
	server.mu.Lock()
	defer server.mu.Unlock()
	
	routeKey := fmt.Sprintf("%s:%s", method, path)
	server.Routes[routeKey] = HTTPHandler{
		Method:  method,
		Path:    path,
		Handler: handler,
	}
	
	// Register with mux
	server.Mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		// Check method
		if r.Method != method && method != "ANY" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		
		// Parse request
		req := &HTTPServerRequest{
			Method:  r.Method,
			Path:    r.URL.Path,
			Headers: make(map[string]string),
			Query:   make(map[string]string),
			Params:  make(map[string]string),
		}
		
		// Copy headers
		for key, values := range r.Header {
			if len(values) > 0 {
				req.Headers[key] = values[0]
			}
		}
		
		// Parse query parameters
		for key, values := range r.URL.Query() {
			if len(values) > 0 {
				req.Query[key] = values[0]
			}
		}
		
		// Read body
		if r.Body != nil {
			body, _ := ioutil.ReadAll(r.Body)
			req.Body = string(body)
		}
		
		// Call handler
		resp := handler(req)
		if resp == nil {
			resp = &HTTPServerResponse{
				StatusCode: 200,
				Body:       "OK",
				Headers:    make(map[string]string),
			}
		}
		
		// Set headers
		for key, value := range resp.Headers {
			w.Header().Set(key, value)
		}
		
		// Write response
		w.WriteHeader(resp.StatusCode)
		w.Write([]byte(resp.Body))
	})
	
	return nil
}

// StartHTTPServer starts the HTTP server
func (n *NetworkModule) StartHTTPServer(serverID string) error {
	n.mu.RLock()
	server, exists := n.HTTPServers[serverID]
	n.mu.RUnlock()
	
	if !exists {
		return fmt.Errorf("server not found: %s", serverID)
	}
	
	server.mu.Lock()
	if server.Running {
		server.mu.Unlock()
		return fmt.Errorf("server already running")
	}
	
	server.Server = &http.Server{
		Addr:    fmt.Sprintf("%s:%d", server.Address, server.Port),
		Handler: server.Mux,
	}
	server.Running = true
	server.mu.Unlock()
	
	// Start server in goroutine
	go func() {
		err := server.Server.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			server.mu.Lock()
			server.Running = false
			server.mu.Unlock()
		}
	}()
	
	// Wait a moment for server to start
	time.Sleep(100 * time.Millisecond)
	
	return nil
}

// StopHTTPServer stops the HTTP server
func (n *NetworkModule) StopHTTPServer(serverID string) error {
	n.mu.RLock()
	server, exists := n.HTTPServers[serverID]
	n.mu.RUnlock()
	
	if !exists {
		return fmt.Errorf("server not found: %s", serverID)
	}
	
	server.mu.Lock()
	defer server.mu.Unlock()
	
	if !server.Running {
		return fmt.Errorf("server not running")
	}
	
	server.Running = false
	if server.Server != nil {
		return server.Server.Close()
	}
	
	return nil
}

// ServeStatic serves static files from a directory
func (n *NetworkModule) ServeStatic(serverID, urlPath, directory string) error {
	n.mu.RLock()
	server, exists := n.HTTPServers[serverID]
	n.mu.RUnlock()
	
	if !exists {
		return fmt.Errorf("server not found: %s", serverID)
	}
	
	server.mu.Lock()
	defer server.mu.Unlock()
	
	// Create file server
	fs := http.FileServer(http.Dir(directory))
	server.Mux.Handle(urlPath, http.StripPrefix(urlPath, fs))
	
	return nil
}

// JSONResponse creates a JSON response
func (n *NetworkModule) JSONResponse(statusCode int, data interface{}) (*HTTPServerResponse, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	
	return &HTTPServerResponse{
		StatusCode: statusCode,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: string(jsonData),
	}, nil
}