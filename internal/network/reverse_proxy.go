package network

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

// Reverse Proxy implementation

// CreateReverseProxy creates a reverse proxy with load balancing
func CreateReverseProxy(port int, backends []string) (*ReverseProxy, error) {
	rp := &ReverseProxy{
		ID:            generateID("rproxy"),
		Port:          port,
		Backends:      make([]*Backend, 0),
		LoadBalancing: "round_robin",
		Running:       true,
		Stats: &ReverseProxyStats{
			BackendsActive: 0,
		},
	}

	// Add backends
	for _, backendURL := range backends {
		backend := &Backend{
			ID:      generateID("backend"),
			URL:     backendURL,
			Weight:  1,
			Healthy: true,
			Stats: &BackendStats{
				LastAccess: time.Now(),
			},
		}
		rp.Backends = append(rp.Backends, backend)
	}

	rp.Stats.BackendsActive = len(rp.Backends)

	// Store the reverse proxy
	registryMutex.Lock()
	reverseProxies[rp.ID] = rp
	registryMutex.Unlock()

	// Start server in background
	go rp.serve()

	return rp, nil
}

// serve runs the reverse proxy HTTP server
func (rp *ReverseProxy) serve() {
	handler := http.HandlerFunc(rp.handleRequest)
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", rp.Port),
		Handler: handler,
	}

	server.ListenAndServe()
}

// handleRequest handles an incoming request and forwards to backend
func (rp *ReverseProxy) handleRequest(w http.ResponseWriter, r *http.Request) {
	rp.mu.Lock()
	rp.Stats.TotalRequests++
	rp.mu.Unlock()

	// Select backend based on load balancing algorithm
	backend := rp.selectBackend()
	if backend == nil {
		rp.mu.Lock()
		rp.Stats.TotalErrors++
		rp.mu.Unlock()

		http.Error(w, "No available backends", http.StatusServiceUnavailable)
		return
	}

	// Parse backend URL
	target, err := url.Parse(backend.URL)
	if err != nil {
		http.Error(w, "Backend configuration error", http.StatusInternalServerError)
		return
	}

	// Create reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(target)

	// Update backend stats
	backend.Stats.Requests++
	backend.Stats.LastAccess = time.Now()

	// Forward the request
	proxy.ServeHTTP(w, r)
}

// selectBackend selects a backend based on the load balancing algorithm
func (rp *ReverseProxy) selectBackend() *Backend {
	rp.mu.Lock()
	defer rp.mu.Unlock()

	if len(rp.Backends) == 0 {
		return nil
	}

	switch rp.LoadBalancing {
	case "round_robin":
		// Simple round robin
		backend := rp.Backends[rp.currentBackend]
		rp.currentBackend = (rp.currentBackend + 1) % len(rp.Backends)
		return backend

	case "least_connections":
		// Select backend with least requests
		var selected *Backend
		minRequests := uint64(^uint64(0)) // Max uint64

		for _, backend := range rp.Backends {
			if backend.Healthy && backend.Stats.Requests < minRequests {
				minRequests = backend.Stats.Requests
				selected = backend
			}
		}
		return selected

	default:
		// Default to round robin
		return rp.Backends[0]
	}
}

// AddBackend adds a new backend to the reverse proxy
func AddBackend(proxyID, backendURL string, weight int) (*Backend, error) {
	registryMutex.RLock()
	rp, exists := reverseProxies[proxyID]
	registryMutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("reverse proxy '%s' not found", proxyID)
	}

	backend := &Backend{
		ID:      generateID("backend"),
		URL:     backendURL,
		Weight:  weight,
		Healthy: true,
		Stats: &BackendStats{
			LastAccess: time.Now(),
		},
	}

	rp.mu.Lock()
	rp.Backends = append(rp.Backends, backend)
	rp.Stats.BackendsActive = len(rp.Backends)
	rp.mu.Unlock()

	return backend, nil
}

// RemoveBackend removes a backend from the reverse proxy
func RemoveBackend(proxyID, backendID string) error {
	registryMutex.RLock()
	rp, exists := reverseProxies[proxyID]
	registryMutex.RUnlock()

	if !exists {
		return fmt.Errorf("reverse proxy '%s' not found", proxyID)
	}

	rp.mu.Lock()
	defer rp.mu.Unlock()

	for i, backend := range rp.Backends {
		if backend.ID == backendID {
			rp.Backends = append(rp.Backends[:i], rp.Backends[i+1:]...)
			rp.Stats.BackendsActive = len(rp.Backends)
			return nil
		}
	}

	return fmt.Errorf("backend '%s' not found", backendID)
}

// SetLoadBalancing sets the load balancing algorithm
func SetLoadBalancing(proxyID, algorithm string) error {
	registryMutex.RLock()
	rp, exists := reverseProxies[proxyID]
	registryMutex.RUnlock()

	if !exists {
		return fmt.Errorf("reverse proxy '%s' not found", proxyID)
	}

	rp.mu.Lock()
	rp.LoadBalancing = algorithm
	rp.mu.Unlock()

	return nil
}

// GetReverseProxyHealth returns health status of reverse proxy
func GetReverseProxyHealth(proxyID string) (map[string]interface{}, error) {
	registryMutex.RLock()
	rp, exists := reverseProxies[proxyID]
	registryMutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("reverse proxy '%s' not found", proxyID)
	}

	rp.mu.RLock()
	defer rp.mu.RUnlock()

	backends := make([]map[string]interface{}, 0)
	healthyCount := 0

	for _, backend := range rp.Backends {
		if backend.Healthy {
			healthyCount++
		}

		backends = append(backends, map[string]interface{}{
			"id":       backend.ID,
			"url":      backend.URL,
			"healthy":  backend.Healthy,
			"requests": backend.Stats.Requests,
		})
	}

	return map[string]interface{}{
		"id":              rp.ID,
		"running":         rp.Running,
		"backends_total":  len(rp.Backends),
		"backends_healthy": healthyCount,
		"backends":        backends,
	}, nil
}

// ReverseProxyToMap converts a ReverseProxy to a map for VM
func ReverseProxyToMap(rp *ReverseProxy) map[string]interface{} {
	rp.mu.RLock()
	defer rp.mu.RUnlock()

	backends := make([]map[string]interface{}, 0)
	for _, backend := range rp.Backends {
		backends = append(backends, BackendToMap(backend))
	}

	return map[string]interface{}{
		"id":              rp.ID,
		"port":            rp.Port,
		"running":         rp.Running,
		"load_balancing":  rp.LoadBalancing,
		"backends":        backends,
		"backends_active": rp.Stats.BackendsActive,
	}
}

// BackendToMap converts a Backend to a map for VM
func BackendToMap(backend *Backend) map[string]interface{} {
	return map[string]interface{}{
		"id":       backend.ID,
		"url":      backend.URL,
		"weight":   backend.Weight,
		"healthy":  backend.Healthy,
		"requests": backend.Stats.Requests,
	}
}
