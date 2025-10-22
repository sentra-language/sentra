package network

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

// HTTP/HTTPS Proxy implementation

// StartProxy starts an HTTP/HTTPS proxy server
func StartProxy(port int, options map[string]interface{}) (*ProxyServer, error) {
	proxy := &ProxyServer{
		ID:      generateID("proxy"),
		Port:    port,
		Running: true,
		Stats: &ProxyStats{
			LastRequest: time.Now(),
		},
		Filters: make([]ProxyFilter, 0),
	}

	// Store the proxy
	registryMutex.Lock()
	proxyServers[proxy.ID] = proxy
	registryMutex.Unlock()

	// Start HTTP server in background
	go proxy.serve()

	return proxy, nil
}

// serve runs the HTTP proxy server
func (p *ProxyServer) serve() {
	handler := http.HandlerFunc(p.handleRequest)
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", p.Port),
		Handler: handler,
	}

	server.ListenAndServe()
}

// handleRequest handles an incoming proxy request
func (p *ProxyServer) handleRequest(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	p.Stats.RequestsTotal++
	p.Stats.LastRequest = time.Now()
	p.mu.Unlock()

	// Apply filters
	for _, filter := range p.Filters {
		reqMap := requestToMap(r)
		if block, reason := filter(reqMap); block {
			p.mu.Lock()
			p.Stats.RequestsBlocked++
			p.mu.Unlock()

			http.Error(w, fmt.Sprintf("Blocked: %s", reason), http.StatusForbidden)
			return
		}
	}

	// Forward request to upstream or target
	target := p.Upstream
	if target == "" {
		target = r.URL.String()
	}

	// Create forwarded request
	req, err := http.NewRequest(r.Method, target, r.Body)
	if err != nil {
		http.Error(w, "Proxy error", http.StatusBadGateway)
		return
	}

	// Copy headers
	for key, values := range r.Header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	// Send request
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Copy response
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// StopProxy stops a running proxy server
func StopProxy(proxyID string) error {
	registryMutex.Lock()
	defer registryMutex.Unlock()

	proxy, exists := proxyServers[proxyID]
	if !exists {
		return fmt.Errorf("proxy '%s' not found", proxyID)
	}

	proxy.mu.Lock()
	proxy.Running = false
	proxy.mu.Unlock()

	delete(proxyServers, proxyID)
	return nil
}

// SetProxyUpstream sets the upstream URL for a proxy
func SetProxyUpstream(proxyID, upstreamURL string) error {
	registryMutex.RLock()
	proxy, exists := proxyServers[proxyID]
	registryMutex.RUnlock()

	if !exists {
		return fmt.Errorf("proxy '%s' not found", proxyID)
	}

	proxy.mu.Lock()
	proxy.Upstream = upstreamURL
	proxy.mu.Unlock()

	return nil
}

// AddProxyFilter adds a filter function to a proxy
func AddProxyFilter(proxyID string, filter ProxyFilter) error {
	registryMutex.RLock()
	proxy, exists := proxyServers[proxyID]
	registryMutex.RUnlock()

	if !exists {
		return fmt.Errorf("proxy '%s' not found", proxyID)
	}

	proxy.mu.Lock()
	proxy.Filters = append(proxy.Filters, filter)
	proxy.mu.Unlock()

	return nil
}

// GetProxyStats returns proxy statistics
func GetProxyStats(proxyID string) (*ProxyStats, error) {
	registryMutex.RLock()
	proxy, exists := proxyServers[proxyID]
	registryMutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("proxy '%s' not found", proxyID)
	}

	proxy.mu.RLock()
	defer proxy.mu.RUnlock()

	return proxy.Stats, nil
}

// GetProxyLogs returns proxy request logs (placeholder)
func GetProxyLogs(proxyID string, limit int) ([]map[string]interface{}, error) {
	registryMutex.RLock()
	_, exists := proxyServers[proxyID]
	registryMutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("proxy '%s' not found", proxyID)
	}

	// In a real implementation, this would return actual request logs
	return []map[string]interface{}{}, nil
}

// Helper to convert HTTP request to map
func requestToMap(r *http.Request) map[string]interface{} {
	headers := make(map[string]interface{})
	for key, values := range r.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}

	return map[string]interface{}{
		"method":  r.Method,
		"url":     r.URL.String(),
		"path":    r.URL.Path,
		"host":    r.Host,
		"headers": headers,
	}
}

// ProxyToMap converts a ProxyServer to a map for VM
func ProxyToMap(proxy *ProxyServer) map[string]interface{} {
	proxy.mu.RLock()
	defer proxy.mu.RUnlock()

	return map[string]interface{}{
		"id":      proxy.ID,
		"port":    proxy.Port,
		"running": proxy.Running,
		"upstream": proxy.Upstream,
	}
}

// ProxyStatsToMap converts ProxyStats to a map for VM
func ProxyStatsToMap(stats *ProxyStats) map[string]interface{} {
	return map[string]interface{}{
		"requests_total":   stats.RequestsTotal,
		"requests_blocked": stats.RequestsBlocked,
		"bytes_in":         stats.BytesIn,
		"bytes_out":        stats.BytesOut,
		"last_request":     stats.LastRequest.Unix(),
	}
}
