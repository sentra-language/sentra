package network

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// FastNetworkModule provides zero-latency network operations for security scanning
type FastNetworkModule struct {
	*NetworkModule
	
	// Connection pooling
	connPool    map[string]net.Conn
	connPoolMux sync.RWMutex
	
	// DNS caching
	dnsCache    map[string][]string
	dnsCacheMux sync.RWMutex
	
	// HTTP client with connection pooling
	httpClient *http.Client
	
	// Port scan results cache
	portCache    map[string]map[int]bool
	portCacheMux sync.RWMutex
	
	// Concurrent scanners
	scanWorkers int
}

// NewFastNetworkModule creates an optimized network module
func NewFastNetworkModule() *FastNetworkModule {
	return &FastNetworkModule{
		NetworkModule: NewNetworkModule(),
		connPool:      make(map[string]net.Conn),
		dnsCache:      make(map[string][]string),
		portCache:     make(map[string]map[int]bool),
		scanWorkers:   100, // High concurrency for fast scanning
		httpClient: &http.Client{
			Timeout: 2 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
				DisableKeepAlives:   false,
				DisableCompression:  true, // Faster for security scanning
				DialContext: (&net.Dialer{
					Timeout:   1 * time.Second,
					KeepAlive: 30 * time.Second,
					DualStack: true,
				}).DialContext,
			},
		},
	}
}

// FastPortScan performs ultra-fast port scanning using goroutines
func (f *FastNetworkModule) FastPortScan(host string, ports []int) map[int]bool {
	// Check cache first
	cacheKey := fmt.Sprintf("%s:%v", host, ports)
	f.portCacheMux.RLock()
	if cached, exists := f.portCache[cacheKey]; exists {
		f.portCacheMux.RUnlock()
		return cached
	}
	f.portCacheMux.RUnlock()
	
	results := make(map[int]bool)
	resultsMux := sync.Mutex{}
	
	// Use worker pool for concurrent scanning
	sem := make(chan struct{}, f.scanWorkers)
	var wg sync.WaitGroup
	
	for _, port := range ports {
		wg.Add(1)
		sem <- struct{}{} // Acquire semaphore
		
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }() // Release semaphore
			
			// Ultra-fast connection with 100ms timeout
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, p), 100*time.Millisecond)
			
			resultsMux.Lock()
			results[p] = err == nil
			resultsMux.Unlock()
			
			if conn != nil {
				conn.Close()
			}
		}(port)
	}
	
	wg.Wait()
	
	// Cache the results
	f.portCacheMux.Lock()
	f.portCache[cacheKey] = results
	f.portCacheMux.Unlock()
	
	return results
}

// FastDNSLookup performs cached DNS lookups
func (f *FastNetworkModule) FastDNSLookup(hostname string) ([]string, error) {
	// Check cache first
	f.dnsCacheMux.RLock()
	if cached, exists := f.dnsCache[hostname]; exists {
		f.dnsCacheMux.RUnlock()
		return cached, nil
	}
	f.dnsCacheMux.RUnlock()
	
	// Use custom resolver with timeout
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: 500 * time.Millisecond,
			}
			return d.DialContext(ctx, network, address)
		},
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	
	addrs, err := r.LookupHost(ctx, hostname)
	if err != nil {
		return nil, err
	}
	
	// Cache the results
	f.dnsCacheMux.Lock()
	f.dnsCache[hostname] = addrs
	f.dnsCacheMux.Unlock()
	
	return addrs, nil
}

// FastHTTPGet performs a fast HTTP GET with connection pooling
func (f *FastNetworkModule) FastHTTPGet(url string) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, nil, err
	}
	
	// Add security scanner headers
	req.Header.Set("User-Agent", "Sentra-Security-Scanner/1.0")
	
	resp, err := f.httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	
	// Read only first 1MB for security scanning
	body := make([]byte, 1024*1024)
	n, _ := resp.Body.Read(body)
	
	return resp.StatusCode, body[:n], nil
}

// BatchPortScan scans multiple hosts in parallel
func (f *FastNetworkModule) BatchPortScan(hosts []string, ports []int) map[string]map[int]bool {
	results := make(map[string]map[int]bool)
	resultsMux := sync.Mutex{}
	
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10) // Limit concurrent host scans
	
	for _, host := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		
		go func(h string) {
			defer wg.Done()
			defer func() { <-sem }()
			
			scanResult := f.FastPortScan(h, ports)
			
			resultsMux.Lock()
			results[h] = scanResult
			resultsMux.Unlock()
		}(host)
	}
	
	wg.Wait()
	return results
}

// ServiceDetection performs fast service detection on open ports
func (f *FastNetworkModule) ServiceDetection(host string, port int) string {
	// Common service signatures
	services := map[int]string{
		21:    "FTP",
		22:    "SSH",
		23:    "Telnet",
		25:    "SMTP",
		53:    "DNS",
		80:    "HTTP",
		110:   "POP3",
		143:   "IMAP",
		443:   "HTTPS",
		445:   "SMB",
		3306:  "MySQL",
		3389:  "RDP",
		5432:  "PostgreSQL",
		6379:  "Redis",
		8080:  "HTTP-Alt",
		27017: "MongoDB",
	}
	
	// Check known ports first
	if service, exists := services[port]; exists {
		// Verify the service is actually running
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return service
		}
	}
	
	return "Unknown"
}

// NetworkSweep performs a fast network sweep
func (f *FastNetworkModule) NetworkSweep(subnet string) []string {
	var activeHosts []string
	var mu sync.Mutex
	
	// Parse subnet
	_, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		// Try as single IP
		activeHosts = append(activeHosts, subnet)
		return activeHosts
	}
	
	// Generate all IPs in subnet
	var ips []string
	for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	
	// Ping sweep with goroutines
	var wg sync.WaitGroup
	sem := make(chan struct{}, 100)
	
	for _, ip := range ips {
		wg.Add(1)
		sem <- struct{}{}
		
		go func(ipAddr string) {
			defer wg.Done()
			defer func() { <-sem }()
			
			// Fast ping using TCP connect to common port
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:445", ipAddr), 50*time.Millisecond)
			if err == nil {
				conn.Close()
				mu.Lock()
				activeHosts = append(activeHosts, ipAddr)
				mu.Unlock()
				return
			}
			
			// Try another common port
			conn, err = net.DialTimeout("tcp", fmt.Sprintf("%s:135", ipAddr), 50*time.Millisecond)
			if err == nil {
				conn.Close()
				mu.Lock()
				activeHosts = append(activeHosts, ipAddr)
				mu.Unlock()
			}
		}(ip)
	}
	
	wg.Wait()
	return activeHosts
}

// ClearCache clears all caches for fresh scans
func (f *FastNetworkModule) ClearCache() {
	f.connPoolMux.Lock()
	for _, conn := range f.connPool {
		conn.Close()
	}
	f.connPool = make(map[string]net.Conn)
	f.connPoolMux.Unlock()
	
	f.dnsCacheMux.Lock()
	f.dnsCache = make(map[string][]string)
	f.dnsCacheMux.Unlock()
	
	f.portCacheMux.Lock()
	f.portCache = make(map[string]map[int]bool)
	f.portCacheMux.Unlock()
}

// Helper function to increment IP
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}