package network

import (
	"fmt"
	"sync"
	"time"
)

// Common types for network operations

// FirewallRule represents a firewall rule
type FirewallRule struct {
	ID       string
	Chain    string // INPUT, OUTPUT, FORWARD
	Protocol string // tcp, udp, icmp, all
	SrcIP    string
	DstIP    string
	SrcPort  string
	DstPort  string
	Action   string // ACCEPT, DROP, REJECT
	Created  time.Time
}

// FirewallStats contains firewall statistics
type FirewallStats struct {
	RulesCount    int
	PacketsBlocked uint64
	PacketsAllowed uint64
	LastUpdate    time.Time
}

// ProxyServer represents an HTTP/HTTPS proxy server
type ProxyServer struct {
	ID       string
	Port     int
	Running  bool
	Upstream string
	Filters  []ProxyFilter
	Stats    *ProxyStats
	mu       sync.RWMutex
}

// ProxyFilter is a function that filters proxy requests
type ProxyFilter func(request map[string]interface{}) (block bool, reason string)

// ProxyStats contains proxy statistics
type ProxyStats struct {
	RequestsTotal   uint64
	RequestsBlocked uint64
	BytesIn         uint64
	BytesOut        uint64
	LastRequest     time.Time
}

// ReverseProxy represents a reverse proxy server
type ReverseProxy struct {
	ID             string
	Port           int
	Backends       []*Backend
	LoadBalancing  string // round_robin, least_connections, ip_hash
	Running        bool
	Stats          *ReverseProxyStats
	currentBackend int
	mu             sync.RWMutex
}

// Backend represents a backend server for reverse proxy
type Backend struct {
	ID      string
	URL     string
	Weight  int
	Healthy bool
	Stats   *BackendStats
}

// BackendStats contains backend statistics
type BackendStats struct {
	Requests   uint64
	Errors     uint64
	LastAccess time.Time
}

// ReverseProxyStats contains reverse proxy statistics
type ReverseProxyStats struct {
	TotalRequests  uint64
	TotalErrors    uint64
	BackendsActive int
}

// IDS represents an Intrusion Detection System
type IDS struct {
	ID        string
	Interface string
	Rules     []*IDSRule
	Alerts    []*Alert
	Running   bool
	Stats     *IDSStats
	mu        sync.RWMutex
}

// IDSRule represents an IDS detection rule
type IDSRule struct {
	ID       string
	Name     string
	Pattern  string
	Severity string // low, medium, high, critical
	Action   string // alert, block, log
	Enabled  bool
}

// Alert represents a security alert
type Alert struct {
	ID        string
	Timestamp time.Time
	Severity  string
	Message   string
	SrcIP     string
	DstIP     string
	Protocol  string
	Details   map[string]interface{}
}

// IDSStats contains IDS statistics
type IDSStats struct {
	PacketsAnalyzed uint64
	AlertsGenerated uint64
	ThreatsBlocked  uint64
	LastAlert       time.Time
}

// NetworkMonitor represents a network traffic monitor
type NetworkMonitor struct {
	ID        string
	Interface string
	Stats     *NetworkStats
	Flows     []*Flow
	Running   bool
	mu        sync.RWMutex
}

// NetworkStats contains network statistics
type NetworkStats struct {
	RxBytes   uint64
	TxBytes   uint64
	RxPackets uint64
	TxPackets uint64
	RxMbps    float64
	TxMbps    float64
	LastUpdate time.Time
}

// Flow represents a network flow
type Flow struct {
	SrcIP    string
	DstIP    string
	SrcPort  int
	DstPort  int
	Protocol string
	Bytes    uint64
	Packets  uint64
	Started  time.Time
}

// PacketCapture represents a packet capture session
type PacketCapture struct {
	ID        string
	Interface string
	Filter    string
	Packets   []*Packet
	Running   bool
	mu        sync.RWMutex
}

// Packet represents a captured network packet
type Packet struct {
	Timestamp time.Time
	Length    int
	SrcIP     string
	DstIP     string
	SrcPort   int
	DstPort   int
	Protocol  string
	Data      []byte
}

// HostInfo represents discovered host information
type HostInfo struct {
	IP       string
	Hostname string
	MAC      string
	Vendor   string
	Online   bool
}

// Global registries for managing instances
var (
	firewallRules   = make(map[string]*FirewallRule)
	proxyServers    = make(map[string]*ProxyServer)
	reverseProxies  = make(map[string]*ReverseProxy)
	idsInstances    = make(map[string]*IDS)
	monitors        = make(map[string]*NetworkMonitor)
	captures        = make(map[string]*PacketCapture)
	registryMutex   sync.RWMutex
)

// Helper functions for ID generation
var idCounter uint64

func generateID(prefix string) string {
	idCounter++
	return fmt.Sprintf("%s-%d-%d", prefix, time.Now().Unix(), idCounter)
}
