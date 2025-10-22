package network

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Port scanning and network discovery implementation

// PortScanResult represents port scan results
type PortScanResult struct {
	Target    string
	OpenPorts []int
	Services  map[int]string
	OS        string
	Timestamp time.Time
}

// ScanPorts scans a target for open ports in the specified range
func ScanPorts(target, portRange string) (*PortScanResult, error) {
	result := &PortScanResult{
		Target:    target,
		OpenPorts: make([]int, 0),
		Services:  make(map[int]string),
		Timestamp: time.Now(),
	}

	// Parse port range (e.g., "1-1000" or "80,443,8080")
	ports := parsePortRange(portRange)

	// Scan each port
	for _, port := range ports {
		if isPortOpen(target, port) {
			result.OpenPorts = append(result.OpenPorts, port)
			result.Services[port] = identifyService(port)
		}
	}

	return result, nil
}

// ScanNetwork scans a network CIDR for active hosts
func ScanNetwork(networkCIDR string) ([]*HostInfo, error) {
	hosts := make([]*HostInfo, 0)

	// Parse CIDR
	ip, ipNet, err := net.ParseCIDR(networkCIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %v", err)
	}

	// Iterate through IP range
	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); incIP(ip) {
		ipStr := ip.String()

		// Check if host is online (ping)
		if isHostOnline(ipStr) {
			host := &HostInfo{
				IP:       ipStr,
				Hostname: resolveHostname(ipStr),
				Online:   true,
			}
			hosts = append(hosts, host)
		}
	}

	return hosts, nil
}

// ScanServiceVersion attempts to identify service version on a port
func ScanServiceVersion(target string, port int) (string, error) {
	if !isPortOpen(target, port) {
		return "", fmt.Errorf("port %d is closed", port)
	}

	// In a real implementation, would send service-specific probes
	// and parse banners to identify version
	service := identifyService(port)
	version := "unknown"

	return fmt.Sprintf("%s (%s)", service, version), nil
}

// ScanOSFingerprint attempts to identify the operating system
func ScanOSFingerprint(target string) (string, error) {
	// In a real implementation, would use TCP/IP stack fingerprinting
	// techniques (TCP options, window size, TTL, etc.)
	// For now, placeholder
	return "Unknown OS", nil
}

// ScanVulnerabilities scans a target for known vulnerabilities
func ScanVulnerabilities(target string) ([]map[string]interface{}, error) {
	vulnerabilities := make([]map[string]interface{}, 0)

	// In a real implementation, would:
	// 1. Scan for open ports
	// 2. Identify services and versions
	// 3. Check against CVE database
	// 4. Test for common vulnerabilities (SQLi, XSS, etc.)

	// Placeholder
	return vulnerabilities, nil
}

// Helper functions

// parsePortRange parses a port range string into a slice of ports
func parsePortRange(portRange string) []int {
	ports := make([]int, 0)

	// Handle comma-separated ports
	if strings.Contains(portRange, ",") {
		parts := strings.Split(portRange, ",")
		for _, part := range parts {
			if port, err := strconv.Atoi(strings.TrimSpace(part)); err == nil {
				ports = append(ports, port)
			}
		}
		return ports
	}

	// Handle range (e.g., "1-1000")
	if strings.Contains(portRange, "-") {
		parts := strings.Split(portRange, "-")
		if len(parts) == 2 {
			start, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))

			if err1 == nil && err2 == nil {
				for i := start; i <= end; i++ {
					ports = append(ports, i)
				}
			}
		}
		return ports
	}

	// Single port
	if port, err := strconv.Atoi(portRange); err == nil {
		ports = append(ports, port)
	}

	return ports
}

// isPortOpen checks if a port is open on a target
func isPortOpen(target string, port int) bool {
	address := fmt.Sprintf("%s:%d", target, port)
	conn, err := net.DialTimeout("tcp", address, 1*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// isHostOnline checks if a host is online
func isHostOnline(ip string) bool {
	// Try to connect to common ports
	commonPorts := []int{80, 443, 22, 21, 25}

	for _, port := range commonPorts {
		if isPortOpen(ip, port) {
			return true
		}
	}

	return false
}

// resolveHostname resolves IP to hostname
func resolveHostname(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return names[0]
}

// identifyService identifies service name from port number
func identifyService(port int) string {
	commonServices := map[int]string{
		20:   "FTP-DATA",
		21:   "FTP",
		22:   "SSH",
		23:   "Telnet",
		25:   "SMTP",
		53:   "DNS",
		80:   "HTTP",
		110:  "POP3",
		143:  "IMAP",
		443:  "HTTPS",
		445:  "SMB",
		3306: "MySQL",
		3389: "RDP",
		5432: "PostgreSQL",
		6379: "Redis",
		8080: "HTTP-Alt",
		8443: "HTTPS-Alt",
		9200: "Elasticsearch",
		27017: "MongoDB",
	}

	if service, exists := commonServices[port]; exists {
		return service
	}

	return fmt.Sprintf("Unknown (%d)", port)
}

// incIP increments an IP address
func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// PortScanResultToMap converts a PortScanResult to a map for VM
func PortScanResultToMap(result *PortScanResult) map[string]interface{} {
	services := make(map[string]interface{})
	for port, service := range result.Services {
		services[strconv.Itoa(port)] = service
	}

	openPorts := make([]interface{}, 0)
	for _, port := range result.OpenPorts {
		openPorts = append(openPorts, port)
	}

	return map[string]interface{}{
		"target":     result.Target,
		"open_ports": openPorts,
		"services":   services,
		"os":         result.OS,
		"timestamp":  result.Timestamp.Unix(),
	}
}

// HostInfoToMap converts a HostInfo to a map for VM
func HostInfoToMap(host *HostInfo) map[string]interface{} {
	return map[string]interface{}{
		"ip":       host.IP,
		"hostname": host.Hostname,
		"mac":      host.MAC,
		"vendor":   host.Vendor,
		"online":   host.Online,
	}
}
