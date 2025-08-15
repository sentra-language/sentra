// Package security provides native security functions for Sentra
package security

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"regexp"
	"strings"
	"time"
)

// SecurityModule contains all security-related functions
type SecurityModule struct {
	// Threat intelligence database
	ThreatDB map[string]ThreatInfo
	// Firewall rules
	FirewallRules []FirewallRule
	// Active connections
	Connections map[string]*Connection
}

type ThreatInfo struct {
	Hash        string
	Severity    string
	Description string
	LastSeen    time.Time
}

type FirewallRule struct {
	Action   string // ALLOW, BLOCK, LOG
	Protocol string // TCP, UDP, ICMP
	Port     int
	Source   string // IP or CIDR
	Enabled  bool
}

type Connection struct {
	SourceIP   string
	DestIP     string
	Port       int
	Protocol   string
	Timestamp  time.Time
	PacketCount int
}

// NewSecurityModule creates a new security module instance
func NewSecurityModule() *SecurityModule {
	return &SecurityModule{
		ThreatDB:      make(map[string]ThreatInfo),
		FirewallRules: []FirewallRule{},
		Connections:   make(map[string]*Connection),
	}
}

// Hash functions
func (s *SecurityModule) SHA256(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func (s *SecurityModule) SHA1(data string) string {
	hash := sha1.Sum([]byte(data))
	return hex.EncodeToString(hash[:])
}

func (s *SecurityModule) MD5(data string) string {
	hash := md5.Sum([]byte(data))
	return hex.EncodeToString(hash[:])
}

// Encoding functions
func (s *SecurityModule) Base64Encode(data string) string {
	return base64.StdEncoding.EncodeToString([]byte(data))
}

func (s *SecurityModule) Base64Decode(encoded string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

func (s *SecurityModule) HexEncode(data string) string {
	return hex.EncodeToString([]byte(data))
}

func (s *SecurityModule) HexDecode(encoded string) (string, error) {
	decoded, err := hex.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

// Pattern matching
func (s *SecurityModule) Match(text, pattern string) bool {
	matched, _ := regexp.MatchString(pattern, text)
	return matched
}

func (s *SecurityModule) FindAll(text, pattern string) []string {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return []string{}
	}
	return re.FindAllString(text, -1)
}

// Network functions
func (s *SecurityModule) IsValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func (s *SecurityModule) IsPrivateIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
	}
	
	for _, cidr := range privateRanges {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(parsedIP) {
			return true
		}
	}
	return false
}

func (s *SecurityModule) PortScan(host string, startPort, endPort int) []int {
	openPorts := []int{}
	
	for port := startPort; port <= endPort && port <= startPort+100; port++ { // Limit for demo
		address := fmt.Sprintf("%s:%d", host, port)
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			openPorts = append(openPorts, port)
			conn.Close()
		}
	}
	
	return openPorts
}

// Firewall functions
func (s *SecurityModule) AddFirewallRule(action, protocol string, port int, source string) {
	rule := FirewallRule{
		Action:   action,
		Protocol: protocol,
		Port:     port,
		Source:   source,
		Enabled:  true,
	}
	s.FirewallRules = append(s.FirewallRules, rule)
}

func (s *SecurityModule) CheckFirewall(sourceIP string, port int) string {
	for _, rule := range s.FirewallRules {
		if !rule.Enabled {
			continue
		}
		
		if rule.Port == port || rule.Port == 0 { // 0 means all ports
			if rule.Source == "0.0.0.0/0" || rule.Source == sourceIP {
				return rule.Action
			}
		}
	}
	return "ALLOW" // Default allow
}

// Threat detection
func (s *SecurityModule) CheckThreat(data string) (bool, string) {
	hash := s.SHA256(data)
	if threat, exists := s.ThreatDB[hash]; exists {
		return true, threat.Severity
	}
	
	// Check for common attack patterns
	patterns := map[string]string{
		"SQL Injection": `(?i)(union\s+select|or\s+1\s*=\s*1|drop\s+table)`,
		"XSS": `(?i)(<script|javascript:|onerror=)`,
		"Path Traversal": `\.\.\/|\.\.\\`,
		"Command Injection": `(?i)(;|\||&&|\$\()`,
	}
	
	for attackType, pattern := range patterns {
		if matched, _ := regexp.MatchString(pattern, data); matched {
			return true, attackType
		}
	}
	
	return false, ""
}

// Password security
func (s *SecurityModule) CheckPasswordStrength(password string) int {
	score := 0
	
	if len(password) >= 8 {
		score++
	}
	if len(password) >= 12 {
		score++
	}
	if matched, _ := regexp.MatchString(`[A-Z]`, password); matched {
		score++
	}
	if matched, _ := regexp.MatchString(`[a-z]`, password); matched {
		score++
	}
	if matched, _ := regexp.MatchString(`[0-9]`, password); matched {
		score++
	}
	if matched, _ := regexp.MatchString(`[!@#$%^&*(),.?":|<>{}]`, password); matched {
		score++
	}
	
	return score
}

func (s *SecurityModule) GeneratePassword(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
	rand.Seed(time.Now().UnixNano())
	
	password := make([]byte, length)
	for i := range password {
		password[i] = charset[rand.Intn(len(charset))]
	}
	
	return string(password)
}

// Connection tracking
func (s *SecurityModule) TrackConnection(sourceIP, destIP string, port int, protocol string) {
	key := fmt.Sprintf("%s:%s:%d", sourceIP, destIP, port)
	
	if conn, exists := s.Connections[key]; exists {
		conn.PacketCount++
	} else {
		s.Connections[key] = &Connection{
			SourceIP:    sourceIP,
			DestIP:      destIP,
			Port:        port,
			Protocol:    protocol,
			Timestamp:   time.Now(),
			PacketCount: 1,
		}
	}
}

func (s *SecurityModule) DetectPortScan(sourceIP string) bool {
	uniquePorts := make(map[int]bool)
	
	for key, conn := range s.Connections {
		if strings.HasPrefix(key, sourceIP+":") {
			uniquePorts[conn.Port] = true
		}
	}
	
	// If scanning more than 10 different ports, it's likely a port scan
	return len(uniquePorts) > 10
}

// Exploit simulation (for demos)
func (s *SecurityModule) SimulateExploit(targetType string) map[string]interface{} {
	exploits := map[string]map[string]interface{}{
		"apache": {
			"vulnerable": true,
			"cve":        "CVE-2021-41773",
			"severity":   "critical",
			"success":    true,
		},
		"ssh": {
			"vulnerable": true,
			"cve":        "CVE-2018-15473",
			"severity":   "medium",
			"success":    false,
		},
		"smb": {
			"vulnerable": true,
			"cve":        "MS17-010",
			"severity":   "critical",
			"success":    true,
		},
	}
	
	if exploit, exists := exploits[targetType]; exists {
		return exploit
	}
	
	return map[string]interface{}{
		"vulnerable": false,
		"cve":        "none",
		"severity":   "none",
		"success":    false,
	}
}

// Generate API Key
func (s *SecurityModule) GenerateAPIKey(prefix string, length int) string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	rand.Seed(time.Now().UnixNano())
	
	key := make([]byte, length)
	for i := range key {
		key[i] = charset[rand.Intn(len(charset))]
	}
	
	return fmt.Sprintf("%s_%s", prefix, string(key))
}