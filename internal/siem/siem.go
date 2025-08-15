package siem

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// SIEMIntegration provides SIEM integration and log analysis capabilities
type SIEMIntegration struct {
	parsers      map[string]LogParser
	correlations []CorrelationRule
	alerts       []Alert
	connections  map[string]SIEMConnection
}

// LogEntry represents a parsed log entry
type LogEntry struct {
	Timestamp   time.Time         `json:"timestamp"`
	Level       string            `json:"level"`
	Source      string            `json:"source"`
	Host        string            `json:"host"`
	Message     string            `json:"message"`
	Fields      map[string]string `json:"fields"`
	EventType   string            `json:"event_type"`
	Severity    int               `json:"severity"`
	Category    string            `json:"category"`
	Raw         string            `json:"raw"`
	Normalized  bool              `json:"normalized"`
}

// LogParser interface for different log formats
type LogParser interface {
	Parse(line string) (*LogEntry, error)
	GetFormat() string
	GetPatterns() []string
}

// CorrelationRule defines rules for event correlation
type CorrelationRule struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Conditions  []RuleCondition   `json:"conditions"`
	Timeframe   time.Duration     `json:"timeframe"`
	Threshold   int               `json:"threshold"`
	Actions     []string          `json:"actions"`
	Severity    string            `json:"severity"`
	Category    string            `json:"category"`
	Enabled     bool              `json:"enabled"`
	Metadata    map[string]string `json:"metadata"`
}

// RuleCondition represents a condition in a correlation rule
type RuleCondition struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
	Regex    string `json:"regex,omitempty"`
}

// Alert represents a security alert
type Alert struct {
	ID          string            `json:"id"`
	RuleID      string            `json:"rule_id"`
	Timestamp   time.Time         `json:"timestamp"`
	Severity    string            `json:"severity"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Events      []*LogEntry       `json:"events"`
	Source      string            `json:"source"`
	Category    string            `json:"category"`
	Indicators  []string          `json:"indicators"`
	Metadata    map[string]string `json:"metadata"`
	Status      string            `json:"status"`
}

// SIEMConnection represents a connection to a SIEM platform
type SIEMConnection struct {
	Platform   string            `json:"platform"`
	Host       string            `json:"host"`
	Port       int               `json:"port"`
	Protocol   string            `json:"protocol"`
	Username   string            `json:"username"`
	Password   string            `json:"password"`
	APIKey     string            `json:"api_key"`
	TLS        bool              `json:"tls"`
	Connected  bool              `json:"connected"`
	LastSeen   time.Time         `json:"last_seen"`
	Config     map[string]string `json:"config"`
}

// EventStats represents statistics about processed events
type EventStats struct {
	TotalEvents    int                    `json:"total_events"`
	EventsBySource map[string]int         `json:"events_by_source"`
	EventsByLevel  map[string]int         `json:"events_by_level"`
	EventsByType   map[string]int         `json:"events_by_type"`
	AlertsGenerated int                   `json:"alerts_generated"`
	TimeRange      [2]time.Time           `json:"time_range"`
	TopSources     []SourceStats          `json:"top_sources"`
	ThreatIndicators []ThreatIndicator    `json:"threat_indicators"`
}

// SourceStats represents statistics for a log source
type SourceStats struct {
	Source string `json:"source"`
	Count  int    `json:"count"`
	Level  string `json:"level"`
}

// ThreatIndicator represents a potential threat indicator
type ThreatIndicator struct {
	Type        string    `json:"type"`
	Value       string    `json:"value"`
	Confidence  float64   `json:"confidence"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Count       int       `json:"count"`
	Description string    `json:"description"`
}

// NewSIEMIntegration creates a new SIEM integration instance
func NewSIEMIntegration() *SIEMIntegration {
	siem := &SIEMIntegration{
		parsers:      make(map[string]LogParser),
		correlations: []CorrelationRule{},
		alerts:       []Alert{},
		connections:  make(map[string]SIEMConnection),
	}
	
	// Register default parsers
	siem.registerDefaultParsers()
	siem.loadDefaultRules()
	
	return siem
}

// registerDefaultParsers registers built-in log parsers
func (s *SIEMIntegration) registerDefaultParsers() {
	s.parsers["syslog"] = &SyslogParser{}
	s.parsers["apache"] = &ApacheParser{}
	s.parsers["nginx"] = &NginxParser{}
	s.parsers["windows"] = &WindowsEventParser{}
	s.parsers["json"] = &JSONParser{}
	s.parsers["cef"] = &CEFParser{}
	s.parsers["leef"] = &LEEFParser{}
}

// ParseLogFile parses a log file and returns entries
func (s *SIEMIntegration) ParseLogFile(filePath string, format string) ([]*LogEntry, error) {
	parser, ok := s.parsers[format]
	if !ok {
		return nil, fmt.Errorf("unsupported log format: %s", format)
	}
	
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}
	defer file.Close()
	
	var entries []*LogEntry
	scanner := bufio.NewScanner(file)
	lineNum := 0
	
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		
		entry, err := parser.Parse(line)
		if err != nil {
			// Log parsing error but continue
			fmt.Printf("Warning: Failed to parse line %d: %v\n", lineNum, err)
			continue
		}
		
		if entry != nil {
			entry.Raw = line
			entries = append(entries, entry)
		}
	}
	
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading log file: %w", err)
	}
	
	return entries, nil
}

// AnalyzeLogs analyzes log entries for patterns and threats
func (s *SIEMIntegration) AnalyzeLogs(entries []*LogEntry) *EventStats {
	stats := &EventStats{
		TotalEvents:      len(entries),
		EventsBySource:   make(map[string]int),
		EventsByLevel:    make(map[string]int),
		EventsByType:     make(map[string]int),
		TopSources:       []SourceStats{},
		ThreatIndicators: []ThreatIndicator{},
	}
	
	if len(entries) == 0 {
		return stats
	}
	
	// Set time range
	stats.TimeRange[0] = entries[0].Timestamp
	stats.TimeRange[1] = entries[len(entries)-1].Timestamp
	
	// Analyze entries
	threatMap := make(map[string]*ThreatIndicator)
	
	for _, entry := range entries {
		// Count by source
		stats.EventsBySource[entry.Source]++
		
		// Count by level
		stats.EventsByLevel[entry.Level]++
		
		// Count by type
		stats.EventsByType[entry.EventType]++
		
		// Check for threat indicators
		indicators := s.extractThreatIndicators(entry)
		for _, indicator := range indicators {
			key := fmt.Sprintf("%s:%s", indicator.Type, indicator.Value)
			if existing, ok := threatMap[key]; ok {
				existing.Count++
				existing.LastSeen = entry.Timestamp
			} else {
				indicator.FirstSeen = entry.Timestamp
				indicator.LastSeen = entry.Timestamp
				indicator.Count = 1
				threatMap[key] = &indicator
			}
		}
	}
	
	// Convert threat map to slice
	for _, indicator := range threatMap {
		stats.ThreatIndicators = append(stats.ThreatIndicators, *indicator)
	}
	
	// Sort threat indicators by count
	sort.Slice(stats.ThreatIndicators, func(i, j int) bool {
		return stats.ThreatIndicators[i].Count > stats.ThreatIndicators[j].Count
	})
	
	// Create top sources
	type sourceCount struct {
		source string
		count  int
	}
	var sources []sourceCount
	for source, count := range stats.EventsBySource {
		sources = append(sources, sourceCount{source, count})
	}
	sort.Slice(sources, func(i, j int) bool {
		return sources[i].count > sources[j].count
	})
	
	for i, sc := range sources {
		if i >= 10 { // Top 10
			break
		}
		stats.TopSources = append(stats.TopSources, SourceStats{
			Source: sc.source,
			Count:  sc.count,
			Level:  "INFO", // Default
		})
	}
	
	return stats
}

// extractThreatIndicators extracts potential threat indicators from log entry
func (s *SIEMIntegration) extractThreatIndicators(entry *LogEntry) []ThreatIndicator {
	var indicators []ThreatIndicator
	
	// IP address patterns
	ipRegex := regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	ips := ipRegex.FindAllString(entry.Message, -1)
	for _, ip := range ips {
		if s.isSuspiciousIP(ip) {
			indicators = append(indicators, ThreatIndicator{
				Type:        "ip",
				Value:       ip,
				Confidence:  0.7,
				Description: "Suspicious IP address detected",
			})
		}
	}
	
	// Domain patterns
	domainRegex := regexp.MustCompile(`\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\b`)
	domains := domainRegex.FindAllString(entry.Message, -1)
	for _, domain := range domains {
		if s.isSuspiciousDomain(domain) {
			indicators = append(indicators, ThreatIndicator{
				Type:        "domain",
				Value:       domain,
				Confidence:  0.6,
				Description: "Suspicious domain detected",
			})
		}
	}
	
	// Hash patterns (MD5, SHA1, SHA256)
	hashRegex := regexp.MustCompile(`\b[a-fA-F0-9]{32,64}\b`)
	hashes := hashRegex.FindAllString(entry.Message, -1)
	for _, hash := range hashes {
		indicators = append(indicators, ThreatIndicator{
			Type:        "hash",
			Value:       hash,
			Confidence:  0.8,
			Description: "File hash detected",
		})
	}
	
	// Check for attack patterns
	attackPatterns := map[string]float64{
		"sql injection":     0.9,
		"union select":      0.9,
		"<script":          0.8,
		"javascript:":      0.7,
		"../":              0.6,
		"passwd":           0.7,
		"shadow":           0.7,
		"cmd.exe":          0.8,
		"powershell":       0.7,
		"base64":           0.5,
	}
	
	lowerMessage := strings.ToLower(entry.Message)
	for pattern, confidence := range attackPatterns {
		if strings.Contains(lowerMessage, pattern) {
			indicators = append(indicators, ThreatIndicator{
				Type:        "attack_pattern",
				Value:       pattern,
				Confidence:  confidence,
				Description: fmt.Sprintf("Attack pattern '%s' detected", pattern),
			})
		}
	}
	
	return indicators
}

// isSuspiciousIP checks if an IP address is suspicious
func (s *SIEMIntegration) isSuspiciousIP(ip string) bool {
	// Simple checks for suspicious IPs
	suspiciousRanges := []string{
		"0.0.0.0",
		"127.", // Localhost (might be suspicious in certain contexts)
		"255.255.255.255",
	}
	
	for _, suspicious := range suspiciousRanges {
		if strings.HasPrefix(ip, suspicious) {
			return true
		}
	}
	
	// Check for private IP ranges that might be suspicious in external logs
	parsedIP := net.ParseIP(ip)
	if parsedIP != nil {
		// Add more sophisticated IP reputation checking here
		return false
	}
	
	return false
}

// isSuspiciousDomain checks if a domain is suspicious
func (s *SIEMIntegration) isSuspiciousDomain(domain string) bool {
	// Simple domain reputation checking
	suspiciousTLDs := []string{
		".tk", ".ml", ".ga", ".cf", // Free domains often used maliciously
		".bit", ".onion", // Special domains
	}
	
	lowerDomain := strings.ToLower(domain)
	for _, tld := range suspiciousTLDs {
		if strings.HasSuffix(lowerDomain, tld) {
			return true
		}
	}
	
	// Check for DGA-like patterns (many consonants, random-looking)
	vowels := "aeiou"
	consonantCount := 0
	for _, char := range lowerDomain {
		if !strings.ContainsRune(vowels, char) && char != '.' && char != '-' {
			consonantCount++
		}
	}
	
	// Simple heuristic: if more than 70% consonants, might be DGA
	if len(domain) > 8 && float64(consonantCount)/float64(len(domain)) > 0.7 {
		return true
	}
	
	return false
}

// CorrelateEvents correlates events based on defined rules
func (s *SIEMIntegration) CorrelateEvents(entries []*LogEntry) ([]*Alert, error) {
	var alerts []*Alert
	
	for _, rule := range s.correlations {
		if !rule.Enabled {
			continue
		}
		
		matchingEvents := s.findMatchingEvents(entries, rule)
		if len(matchingEvents) >= rule.Threshold {
			alert := &Alert{
				ID:          fmt.Sprintf("alert_%d", time.Now().Unix()),
				RuleID:      rule.ID,
				Timestamp:   time.Now(),
				Severity:    rule.Severity,
				Title:       rule.Name,
				Description: rule.Description,
				Events:      matchingEvents,
				Source:      "correlation_engine",
				Category:    rule.Category,
				Status:      "open",
				Metadata:    make(map[string]string),
			}
			
			// Extract indicators from events
			var indicators []string
			for _, event := range matchingEvents {
				threatIndicators := s.extractThreatIndicators(event)
				for _, ti := range threatIndicators {
					indicators = append(indicators, fmt.Sprintf("%s: %s", ti.Type, ti.Value))
				}
			}
			alert.Indicators = indicators
			
			alerts = append(alerts, alert)
		}
	}
	
	return alerts, nil
}

// findMatchingEvents finds events that match a correlation rule
func (s *SIEMIntegration) findMatchingEvents(entries []*LogEntry, rule CorrelationRule) []*LogEntry {
	var matching []*LogEntry
	cutoffTime := time.Now().Add(-rule.Timeframe)
	
	for _, entry := range entries {
		if entry.Timestamp.Before(cutoffTime) {
			continue
		}
		
		if s.eventMatchesRule(entry, rule) {
			matching = append(matching, entry)
		}
	}
	
	return matching
}

// eventMatchesRule checks if an event matches a correlation rule
func (s *SIEMIntegration) eventMatchesRule(entry *LogEntry, rule CorrelationRule) bool {
	for _, condition := range rule.Conditions {
		if !s.evaluateCondition(entry, condition) {
			return false
		}
	}
	return true
}

// evaluateCondition evaluates a single rule condition
func (s *SIEMIntegration) evaluateCondition(entry *LogEntry, condition RuleCondition) bool {
	var fieldValue string
	
	switch condition.Field {
	case "message":
		fieldValue = entry.Message
	case "level":
		fieldValue = entry.Level
	case "source":
		fieldValue = entry.Source
	case "event_type":
		fieldValue = entry.EventType
	case "host":
		fieldValue = entry.Host
	default:
		if val, ok := entry.Fields[condition.Field]; ok {
			fieldValue = val
		}
	}
	
	switch condition.Operator {
	case "equals":
		return fieldValue == condition.Value
	case "contains":
		return strings.Contains(strings.ToLower(fieldValue), strings.ToLower(condition.Value))
	case "regex":
		if condition.Regex != "" {
			matched, _ := regexp.MatchString(condition.Regex, fieldValue)
			return matched
		}
	case "greater_than":
		if val, err := strconv.Atoi(fieldValue); err == nil {
			if threshold, err := strconv.Atoi(condition.Value); err == nil {
				return val > threshold
			}
		}
	case "less_than":
		if val, err := strconv.Atoi(fieldValue); err == nil {
			if threshold, err := strconv.Atoi(condition.Value); err == nil {
				return val < threshold
			}
		}
	}
	
	return false
}

// SendToSyslog sends events to a syslog server
func (s *SIEMIntegration) SendToSyslog(host string, port int, entries []*LogEntry) error {
	conn, err := net.Dial("udp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return fmt.Errorf("failed to connect to syslog server: %w", err)
	}
	defer conn.Close()
	
	for _, entry := range entries {
		// Format as RFC3164 syslog message
		priority := 16 // Local use facility, info level
		timestamp := entry.Timestamp.Format("Jan 02 15:04:05")
		message := fmt.Sprintf("<%d>%s %s sentra: %s", priority, timestamp, entry.Host, entry.Message)
		
		if _, err := conn.Write([]byte(message)); err != nil {
			return fmt.Errorf("failed to send syslog message: %w", err)
		}
	}
	
	return nil
}

// ExportEvents exports events to various formats
func (s *SIEMIntegration) ExportEvents(entries []*LogEntry, format string, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()
	
	switch strings.ToLower(format) {
	case "json":
		return s.exportJSON(entries, file)
	case "csv":
		return s.exportCSV(entries, file)
	case "cef":
		return s.exportCEF(entries, file)
	default:
		return fmt.Errorf("unsupported export format: %s", format)
	}
}

// exportJSON exports events as JSON
func (s *SIEMIntegration) exportJSON(entries []*LogEntry, writer io.Writer) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(entries)
}

// exportCSV exports events as CSV
func (s *SIEMIntegration) exportCSV(entries []*LogEntry, writer io.Writer) error {
	// Write CSV header
	header := "timestamp,level,source,host,event_type,message\n"
	if _, err := writer.Write([]byte(header)); err != nil {
		return err
	}
	
	// Write entries
	for _, entry := range entries {
		row := fmt.Sprintf("%s,%s,%s,%s,%s,\"%s\"\n",
			entry.Timestamp.Format(time.RFC3339),
			entry.Level,
			entry.Source,
			entry.Host,
			entry.EventType,
			strings.ReplaceAll(entry.Message, "\"", "\"\""), // Escape quotes
		)
		if _, err := writer.Write([]byte(row)); err != nil {
			return err
		}
	}
	
	return nil
}

// exportCEF exports events in Common Event Format
func (s *SIEMIntegration) exportCEF(entries []*LogEntry, writer io.Writer) error {
	for _, entry := range entries {
		// CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
		cef := fmt.Sprintf("CEF:0|Sentra|SecurityAnalyzer|1.0|%s|%s|%d|src=%s msg=%s\n",
			entry.EventType,
			entry.Message,
			entry.Severity,
			entry.Host,
			entry.Message,
		)
		if _, err := writer.Write([]byte(cef)); err != nil {
			return err
		}
	}
	
	return nil
}

// loadDefaultRules loads default correlation rules
func (s *SIEMIntegration) loadDefaultRules() {
	defaultRules := []CorrelationRule{
		{
			ID:          "brute_force_ssh",
			Name:        "SSH Brute Force Attack",
			Description: "Multiple failed SSH login attempts detected",
			Conditions: []RuleCondition{
				{Field: "message", Operator: "contains", Value: "failed password"},
				{Field: "source", Operator: "contains", Value: "ssh"},
			},
			Timeframe: 5 * time.Minute,
			Threshold: 5,
			Severity:  "HIGH",
			Category:  "authentication",
			Enabled:   true,
		},
		{
			ID:          "web_attack",
			Name:        "Web Application Attack",
			Description: "Potential web application attack detected",
			Conditions: []RuleCondition{
				{Field: "message", Operator: "regex", Regex: "(?i)(union select|<script|javascript:|../|cmd\\.exe)"},
			},
			Timeframe: 1 * time.Minute,
			Threshold: 1,
			Severity:  "MEDIUM",
			Category:  "web_attack",
			Enabled:   true,
		},
		{
			ID:          "privilege_escalation",
			Name:        "Privilege Escalation Attempt",
			Description: "Potential privilege escalation detected",
			Conditions: []RuleCondition{
				{Field: "message", Operator: "contains", Value: "sudo"},
				{Field: "level", Operator: "equals", Value: "warning"},
			},
			Timeframe: 2 * time.Minute,
			Threshold: 3,
			Severity:  "HIGH",
			Category:  "privilege_escalation",
			Enabled:   true,
		},
	}
	
	s.correlations = append(s.correlations, defaultRules...)
}