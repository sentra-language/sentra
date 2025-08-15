package siem

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// SyslogParser parses syslog format messages
type SyslogParser struct{}

func (p *SyslogParser) Parse(line string) (*LogEntry, error) {
	// RFC3164 syslog format: <priority>timestamp hostname tag: message
	syslogRegex := regexp.MustCompile(`^<(\d+)>(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+([^:]+):\s*(.*)$`)
	matches := syslogRegex.FindStringSubmatch(line)
	
	if len(matches) != 6 {
		// Try simpler format
		simpleRegex := regexp.MustCompile(`^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(.*)$`)
		simpleMatches := simpleRegex.FindStringSubmatch(line)
		if len(simpleMatches) != 4 {
			return nil, fmt.Errorf("invalid syslog format")
		}
		
		timestamp, err := time.Parse("Jan 02 15:04:05", simpleMatches[1])
		if err != nil {
			timestamp = time.Now()
		}
		
		return &LogEntry{
			Timestamp: timestamp,
			Level:     "INFO",
			Source:    "syslog",
			Host:      simpleMatches[2],
			Message:   simpleMatches[3],
			Fields:    make(map[string]string),
			EventType: "system",
			Severity:  1,
			Category:  "system",
		}, nil
	}
	
	priority, _ := strconv.Atoi(matches[1])
	timestamp, err := time.Parse("Jan 02 15:04:05", matches[2])
	if err != nil {
		timestamp = time.Now()
	}
	
	// Extract facility and severity from priority
	facility := priority / 8
	severity := priority % 8
	
	level := p.severityToLevel(severity)
	
	return &LogEntry{
		Timestamp: timestamp,
		Level:     level,
		Source:    "syslog",
		Host:      matches[3],
		Message:   matches[5],
		Fields: map[string]string{
			"tag":      matches[4],
			"facility": strconv.Itoa(facility),
			"priority": matches[1],
		},
		EventType: "system",
		Severity:  severity,
		Category:  "system",
	}, nil
}

func (p *SyslogParser) GetFormat() string {
	return "syslog"
}

func (p *SyslogParser) GetPatterns() []string {
	return []string{
		`<\d+>\w+\s+\d+\s+\d+:\d+:\d+\s+\S+\s+[^:]+:.*`,
		`\w+\s+\d+\s+\d+:\d+:\d+\s+\S+\s+.*`,
	}
}

func (p *SyslogParser) severityToLevel(severity int) string {
	switch severity {
	case 0, 1, 2:
		return "ERROR"
	case 3:
		return "WARNING"
	case 4, 5:
		return "NOTICE"
	case 6:
		return "INFO"
	case 7:
		return "DEBUG"
	default:
		return "INFO"
	}
}

// ApacheParser parses Apache access logs
type ApacheParser struct{}

func (p *ApacheParser) Parse(line string) (*LogEntry, error) {
	// Common Log Format: IP - - [timestamp] "method URI protocol" status size
	apacheRegex := regexp.MustCompile(`^(\S+) (\S+) (\S+) \[([^\]]+)\] "([^"]*)" (\d+) (\S+)(.*)$`)
	matches := apacheRegex.FindStringSubmatch(line)
	
	if len(matches) < 8 {
		return nil, fmt.Errorf("invalid Apache log format")
	}
	
	timestamp, err := time.Parse("02/Jan/2006:15:04:05 -0700", matches[4])
	if err != nil {
		timestamp = time.Now()
	}
	
	status, _ := strconv.Atoi(matches[6])
	size := matches[7]
	if size == "-" {
		size = "0"
	}
	
	requestParts := strings.Fields(matches[5])
	method, uri, protocol := "", "", ""
	if len(requestParts) >= 3 {
		method = requestParts[0]
		uri = requestParts[1]
		protocol = requestParts[2]
	}
	
	level := "INFO"
	if status >= 400 {
		level = "WARNING"
	}
	if status >= 500 {
		level = "ERROR"
	}
	
	return &LogEntry{
		Timestamp: timestamp,
		Level:     level,
		Source:    "apache",
		Host:      matches[1],
		Message:   fmt.Sprintf("%s %s %s - %d", method, uri, protocol, status),
		Fields: map[string]string{
			"client_ip":    matches[1],
			"identity":     matches[2],
			"user":         matches[3],
			"method":       method,
			"uri":          uri,
			"protocol":     protocol,
			"status":       matches[6],
			"size":         size,
			"user_agent":   strings.Trim(matches[8], `" `),
		},
		EventType: "web_access",
		Severity:  p.statusToSeverity(status),
		Category:  "web",
	}, nil
}

func (p *ApacheParser) GetFormat() string {
	return "apache"
}

func (p *ApacheParser) GetPatterns() []string {
	return []string{
		`^\S+ \S+ \S+ \[[^\]]+\] "[^"]*" \d+ \S+`,
	}
}

func (p *ApacheParser) statusToSeverity(status int) int {
	if status >= 500 {
		return 3 // Error
	}
	if status >= 400 {
		return 2 // Warning
	}
	return 1 // Info
}

// NginxParser parses Nginx access logs
type NginxParser struct{}

func (p *NginxParser) Parse(line string) (*LogEntry, error) {
	// Nginx default format: IP - user [timestamp] "request" status size "referer" "user-agent"
	nginxRegex := regexp.MustCompile(`^(\S+) - (\S+) \[([^\]]+)\] "([^"]*)" (\d+) (\d+) "([^"]*)" "([^"]*)"`)
	matches := nginxRegex.FindStringSubmatch(line)
	
	if len(matches) != 9 {
		return nil, fmt.Errorf("invalid Nginx log format")
	}
	
	timestamp, err := time.Parse("02/Jan/2006:15:04:05 -0700", matches[3])
	if err != nil {
		timestamp = time.Now()
	}
	
	status, _ := strconv.Atoi(matches[5])
	_, _ = strconv.Atoi(matches[6]) // size - not used in message
	
	requestParts := strings.Fields(matches[4])
	method, uri, protocol := "", "", ""
	if len(requestParts) >= 3 {
		method = requestParts[0]
		uri = requestParts[1]
		protocol = requestParts[2]
	}
	
	level := "INFO"
	if status >= 400 {
		level = "WARNING"
	}
	if status >= 500 {
		level = "ERROR"
	}
	
	return &LogEntry{
		Timestamp: timestamp,
		Level:     level,
		Source:    "nginx",
		Host:      matches[1],
		Message:   fmt.Sprintf("%s %s %s - %d", method, uri, protocol, status),
		Fields: map[string]string{
			"client_ip":   matches[1],
			"user":        matches[2],
			"method":      method,
			"uri":         uri,
			"protocol":    protocol,
			"status":      matches[5],
			"size":        matches[6],
			"referer":     matches[7],
			"user_agent":  matches[8],
		},
		EventType: "web_access",
		Severity:  p.statusToSeverity(status),
		Category:  "web",
	}, nil
}

func (p *NginxParser) GetFormat() string {
	return "nginx"
}

func (p *NginxParser) GetPatterns() []string {
	return []string{
		`^\S+ - \S+ \[[^\]]+\] "[^"]*" \d+ \d+ "[^"]*" "[^"]*"`,
	}
}

func (p *NginxParser) statusToSeverity(status int) int {
	if status >= 500 {
		return 3
	}
	if status >= 400 {
		return 2
	}
	return 1
}

// WindowsEventParser parses Windows Event Log format
type WindowsEventParser struct{}

func (p *WindowsEventParser) Parse(line string) (*LogEntry, error) {
	// Simplified Windows Event Log parsing
	// Format: Timestamp Level Source EventID Message
	parts := strings.SplitN(line, " ", 5)
	if len(parts) < 5 {
		return nil, fmt.Errorf("invalid Windows event format")
	}
	
	timestamp, err := time.Parse("2006-01-02 15:04:05", parts[0]+" "+parts[1])
	if err != nil {
		timestamp = time.Now()
	}
	
	eventID := ""
	if len(parts) > 4 {
		eventID = parts[3]
	}
	
	return &LogEntry{
		Timestamp: timestamp,
		Level:     strings.ToUpper(parts[2]),
		Source:    "windows",
		Host:      "localhost",
		Message:   parts[4],
		Fields: map[string]string{
			"source_name": parts[3],
			"event_id":    eventID,
		},
		EventType: "windows_event",
		Severity:  p.levelToSeverity(parts[2]),
		Category:  "system",
	}, nil
}

func (p *WindowsEventParser) GetFormat() string {
	return "windows"
}

func (p *WindowsEventParser) GetPatterns() []string {
	return []string{
		`^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \w+ \S+ .*`,
	}
}

func (p *WindowsEventParser) levelToSeverity(level string) int {
	switch strings.ToUpper(level) {
	case "CRITICAL", "ERROR":
		return 3
	case "WARNING":
		return 2
	case "INFORMATION", "INFO":
		return 1
	default:
		return 1
	}
}

// JSONParser parses JSON log entries
type JSONParser struct{}

func (p *JSONParser) Parse(line string) (*LogEntry, error) {
	var rawEntry map[string]interface{}
	if err := json.Unmarshal([]byte(line), &rawEntry); err != nil {
		return nil, fmt.Errorf("invalid JSON format: %w", err)
	}
	
	entry := &LogEntry{
		Fields:   make(map[string]string),
		Category: "application",
	}
	
	// Extract common fields
	if ts, ok := rawEntry["timestamp"].(string); ok {
		if timestamp, err := time.Parse(time.RFC3339, ts); err == nil {
			entry.Timestamp = timestamp
		}
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}
	
	if level, ok := rawEntry["level"].(string); ok {
		entry.Level = strings.ToUpper(level)
	} else {
		entry.Level = "INFO"
	}
	
	if source, ok := rawEntry["source"].(string); ok {
		entry.Source = source
	} else {
		entry.Source = "application"
	}
	
	if host, ok := rawEntry["host"].(string); ok {
		entry.Host = host
	} else {
		entry.Host = "localhost"
	}
	
	if message, ok := rawEntry["message"].(string); ok {
		entry.Message = message
	}
	
	if eventType, ok := rawEntry["event_type"].(string); ok {
		entry.EventType = eventType
	} else {
		entry.EventType = "application"
	}
	
	// Convert all fields to strings
	for key, value := range rawEntry {
		if key != "timestamp" && key != "level" && key != "source" && key != "host" && key != "message" && key != "event_type" {
			entry.Fields[key] = fmt.Sprintf("%v", value)
		}
	}
	
	entry.Severity = p.levelToSeverity(entry.Level)
	
	return entry, nil
}

func (p *JSONParser) GetFormat() string {
	return "json"
}

func (p *JSONParser) GetPatterns() []string {
	return []string{
		`^\{.*\}$`,
	}
}

func (p *JSONParser) levelToSeverity(level string) int {
	switch strings.ToUpper(level) {
	case "FATAL", "ERROR":
		return 3
	case "WARN", "WARNING":
		return 2
	case "INFO", "INFORMATION":
		return 1
	case "DEBUG", "TRACE":
		return 0
	default:
		return 1
	}
}

// CEFParser parses Common Event Format logs
type CEFParser struct{}

func (p *CEFParser) Parse(line string) (*LogEntry, error) {
	// CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
	if !strings.HasPrefix(line, "CEF:") {
		return nil, fmt.Errorf("not a CEF format log")
	}
	
	parts := strings.Split(line[4:], "|")
	if len(parts) < 7 {
		return nil, fmt.Errorf("invalid CEF format")
	}
	
	severity, _ := strconv.Atoi(parts[6])
	
	entry := &LogEntry{
		Timestamp: time.Now(),
		Level:     p.severityToCEFLevel(severity),
		Source:    "cef",
		Host:      "localhost",
		Message:   parts[5], // Name field
		Fields: map[string]string{
			"version":       parts[0],
			"device_vendor": parts[1],
			"device_product": parts[2],
			"device_version": parts[3],
			"signature_id":  parts[4],
		},
		EventType: "security",
		Severity:  severity,
		Category:  "security",
	}
	
	// Parse extension fields if present
	if len(parts) > 7 {
		extensions := p.parseExtensions(parts[7])
		for key, value := range extensions {
			entry.Fields[key] = value
		}
		
		// Override timestamp if present
		if ts, ok := extensions["rt"]; ok {
			if timestamp, err := time.Parse("Jan 02 2006 15:04:05", ts); err == nil {
				entry.Timestamp = timestamp
			}
		}
		
		// Override host if present
		if host, ok := extensions["dhost"]; ok {
			entry.Host = host
		}
	}
	
	return entry, nil
}

func (p *CEFParser) GetFormat() string {
	return "cef"
}

func (p *CEFParser) GetPatterns() []string {
	return []string{
		`^CEF:\d+\|.*\|.*\|.*\|.*\|.*\|\d+`,
	}
}

func (p *CEFParser) parseExtensions(ext string) map[string]string {
	extensions := make(map[string]string)
	pairs := strings.Split(ext, " ")
	
	for _, pair := range pairs {
		if strings.Contains(pair, "=") {
			kv := strings.SplitN(pair, "=", 2)
			if len(kv) == 2 {
				extensions[kv[0]] = kv[1]
			}
		}
	}
	
	return extensions
}

func (p *CEFParser) severityToCEFLevel(severity int) string {
	switch {
	case severity >= 7:
		return "CRITICAL"
	case severity >= 5:
		return "ERROR"
	case severity >= 3:
		return "WARNING"
	default:
		return "INFO"
	}
}

// LEEFParser parses Log Event Extended Format
type LEEFParser struct{}

func (p *LEEFParser) Parse(line string) (*LogEntry, error) {
	// LEEF:Version|Vendor|Product|Version|EventID|DelimiterCharacter|Fields
	if !strings.HasPrefix(line, "LEEF:") {
		return nil, fmt.Errorf("not a LEEF format log")
	}
	
	parts := strings.Split(line[5:], "|")
	if len(parts) < 6 {
		return nil, fmt.Errorf("invalid LEEF format")
	}
	
	delimiter := "|"
	if len(parts) > 5 && parts[5] != "" {
		delimiter = parts[5]
	}
	
	entry := &LogEntry{
		Timestamp: time.Now(),
		Level:     "INFO",
		Source:    "leef",
		Host:      "localhost",
		Message:   parts[4], // EventID
		Fields: map[string]string{
			"version": parts[0],
			"vendor":  parts[1],
			"product": parts[2],
			"product_version": parts[3],
			"event_id": parts[4],
		},
		EventType: "security",
		Severity:  1,
		Category:  "security",
	}
	
	// Parse additional fields
	if len(parts) > 6 {
		fields := p.parseFields(parts[6], delimiter)
		for key, value := range fields {
			entry.Fields[key] = value
		}
		
		// Override fields if present
		if ts, ok := fields["devTime"]; ok {
			if timestamp, err := time.Parse("Jan 02 2006 15:04:05", ts); err == nil {
				entry.Timestamp = timestamp
			}
		}
		
		if severity, ok := fields["sev"]; ok {
			if sev, err := strconv.Atoi(severity); err == nil {
				entry.Severity = sev
				entry.Level = p.severityToLEEFLevel(sev)
			}
		}
	}
	
	return entry, nil
}

func (p *LEEFParser) GetFormat() string {
	return "leef"
}

func (p *LEEFParser) GetPatterns() []string {
	return []string{
		`^LEEF:\d+\|.*\|.*\|.*\|.*\|`,
	}
}

func (p *LEEFParser) parseFields(fields string, delimiter string) map[string]string {
	result := make(map[string]string)
	pairs := strings.Split(fields, delimiter)
	
	for _, pair := range pairs {
		if strings.Contains(pair, "=") {
			kv := strings.SplitN(pair, "=", 2)
			if len(kv) == 2 {
				result[kv[0]] = kv[1]
			}
		}
	}
	
	return result
}

func (p *LEEFParser) severityToLEEFLevel(severity int) string {
	switch {
	case severity >= 8:
		return "CRITICAL"
	case severity >= 6:
		return "ERROR"
	case severity >= 4:
		return "WARNING"
	default:
		return "INFO"
	}
}