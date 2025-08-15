package siem

import (
	"fmt"
	"strconv"
	"time"
)

// Import VM types
type Value interface{}

// Forward declarations for VM types - these should match vm/value.go
type Map struct {
	Items map[string]Value
}

type Array struct {
	Elements []Value
}

// NewMap creates a new map
func NewMap() *Map {
	return &Map{
		Items: make(map[string]Value),
	}
}

// NewArrayFromSlice creates an array from a Go slice
func NewArrayFromSlice(slice []Value) *Array {
	return &Array{
		Elements: slice,
	}
}

// ToString converts a value to string
func ToString(val Value) string {
	if val == nil {
		return ""
	}
	
	switch v := val.(type) {
	case string:
		return v
	case float64:
		if v == float64(int64(v)) {
			return fmt.Sprintf("%.0f", v)
		}
		return fmt.Sprintf("%g", v)
	case bool:
		if v {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprintf("%v", v)
	}
}

// ToNumber converts a value to number
func ToNumber(val Value) float64 {
	if val == nil {
		return 0
	}
	
	switch v := val.(type) {
	case float64:
		return v
	case string:
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
		return 0
	case bool:
		if v {
			return 1
		}
		return 0
	default:
		return 0
	}
}

// SIEMModule provides SIEM integration functions for Sentra VM
type SIEMModule struct {
	siem *SIEMIntegration
}

// NewSIEMModule creates a new SIEM module
func NewSIEMModule() *SIEMModule {
	return &SIEMModule{
		siem: NewSIEMIntegration(),
	}
}

// ParseLogFile parses a log file and returns entries
func (sm *SIEMModule) ParseLogFile(filePathValue Value, formatValue Value) Value {
	filePath := ToString(filePathValue)
	format := ToString(formatValue)
	
	entries, err := sm.siem.ParseLogFile(filePath, format)
	if err != nil {
		return nil
	}
	
	return sm.convertEntriesToValue(entries)
}

// AnalyzeLogs analyzes log entries for patterns and threats
func (sm *SIEMModule) AnalyzeLogs(entriesValue Value) Value {
	entries := sm.convertValueToEntries(entriesValue)
	if entries == nil {
		return nil
	}
	
	stats := sm.siem.AnalyzeLogs(entries)
	return sm.convertStatsToValue(stats)
}

// CorrelateEvents correlates events based on rules
func (sm *SIEMModule) CorrelateEvents(entriesValue Value) Value {
	entries := sm.convertValueToEntries(entriesValue)
	if entries == nil {
		return NewArrayFromSlice([]Value{})
	}
	
	alerts, err := sm.siem.CorrelateEvents(entries)
	if err != nil {
		return NewArrayFromSlice([]Value{})
	}
	
	return sm.convertAlertsToValue(alerts)
}

// SendToSyslog sends events to a syslog server
func (sm *SIEMModule) SendToSyslog(hostValue Value, portValue Value, entriesValue Value) Value {
	host := ToString(hostValue)
	port := int(ToNumber(portValue))
	entries := sm.convertValueToEntries(entriesValue)
	
	if entries == nil {
		return false
	}
	
	err := sm.siem.SendToSyslog(host, port, entries)
	return err == nil
}

// ExportEvents exports events to various formats
func (sm *SIEMModule) ExportEvents(entriesValue Value, formatValue Value, outputPathValue Value) Value {
	entries := sm.convertValueToEntries(entriesValue)
	format := ToString(formatValue)
	outputPath := ToString(outputPathValue)
	
	if entries == nil {
		return false
	}
	
	err := sm.siem.ExportEvents(entries, format, outputPath)
	return err == nil
}

// GetSupportedFormats returns supported log formats
func (sm *SIEMModule) GetSupportedFormats() Value {
	formats := []Value{
		"syslog", "apache", "nginx", "windows", "json", "cef", "leef",
	}
	return NewArrayFromSlice(formats)
}

// AddCorrelationRule adds a custom correlation rule
func (sm *SIEMModule) AddCorrelationRule(ruleValue Value) Value {
	// Convert value to correlation rule
	ruleMap, ok := ruleValue.(*Map)
	if !ok {
		return false
	}
	
	rule := CorrelationRule{
		ID:          ToString(ruleMap.Items["id"]),
		Name:        ToString(ruleMap.Items["name"]),
		Description: ToString(ruleMap.Items["description"]),
		Severity:    ToString(ruleMap.Items["severity"]),
		Category:    ToString(ruleMap.Items["category"]),
		Enabled:     true,
		Threshold:   int(ToNumber(ruleMap.Items["threshold"])),
	}
	
	// Parse timeframe
	if timeframeStr := ToString(ruleMap.Items["timeframe"]); timeframeStr != "" {
		if duration, err := time.ParseDuration(timeframeStr); err == nil {
			rule.Timeframe = duration
		} else {
			rule.Timeframe = 5 * time.Minute // Default
		}
	}
	
	// Parse conditions
	if conditionsValue, ok := ruleMap.Items["conditions"]; ok {
		if conditionsArray, ok := conditionsValue.(*Array); ok {
			for _, condValue := range conditionsArray.Elements {
				if condMap, ok := condValue.(*Map); ok {
					condition := RuleCondition{
						Field:    ToString(condMap.Items["field"]),
						Operator: ToString(condMap.Items["operator"]),
						Value:    ToString(condMap.Items["value"]),
						Regex:    ToString(condMap.Items["regex"]),
					}
					rule.Conditions = append(rule.Conditions, condition)
				}
			}
		}
	}
	
	sm.siem.correlations = append(sm.siem.correlations, rule)
	return true
}

// GetCorrelationRules returns all correlation rules
func (sm *SIEMModule) GetCorrelationRules() Value {
	var rules []Value
	
	for _, rule := range sm.siem.correlations {
		ruleMap := NewMap()
		ruleMap.Items["id"] = rule.ID
		ruleMap.Items["name"] = rule.Name
		ruleMap.Items["description"] = rule.Description
		ruleMap.Items["severity"] = rule.Severity
		ruleMap.Items["category"] = rule.Category
		ruleMap.Items["enabled"] = rule.Enabled
		ruleMap.Items["threshold"] = float64(rule.Threshold)
		ruleMap.Items["timeframe"] = rule.Timeframe.String()
		
		// Convert conditions
		var conditions []Value
		for _, cond := range rule.Conditions {
			condMap := NewMap()
			condMap.Items["field"] = cond.Field
			condMap.Items["operator"] = cond.Operator
			condMap.Items["value"] = cond.Value
			if cond.Regex != "" {
				condMap.Items["regex"] = cond.Regex
			}
			conditions = append(conditions, condMap)
		}
		ruleMap.Items["conditions"] = NewArrayFromSlice(conditions)
		
		rules = append(rules, ruleMap)
	}
	
	return NewArrayFromSlice(rules)
}

// ParseSingleEvent parses a single log line
func (sm *SIEMModule) ParseSingleEvent(lineValue Value, formatValue Value) Value {
	line := ToString(lineValue)
	format := ToString(formatValue)
	
	parser, ok := sm.siem.parsers[format]
	if !ok {
		return nil
	}
	
	entry, err := parser.Parse(line)
	if err != nil {
		return nil
	}
	
	return sm.convertEntryToValue(entry)
}

// DetectThreats detects threats in log entries
func (sm *SIEMModule) DetectThreats(entriesValue Value) Value {
	entries := sm.convertValueToEntries(entriesValue)
	if entries == nil {
		return NewArrayFromSlice([]Value{})
	}
	
	var threats []Value
	
	for _, entry := range entries {
		indicators := sm.siem.extractThreatIndicators(entry)
		for _, indicator := range indicators {
			threatMap := NewMap()
			threatMap.Items["type"] = indicator.Type
			threatMap.Items["value"] = indicator.Value
			threatMap.Items["confidence"] = indicator.Confidence
			threatMap.Items["description"] = indicator.Description
			threatMap.Items["source_message"] = entry.Message
			threatMap.Items["timestamp"] = entry.Timestamp.Format(time.RFC3339)
			threats = append(threats, threatMap)
		}
	}
	
	return NewArrayFromSlice(threats)
}

// Helper functions to convert between Value and internal types

func (sm *SIEMModule) convertEntriesToValue(entries []*LogEntry) Value {
	var result []Value
	for _, entry := range entries {
		result = append(result, sm.convertEntryToValue(entry))
	}
	return NewArrayFromSlice(result)
}

func (sm *SIEMModule) convertEntryToValue(entry *LogEntry) Value {
	entryMap := NewMap()
	entryMap.Items["timestamp"] = entry.Timestamp.Format(time.RFC3339)
	entryMap.Items["level"] = entry.Level
	entryMap.Items["source"] = entry.Source
	entryMap.Items["host"] = entry.Host
	entryMap.Items["message"] = entry.Message
	entryMap.Items["event_type"] = entry.EventType
	entryMap.Items["severity"] = float64(entry.Severity)
	entryMap.Items["category"] = entry.Category
	entryMap.Items["normalized"] = entry.Normalized
	
	// Convert fields
	fieldsMap := NewMap()
	for key, value := range entry.Fields {
		fieldsMap.Items[key] = value
	}
	entryMap.Items["fields"] = fieldsMap
	
	return entryMap
}

func (sm *SIEMModule) convertValueToEntries(value Value) []*LogEntry {
	array, ok := value.(*Array)
	if !ok {
		return nil
	}
	
	var entries []*LogEntry
	for _, item := range array.Elements {
		entryMap, ok := item.(*Map)
		if !ok {
			continue
		}
		
		entry := &LogEntry{
			Level:     ToString(entryMap.Items["level"]),
			Source:    ToString(entryMap.Items["source"]),
			Host:      ToString(entryMap.Items["host"]),
			Message:   ToString(entryMap.Items["message"]),
			EventType: ToString(entryMap.Items["event_type"]),
			Severity:  int(ToNumber(entryMap.Items["severity"])),
			Category:  ToString(entryMap.Items["category"]),
			Fields:    make(map[string]string),
		}
		
		// Parse timestamp
		if tsStr := ToString(entryMap.Items["timestamp"]); tsStr != "" {
			if ts, err := time.Parse(time.RFC3339, tsStr); err == nil {
				entry.Timestamp = ts
			}
		}
		
		// Parse fields
		if fieldsValue, ok := entryMap.Items["fields"]; ok {
			if fieldsMap, ok := fieldsValue.(*Map); ok {
				for key, value := range fieldsMap.Items {
					entry.Fields[key] = ToString(value)
				}
			}
		}
		
		entries = append(entries, entry)
	}
	
	return entries
}

func (sm *SIEMModule) convertStatsToValue(stats *EventStats) Value {
	statsMap := NewMap()
	statsMap.Items["total_events"] = float64(stats.TotalEvents)
	statsMap.Items["alerts_generated"] = float64(stats.AlertsGenerated)
	
	// Time range
	if !stats.TimeRange[0].IsZero() && !stats.TimeRange[1].IsZero() {
		timeRangeArray := NewArrayFromSlice([]Value{
			stats.TimeRange[0].Format(time.RFC3339),
			stats.TimeRange[1].Format(time.RFC3339),
		})
		statsMap.Items["time_range"] = timeRangeArray
	}
	
	// Events by source
	sourceMap := NewMap()
	for source, count := range stats.EventsBySource {
		sourceMap.Items[source] = float64(count)
	}
	statsMap.Items["events_by_source"] = sourceMap
	
	// Events by level
	levelMap := NewMap()
	for level, count := range stats.EventsByLevel {
		levelMap.Items[level] = float64(count)
	}
	statsMap.Items["events_by_level"] = levelMap
	
	// Events by type
	typeMap := NewMap()
	for eventType, count := range stats.EventsByType {
		typeMap.Items[eventType] = float64(count)
	}
	statsMap.Items["events_by_type"] = typeMap
	
	// Top sources
	var topSources []Value
	for _, source := range stats.TopSources {
		sourceStats := NewMap()
		sourceStats.Items["source"] = source.Source
		sourceStats.Items["count"] = float64(source.Count)
		sourceStats.Items["level"] = source.Level
		topSources = append(topSources, sourceStats)
	}
	statsMap.Items["top_sources"] = NewArrayFromSlice(topSources)
	
	// Threat indicators
	var indicators []Value
	for _, indicator := range stats.ThreatIndicators {
		indicatorMap := NewMap()
		indicatorMap.Items["type"] = indicator.Type
		indicatorMap.Items["value"] = indicator.Value
		indicatorMap.Items["confidence"] = indicator.Confidence
		indicatorMap.Items["count"] = float64(indicator.Count)
		indicatorMap.Items["description"] = indicator.Description
		indicatorMap.Items["first_seen"] = indicator.FirstSeen.Format(time.RFC3339)
		indicatorMap.Items["last_seen"] = indicator.LastSeen.Format(time.RFC3339)
		indicators = append(indicators, indicatorMap)
	}
	statsMap.Items["threat_indicators"] = NewArrayFromSlice(indicators)
	
	return statsMap
}

func (sm *SIEMModule) convertAlertsToValue(alerts []*Alert) Value {
	var result []Value
	
	for _, alert := range alerts {
		alertMap := NewMap()
		alertMap.Items["id"] = alert.ID
		alertMap.Items["rule_id"] = alert.RuleID
		alertMap.Items["timestamp"] = alert.Timestamp.Format(time.RFC3339)
		alertMap.Items["severity"] = alert.Severity
		alertMap.Items["title"] = alert.Title
		alertMap.Items["description"] = alert.Description
		alertMap.Items["source"] = alert.Source
		alertMap.Items["category"] = alert.Category
		alertMap.Items["status"] = alert.Status
		
		// Convert events
		var events []Value
		for _, event := range alert.Events {
			events = append(events, sm.convertEntryToValue(event))
		}
		alertMap.Items["events"] = NewArrayFromSlice(events)
		
		// Convert indicators
		var indicators []Value
		for _, indicator := range alert.Indicators {
			indicators = append(indicators, indicator)
		}
		alertMap.Items["indicators"] = NewArrayFromSlice(indicators)
		
		// Convert metadata
		metadataMap := NewMap()
		for key, value := range alert.Metadata {
			metadataMap.Items[key] = value
		}
		alertMap.Items["metadata"] = metadataMap
		
		result = append(result, alertMap)
	}
	
	return NewArrayFromSlice(result)
}