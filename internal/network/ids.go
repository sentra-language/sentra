package network

import (
	"fmt"
	"strings"
	"time"
)

// Intrusion Detection System implementation

// StartIDS starts an IDS monitoring system
func StartIDS(iface string, rules map[string]interface{}) (*IDS, error) {
	ids := &IDS{
		ID:        generateID("ids"),
		Interface: iface,
		Rules:     make([]*IDSRule, 0),
		Alerts:    make([]*Alert, 0),
		Running:   true,
		Stats: &IDSStats{
			LastAlert: time.Now(),
		},
	}

	// Add default rules based on options
	if detectPortScan, ok := rules["detect_port_scan"].(bool); ok && detectPortScan {
		ids.Rules = append(ids.Rules, &IDSRule{
			ID:       generateID("rule"),
			Name:     "Port Scan Detection",
			Pattern:  "port_scan",
			Severity: "high",
			Action:   "alert",
			Enabled:  true,
		})
	}

	if detectDos, ok := rules["detect_dos"].(bool); ok && detectDos {
		ids.Rules = append(ids.Rules, &IDSRule{
			ID:       generateID("rule"),
			Name:     "DoS Attack Detection",
			Pattern:  "dos_attack",
			Severity: "critical",
			Action:   "block",
			Enabled:  true,
		})
	}

	if detectSQLi, ok := rules["detect_sql_injection"].(bool); ok && detectSQLi {
		ids.Rules = append(ids.Rules, &IDSRule{
			ID:       generateID("rule"),
			Name:     "SQL Injection Detection",
			Pattern:  "sql_injection",
			Severity: "high",
			Action:   "alert",
			Enabled:  true,
		})
	}

	// Store the IDS
	registryMutex.Lock()
	idsInstances[ids.ID] = ids
	registryMutex.Unlock()

	// Start monitoring in background
	go ids.monitor()

	return ids, nil
}

// monitor runs the IDS monitoring loop
func (ids *IDS) monitor() {
	// In a real implementation, this would analyze network traffic
	// For now, it's a placeholder
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for ids.Running {
		select {
		case <-ticker.C:
			ids.mu.Lock()
			ids.Stats.PacketsAnalyzed++
			ids.mu.Unlock()
		}
	}
}

// StopIDS stops an IDS instance
func StopIDS(idsID string) error {
	registryMutex.Lock()
	defer registryMutex.Unlock()

	ids, exists := idsInstances[idsID]
	if !exists {
		return fmt.Errorf("IDS '%s' not found", idsID)
	}

	ids.mu.Lock()
	ids.Running = false
	ids.mu.Unlock()

	delete(idsInstances, idsID)
	return nil
}

// AddIDSRule adds a new detection rule to an IDS
func AddIDSRule(idsID string, rule *IDSRule) error {
	registryMutex.RLock()
	ids, exists := idsInstances[idsID]
	registryMutex.RUnlock()

	if !exists {
		return fmt.Errorf("IDS '%s' not found", idsID)
	}

	ids.mu.Lock()
	ids.Rules = append(ids.Rules, rule)
	ids.mu.Unlock()

	return nil
}

// GetIDSAlerts returns alerts filtered by severity
func GetIDSAlerts(idsID, severity string, limit int) ([]*Alert, error) {
	registryMutex.RLock()
	ids, exists := idsInstances[idsID]
	registryMutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("IDS '%s' not found", idsID)
	}

	ids.mu.RLock()
	defer ids.mu.RUnlock()

	var filtered []*Alert
	for _, alert := range ids.Alerts {
		if severity == "" || strings.EqualFold(alert.Severity, severity) {
			filtered = append(filtered, alert)
			if len(filtered) >= limit && limit > 0 {
				break
			}
		}
	}

	return filtered, nil
}

// GetIDSStats returns IDS statistics
func GetIDSStats(idsID string) (*IDSStats, error) {
	registryMutex.RLock()
	ids, exists := idsInstances[idsID]
	registryMutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("IDS '%s' not found", idsID)
	}

	ids.mu.RLock()
	defer ids.mu.RUnlock()

	return ids.Stats, nil
}

// BlockThreat blocks a specific threat by ID
func BlockThreat(threatID string) error {
	// In a real implementation, this would block the threat
	// For now, it's a placeholder
	return nil
}

// WhitelistIP adds an IP to the IDS whitelist
func WhitelistIP(ipAddress string) error {
	// In a real implementation, this would add to whitelist
	return nil
}

// CreateAlert creates a new alert (helper function)
func (ids *IDS) CreateAlert(severity, message, srcIP, dstIP, protocol string) {
	alert := &Alert{
		ID:        generateID("alert"),
		Timestamp: time.Now(),
		Severity:  severity,
		Message:   message,
		SrcIP:     srcIP,
		DstIP:     dstIP,
		Protocol:  protocol,
		Details:   make(map[string]interface{}),
	}

	ids.mu.Lock()
	ids.Alerts = append(ids.Alerts, alert)
	ids.Stats.AlertsGenerated++
	ids.Stats.LastAlert = time.Now()
	ids.mu.Unlock()
}

// IDSToMap converts an IDS to a map for VM
func IDSToMap(ids *IDS) map[string]interface{} {
	ids.mu.RLock()
	defer ids.mu.RUnlock()

	rules := make([]map[string]interface{}, 0)
	for _, rule := range ids.Rules {
		rules = append(rules, IDSRuleToMap(rule))
	}

	return map[string]interface{}{
		"id":        ids.ID,
		"interface": ids.Interface,
		"running":   ids.Running,
		"rules":     rules,
		"alerts_count": len(ids.Alerts),
	}
}

// IDSRuleToMap converts an IDSRule to a map for VM
func IDSRuleToMap(rule *IDSRule) map[string]interface{} {
	return map[string]interface{}{
		"id":       rule.ID,
		"name":     rule.Name,
		"pattern":  rule.Pattern,
		"severity": rule.Severity,
		"action":   rule.Action,
		"enabled":  rule.Enabled,
	}
}

// AlertToMap converts an Alert to a map for VM
func AlertToMap(alert *Alert) map[string]interface{} {
	return map[string]interface{}{
		"id":        alert.ID,
		"timestamp": alert.Timestamp.Unix(),
		"severity":  alert.Severity,
		"message":   alert.Message,
		"src_ip":    alert.SrcIP,
		"dst_ip":    alert.DstIP,
		"protocol":  alert.Protocol,
	}
}

// IDSStatsToMap converts IDSStats to a map for VM
func IDSStatsToMap(stats *IDSStats) map[string]interface{} {
	return map[string]interface{}{
		"packets_analyzed":  stats.PacketsAnalyzed,
		"alerts_generated":  stats.AlertsGenerated,
		"threats_blocked":   stats.ThreatsBlocked,
		"last_alert":        stats.LastAlert.Unix(),
	}
}
