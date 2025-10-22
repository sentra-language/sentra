package network

import (
	"fmt"
	"time"
)

// Firewall management functions

// CreateFirewallRule creates a new firewall rule
func CreateFirewallRule(chain, protocol, srcIP, dstIP, srcPort, dstPort, action string) (*FirewallRule, error) {
	rule := &FirewallRule{
		ID:       generateID("fw-rule"),
		Chain:    chain,
		Protocol: protocol,
		SrcIP:    srcIP,
		DstIP:    dstIP,
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Action:   action,
		Created:  time.Now(),
	}

	// Store the rule
	registryMutex.Lock()
	firewallRules[rule.ID] = rule
	registryMutex.Unlock()

	return rule, nil
}

// DeleteFirewallRule deletes a firewall rule by ID
func DeleteFirewallRule(ruleID string) error {
	registryMutex.Lock()
	defer registryMutex.Unlock()

	if _, exists := firewallRules[ruleID]; !exists {
		return fmt.Errorf("firewall rule '%s' not found", ruleID)
	}

	delete(firewallRules, ruleID)
	return nil
}

// ListFirewallRules returns all firewall rules for a given chain
func ListFirewallRules(chain string) []*FirewallRule {
	registryMutex.RLock()
	defer registryMutex.RUnlock()

	var rules []*FirewallRule
	for _, rule := range firewallRules {
		if chain == "" || rule.Chain == chain {
			rules = append(rules, rule)
		}
	}

	return rules
}

// BlockIP creates a rule to block an IP address
func BlockIP(ipAddress string) (*FirewallRule, error) {
	return CreateFirewallRule("INPUT", "all", ipAddress, "any", "any", "any", "DROP")
}

// AllowIP creates a rule to allow an IP address
func AllowIP(ipAddress string) (*FirewallRule, error) {
	return CreateFirewallRule("INPUT", "all", ipAddress, "any", "any", "any", "ACCEPT")
}

// GetFirewallStats returns firewall statistics
func GetFirewallStats() *FirewallStats {
	registryMutex.RLock()
	defer registryMutex.RUnlock()

	// In a real implementation, these would track actual packet counts
	return &FirewallStats{
		RulesCount:     len(firewallRules),
		PacketsBlocked: 0,
		PacketsAllowed: 0,
		LastUpdate:     time.Now(),
	}
}

// EnableFirewall enables the firewall (placeholder)
func EnableFirewall() error {
	// In a real implementation, this would enable iptables/nftables
	return nil
}

// DisableFirewall disables the firewall (placeholder)
func DisableFirewall() error {
	// In a real implementation, this would disable iptables/nftables
	return nil
}

// RuleToMap converts a FirewallRule to a map for VM
func RuleToMap(rule *FirewallRule) map[string]interface{} {
	return map[string]interface{}{
		"id":       rule.ID,
		"chain":    rule.Chain,
		"protocol": rule.Protocol,
		"src_ip":   rule.SrcIP,
		"dst_ip":   rule.DstIP,
		"src_port": rule.SrcPort,
		"dst_port": rule.DstPort,
		"action":   rule.Action,
		"created":  rule.Created.Unix(),
	}
}

// StatsToMap converts FirewallStats to a map for VM
func FirewallStatsToMap(stats *FirewallStats) map[string]interface{} {
	return map[string]interface{}{
		"rules_count":     stats.RulesCount,
		"packets_blocked": stats.PacketsBlocked,
		"packets_allowed": stats.PacketsAllowed,
		"last_update":     stats.LastUpdate.Unix(),
	}
}
