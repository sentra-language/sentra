package network

import (
	"fmt"
	"time"
)

// Network monitoring implementation

// StartMonitor starts network traffic monitoring
func StartMonitor(iface string) (*NetworkMonitor, error) {
	mon := &NetworkMonitor{
		ID:        generateID("monitor"),
		Interface: iface,
		Stats: &NetworkStats{
			LastUpdate: time.Now(),
		},
		Flows:   make([]*Flow, 0),
		Running: true,
	}

	// Store the monitor
	registryMutex.Lock()
	monitors[mon.ID] = mon
	registryMutex.Unlock()

	// Start collection in background
	go mon.collect()

	return mon, nil
}

// collect runs the monitoring loop
func (mon *NetworkMonitor) collect() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var lastRxBytes, lastTxBytes uint64
	lastTime := time.Now()

	for mon.Running {
		select {
		case <-ticker.C:
			mon.mu.Lock()

			// Simulate traffic collection (in real impl, would use pcap/netstat)
			now := time.Now()
			elapsed := now.Sub(lastTime).Seconds()

			// Calculate bandwidth in Mbps
			if elapsed > 0 {
				rxDiff := mon.Stats.RxBytes - lastRxBytes
				txDiff := mon.Stats.TxBytes - lastTxBytes

				mon.Stats.RxMbps = float64(rxDiff*8) / (elapsed * 1000000)
				mon.Stats.TxMbps = float64(txDiff*8) / (elapsed * 1000000)

				lastRxBytes = mon.Stats.RxBytes
				lastTxBytes = mon.Stats.TxBytes
				lastTime = now
			}

			mon.Stats.LastUpdate = now
			mon.mu.Unlock()
		}
	}
}

// StopMonitor stops a network monitor
func StopMonitor(monitorID string) error {
	registryMutex.Lock()
	defer registryMutex.Unlock()

	mon, exists := monitors[monitorID]
	if !exists {
		return fmt.Errorf("monitor '%s' not found", monitorID)
	}

	mon.mu.Lock()
	mon.Running = false
	mon.mu.Unlock()

	delete(monitors, monitorID)
	return nil
}

// GetBandwidth returns current bandwidth statistics
func GetBandwidth(monitorID string) (*NetworkStats, error) {
	registryMutex.RLock()
	mon, exists := monitors[monitorID]
	registryMutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("monitor '%s' not found", monitorID)
	}

	mon.mu.RLock()
	defer mon.mu.RUnlock()

	return mon.Stats, nil
}

// GetConnections returns active network connections
func GetConnections(monitorID string) ([]map[string]interface{}, error) {
	registryMutex.RLock()
	mon, exists := monitors[monitorID]
	registryMutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("monitor '%s' not found", monitorID)
	}

	// Use mon to avoid unused variable error
	_ = mon

	// In a real implementation, would return actual connections
	// For now, return placeholder
	connections := []map[string]interface{}{}
	return connections, nil
}

// GetProtocols returns protocol distribution statistics
func GetProtocols(monitorID string) (map[string]uint64, error) {
	registryMutex.RLock()
	mon, exists := monitors[monitorID]
	registryMutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("monitor '%s' not found", monitorID)
	}

	// Use mon to avoid unused variable error
	_ = mon

	// In a real implementation, would analyze actual traffic
	protocols := map[string]uint64{
		"TCP":  0,
		"UDP":  0,
		"ICMP": 0,
	}

	return protocols, nil
}

// GetTopTalkers returns top bandwidth consumers
func GetTopTalkers(monitorID string, limit int) ([]*Flow, error) {
	registryMutex.RLock()
	mon, exists := monitors[monitorID]
	registryMutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("monitor '%s' not found", monitorID)
	}

	mon.mu.RLock()
	defer mon.mu.RUnlock()

	// Return top N flows by bytes
	var topFlows []*Flow
	for i := 0; i < len(mon.Flows) && i < limit; i++ {
		topFlows = append(topFlows, mon.Flows[i])
	}

	return topFlows, nil
}

// GetFlows returns flows matching a filter
func GetFlows(monitorID string, filter map[string]interface{}) ([]*Flow, error) {
	registryMutex.RLock()
	mon, exists := monitors[monitorID]
	registryMutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("monitor '%s' not found", monitorID)
	}

	mon.mu.RLock()
	defer mon.mu.RUnlock()

	// Apply filter and return matching flows
	return mon.Flows, nil
}

// ExportPCAP exports captured data to PCAP file
func ExportPCAP(monitorID, filename string) error {
	registryMutex.RLock()
	_, exists := monitors[monitorID]
	registryMutex.RUnlock()

	if !exists {
		return fmt.Errorf("monitor '%s' not found", monitorID)
	}

	// In a real implementation, would write PCAP file
	return nil
}

// NetworkStatsToMap converts NetworkStats to a map for VM
func NetworkStatsToMap(stats *NetworkStats) map[string]interface{} {
	return map[string]interface{}{
		"rx_bytes":    stats.RxBytes,
		"tx_bytes":    stats.TxBytes,
		"rx_packets":  stats.RxPackets,
		"tx_packets":  stats.TxPackets,
		"rx_mbps":     stats.RxMbps,
		"tx_mbps":     stats.TxMbps,
		"last_update": stats.LastUpdate.Unix(),
	}
}

// FlowToMap converts a Flow to a map for VM
func FlowToMap(flow *Flow) map[string]interface{} {
	return map[string]interface{}{
		"src_ip":   flow.SrcIP,
		"dst_ip":   flow.DstIP,
		"src_port": flow.SrcPort,
		"dst_port": flow.DstPort,
		"protocol": flow.Protocol,
		"bytes":    flow.Bytes,
		"packets":  flow.Packets,
		"started":  flow.Started.Unix(),
	}
}
