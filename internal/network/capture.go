package network

import (
	"fmt"
	"time"
)

// Packet capture implementation

// StartCapture starts packet capture on an interface
func StartCapture(iface, filter string) (*PacketCapture, error) {
	capture := &PacketCapture{
		ID:        generateID("capture"),
		Interface: iface,
		Filter:    filter,
		Packets:   make([]*Packet, 0),
		Running:   true,
	}

	// Store the capture session
	registryMutex.Lock()
	captures[capture.ID] = capture
	registryMutex.Unlock()

	// Start capture in background
	go capture.capture()

	return capture, nil
}

// capture runs the packet capture loop
func (pc *PacketCapture) capture() {
	// In a real implementation, this would use gopacket/pcap
	// For now, it's a placeholder that simulates packet capture
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for pc.Running {
		select {
		case <-ticker.C:
			// Simulate packet capture
			// Real implementation would use pcap library
		}
	}
}

// StopCapture stops a packet capture session
func StopCapture(captureID string) error {
	registryMutex.Lock()
	defer registryMutex.Unlock()

	capture, exists := captures[captureID]
	if !exists {
		return fmt.Errorf("capture '%s' not found", captureID)
	}

	capture.mu.Lock()
	capture.Running = false
	capture.mu.Unlock()

	delete(captures, captureID)
	return nil
}

// GetPackets returns captured packets
func GetPackets(captureID string, count int) ([]*Packet, error) {
	registryMutex.RLock()
	capture, exists := captures[captureID]
	registryMutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("capture '%s' not found", captureID)
	}

	capture.mu.RLock()
	defer capture.mu.RUnlock()

	// Return up to 'count' packets
	if count <= 0 || count > len(capture.Packets) {
		count = len(capture.Packets)
	}

	return capture.Packets[:count], nil
}

// AnalyzePacket analyzes a packet and returns detailed information
func AnalyzePacket(packet *Packet) map[string]interface{} {
	analysis := map[string]interface{}{
		"timestamp": packet.Timestamp.Unix(),
		"length":    packet.Length,
		"src_ip":    packet.SrcIP,
		"dst_ip":    packet.DstIP,
		"src_port":  packet.SrcPort,
		"dst_port":  packet.DstPort,
		"protocol":  packet.Protocol,
	}

	// In a real implementation, would include:
	// - Layer analysis (Ethernet, IP, TCP/UDP)
	// - Payload inspection
	// - Protocol-specific details
	// - Anomaly detection

	return analysis
}

// SavePCAP saves captured packets to a PCAP file
func SavePCAP(captureID, filename string) error {
	registryMutex.RLock()
	capture, exists := captures[captureID]
	registryMutex.RUnlock()

	if !exists {
		return fmt.Errorf("capture '%s' not found", captureID)
	}

	capture.mu.RLock()
	defer capture.mu.RUnlock()

	// In a real implementation, would write PCAP format
	// For now, placeholder
	return nil
}

// CaptureToMap converts a PacketCapture to a map for VM
func CaptureToMap(capture *PacketCapture) map[string]interface{} {
	capture.mu.RLock()
	defer capture.mu.RUnlock()

	return map[string]interface{}{
		"id":            capture.ID,
		"interface":     capture.Interface,
		"filter":        capture.Filter,
		"running":       capture.Running,
		"packets_count": len(capture.Packets),
	}
}

// PacketToMap converts a Packet to a map for VM
func PacketToMap(packet *Packet) map[string]interface{} {
	return map[string]interface{}{
		"timestamp": packet.Timestamp.Unix(),
		"length":    packet.Length,
		"src_ip":    packet.SrcIP,
		"dst_ip":    packet.DstIP,
		"src_port":  packet.SrcPort,
		"dst_port":  packet.DstPort,
		"protocol":  packet.Protocol,
	}
}
