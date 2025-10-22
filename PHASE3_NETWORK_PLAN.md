# Phase 3: Network Infrastructure - Implementation Plan

**Date**: 2025-10-22
**Status**: 🔄 **IN PROGRESS**

---

## Objective

Implement comprehensive network infrastructure and security capabilities for Sentra, enabling:
- Firewall management
- Network traffic monitoring
- HTTP/HTTPS proxy servers
- Reverse proxy
- IDS (Intrusion Detection System)
- Packet capture and analysis
- Port scanning and network discovery

---

## Architecture Design

### Package Structure

```
internal/network/
├── firewall.go       - Firewall rules and management
├── proxy.go          - HTTP/HTTPS proxy server
├── reverse_proxy.go  - Reverse proxy implementation
├── monitor.go        - Network traffic monitoring
├── ids.go            - Intrusion Detection System
├── capture.go        - Packet capture and analysis
├── scanner.go        - Port scanning and discovery
└── types.go          - Common network types
```

---

## Functions to Implement (30+ functions)

### 1. Firewall Functions (8 functions)

```sentra
// Firewall rule management
firewall_create_rule(chain, protocol, src_ip, dst_ip, src_port, dst_port, action)
firewall_delete_rule(rule_id)
firewall_list_rules(chain)
firewall_enable()
firewall_disable()
firewall_block_ip(ip_address)
firewall_allow_ip(ip_address)
firewall_get_stats()
```

**Use case**:
```sentra
// Block suspicious IP
firewall_block_ip("192.168.1.100")

// Create custom rule
let rule = firewall_create_rule("INPUT", "tcp", "any", "192.168.1.0/24", "any", 22, "ACCEPT")
```

### 2. HTTP/HTTPS Proxy Functions (6 functions)

```sentra
// Proxy server
proxy_start(port, options)
proxy_stop(server_id)
proxy_set_upstream(server_id, upstream_url)
proxy_add_filter(server_id, filter_func)
proxy_get_stats(server_id)
proxy_get_logs(server_id, limit)
```

**Use case**:
```sentra
// Start filtering proxy
let proxy = proxy_start(8080, {
    "log_requests": true,
    "filter_malicious": true
})

// Add custom filter
proxy_add_filter(proxy, fn(req) {
    if req["path"] == "/admin" {
        return {"block": true, "reason": "Unauthorized"}
    }
    return {"block": false}
})
```

### 3. Reverse Proxy Functions (5 functions)

```sentra
// Reverse proxy
reverse_proxy_create(port, backends)
reverse_proxy_add_backend(proxy_id, backend_url, weight)
reverse_proxy_remove_backend(proxy_id, backend_id)
reverse_proxy_set_load_balancing(proxy_id, algorithm)
reverse_proxy_get_health(proxy_id)
```

**Use case**:
```sentra
// Load balancer
let rproxy = reverse_proxy_create(80, [
    "http://backend1:8080",
    "http://backend2:8080",
    "http://backend3:8080"
])

reverse_proxy_set_load_balancing(rproxy, "round_robin")
```

### 4. IDS Functions (7 functions)

```sentra
// Intrusion Detection
ids_start(interface, rules)
ids_stop(ids_id)
ids_add_rule(ids_id, rule)
ids_get_alerts(ids_id, severity, limit)
ids_get_stats(ids_id)
ids_block_threat(threat_id)
ids_whitelist_ip(ip_address)
```

**Use case**:
```sentra
// Start IDS monitoring
let ids = ids_start("eth0", {
    "detect_port_scan": true,
    "detect_dos": true,
    "detect_sql_injection": true
})

// Get critical alerts
let alerts = ids_get_alerts(ids, "critical", 10)
```

### 5. Network Monitoring Functions (8 functions)

```sentra
// Traffic monitoring
monitor_start(interface)
monitor_stop(monitor_id)
monitor_get_bandwidth(monitor_id)
monitor_get_connections(monitor_id)
monitor_get_protocols(monitor_id)
monitor_get_top_talkers(monitor_id, limit)
monitor_get_flows(monitor_id, filter)
monitor_export_pcap(monitor_id, filename)
```

**Use case**:
```sentra
// Monitor network activity
let mon = monitor_start("eth0")
let bandwidth = monitor_get_bandwidth(mon)
log("Download: " + str(bandwidth["rx_mbps"]) + " Mbps")
log("Upload: " + str(bandwidth["tx_mbps"]) + " Mbps")

// Top bandwidth consumers
let top = monitor_get_top_talkers(mon, 5)
```

### 6. Packet Capture Functions (5 functions)

```sentra
// Packet capture
capture_start(interface, filter)
capture_stop(capture_id)
capture_get_packets(capture_id, count)
capture_analyze_packet(packet)
capture_save_pcap(capture_id, filename)
```

**Use case**:
```sentra
// Capture HTTP traffic
let cap = capture_start("eth0", "tcp port 80")
let packets = capture_get_packets(cap, 100)

for packet in packets {
    let analysis = capture_analyze_packet(packet)
    log("Source: " + analysis["src_ip"] + ":" + str(analysis["src_port"]))
}
```

### 7. Port Scanning Functions (5 functions)

```sentra
// Port scanning & discovery
scan_ports(target, port_range)
scan_network(network_cidr)
scan_service_version(target, port)
scan_os_fingerprint(target)
scan_vulnerabilities(target)
```

**Use case**:
```sentra
// Scan target
let open_ports = scan_ports("192.168.1.100", "1-1000")
log("Open ports: " + str(open_ports))

// Network discovery
let hosts = scan_network("192.168.1.0/24")
for host in hosts {
    log("Found: " + host["ip"] + " (" + host["hostname"] + ")")
}
```

---

## Technical Implementation

### 1. Firewall (using iptables/nftables on Linux, Windows Firewall API on Windows)

```go
// internal/network/firewall.go
package network

import (
    "fmt"
    "os/exec"
)

type FirewallRule struct {
    ID       string
    Chain    string
    Protocol string
    SrcIP    string
    DstIP    string
    SrcPort  string
    DstPort  string
    Action   string
}

func CreateFirewallRule(chain, protocol, srcIP, dstIP, srcPort, dstPort, action string) (*FirewallRule, error) {
    // Use iptables on Linux or Windows Firewall API
    rule := &FirewallRule{
        ID:       generateRuleID(),
        Chain:    chain,
        Protocol: protocol,
        SrcIP:    srcIP,
        DstIP:    dstIP,
        SrcPort:  srcPort,
        DstPort:  dstPort,
        Action:   action,
    }

    // Execute firewall command
    return rule, nil
}
```

### 2. HTTP/HTTPS Proxy (using net/http)

```go
// internal/network/proxy.go
package network

import (
    "net/http"
    "net/http/httputil"
)

type ProxyServer struct {
    ID       string
    Port     int
    Server   *http.Server
    Filters  []ProxyFilter
    Stats    *ProxyStats
}

type ProxyFilter func(*http.Request) (block bool, reason string)

func StartProxy(port int, options map[string]interface{}) (*ProxyServer, error) {
    proxy := &ProxyServer{
        ID:   generateProxyID(),
        Port: port,
    }

    handler := http.HandlerFunc(proxy.handleRequest)
    proxy.Server = &http.Server{
        Addr:    fmt.Sprintf(":%d", port),
        Handler: handler,
    }

    go proxy.Server.ListenAndServe()
    return proxy, nil
}
```

### 3. IDS (pattern matching + anomaly detection)

```go
// internal/network/ids.go
package network

type IDS struct {
    ID        string
    Interface string
    Rules     []IDSRule
    Alerts    []*Alert
}

type IDSRule struct {
    Name      string
    Pattern   string
    Severity  string
    Action    string
}

type Alert struct {
    Timestamp int64
    Severity  string
    Message   string
    SrcIP     string
    DstIP     string
}

func StartIDS(iface string, rules map[string]interface{}) (*IDS, error) {
    ids := &IDS{
        ID:        generateIDSID(),
        Interface: iface,
    }

    // Start packet analysis
    go ids.monitor()
    return ids, nil
}
```

### 4. Network Monitor (using gopacket/pcap)

```go
// internal/network/monitor.go
package network

type NetworkMonitor struct {
    ID        string
    Interface string
    Stats     *NetworkStats
}

type NetworkStats struct {
    RxBytes   uint64
    TxBytes   uint64
    RxPackets uint64
    TxPackets uint64
}

func StartMonitor(iface string) (*NetworkMonitor, error) {
    mon := &NetworkMonitor{
        ID:        generateMonitorID(),
        Interface: iface,
        Stats:     &NetworkStats{},
    }

    go mon.collect()
    return mon, nil
}
```

---

## Dependencies

Add to `go.mod`:
```
github.com/google/gopacket v1.1.19
github.com/google/gopacket/pcap
golang.org/x/net/proxy
```

---

## Security Considerations

1. **Privilege Requirements**: Some operations (firewall, packet capture) require elevated privileges
2. **Rate Limiting**: Implement rate limits for scanning operations
3. **Logging**: Comprehensive logging for security auditing
4. **Authentication**: Proxy servers should support authentication
5. **TLS/SSL**: HTTPS proxy support with certificate management

---

## Testing Strategy

1. **Unit Tests**: Test individual functions
2. **Integration Tests**: Test complete workflows
3. **Security Tests**: Verify firewall rules work correctly
4. **Performance Tests**: Monitor resource usage

---

## Timeline

- **Firewall Functions**: 2 hours
- **Proxy Functions**: 3 hours
- **IDS Functions**: 3 hours
- **Monitoring Functions**: 2 hours
- **Packet Capture**: 2 hours
- **Port Scanning**: 2 hours
- **Integration & Testing**: 3 hours

**Total Estimated Time**: 17 hours

---

## Success Criteria

✅ All 30+ network functions implemented
✅ Firewall can block/allow IPs
✅ Proxy can filter and forward traffic
✅ IDS can detect common attacks
✅ Monitor can show real-time network stats
✅ Packet capture can save PCAP files
✅ Port scanner can discover hosts/services
✅ All tests passing
✅ Documentation complete

---

*Phase 3 Plan - Ready to implement*
