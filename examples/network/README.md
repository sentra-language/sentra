# Network Security Examples

This directory contains comprehensive examples demonstrating Sentra's network infrastructure and security capabilities.

## Examples

### 1. IDS System (`ids_system.sn`)

Complete Intrusion Detection System demonstrating:
- Real-time threat detection
- Custom detection rules
- Automated IP blocking
- Security alerting
- Integration with firewall for auto-response

**Run:**
```bash
./sentra run examples/network/ids_system.sn
```

**Features:**
- Port scan detection
- DoS attack detection
- SQL injection detection
- Brute force detection
- Automatic threat blocking
- Real-time statistics

### 2. Network Scanner (`network_scanner.sn`)

Comprehensive network security scanner demonstrating:
- Network host discovery
- Port scanning
- Service identification
- OS fingerprinting
- Vulnerability scanning

**Run:**
```bash
./sentra run examples/network/network_scanner.sn
```

**Features:**
- CIDR network scanning
- Configurable port ranges
- Service version detection
- CVE vulnerability checking
- Detailed scan reports
- Security recommendations

### 3. Firewall Manager (`firewall_manager.sn`)

Full-featured firewall management system demonstrating:
- Firewall rule creation and management
- IP blocking and whitelisting
- Policy configuration
- Real-time statistics
- Traffic monitoring

**Run:**
```bash
./sentra run examples/network/firewall_manager.sn
```

**Features:**
- Rule-based filtering
- Protocol-specific rules
- Subnet blocking
- Trusted IP whitelisting
- Traffic statistics
- Real-time monitoring

### 4. Network Monitor Dashboard (`network_monitor_dashboard.sn`)

Real-time network traffic monitoring dashboard demonstrating:
- Bandwidth monitoring
- Protocol distribution analysis
- Flow tracking
- Packet capture
- Top talker identification

**Run:**
```bash
./sentra run examples/network/network_monitor_dashboard.sn
```

**Features:**
- Real-time bandwidth graphs
- Protocol breakdown (TCP/UDP/ICMP)
- Top bandwidth consumers
- Active connection tracking
- Flow analysis
- PCAP export

### 5. Proxy Server (`proxy_server.sn`)

HTTP/HTTPS forward proxy server demonstrating:
- Request filtering
- Content caching
- Access logging
- Statistics tracking
- Upstream proxy chaining

**Run:**
```bash
./sentra run examples/network/proxy_server.sn
```

**Features:**
- Ad and tracker blocking
- Malware domain filtering
- Rate limiting
- Request logging
- Cache management
- Bandwidth statistics

## Real-World Use Cases

### Use Case 1: Complete Network Security Monitoring

Combine IDS, firewall, and network monitor for comprehensive security:

```bash
# Terminal 1: Start IDS
./sentra run examples/network/ids_system.sn

# Terminal 2: Start firewall manager
./sentra run examples/network/firewall_manager.sn

# Terminal 3: Start network monitor
./sentra run examples/network/network_monitor_dashboard.sn
```

### Use Case 2: Security Assessment

Perform a complete security audit:

```bash
# Run network scanner
./sentra run examples/network/network_scanner.sn

# Review results and configure firewall accordingly
./sentra run examples/network/firewall_manager.sn
```

### Use Case 3: Traffic Filtering and Analysis

Set up a secure proxy with monitoring:

```bash
# Terminal 1: Start proxy server
./sentra run examples/network/proxy_server.sn

# Terminal 2: Monitor traffic
./sentra run examples/network/network_monitor_dashboard.sn
```

## Network Functions Used

These examples demonstrate all 44 network infrastructure functions:

### Firewall (8 functions)
- `firewall_create_rule()` - Create custom firewall rules
- `firewall_delete_rule()` - Remove rules
- `firewall_list_rules()` - List all active rules
- `firewall_block_ip()` - Block IP addresses
- `firewall_allow_ip()` - Whitelist IP addresses
- `firewall_get_stats()` - Get traffic statistics
- `firewall_clear_rules()` - Clear all rules
- `firewall_set_default_policy()` - Set default policies

### HTTP/HTTPS Proxy (6 functions)
- `proxy_start()` - Start proxy server
- `proxy_stop()` - Stop proxy
- `proxy_set_upstream()` - Configure upstream proxy
- `proxy_add_filter()` - Add request filter
- `proxy_get_stats()` - Get proxy statistics
- `proxy_get_logs()` - Retrieve request logs

### IDS (7 functions)
- `ids_start()` - Start intrusion detection
- `ids_stop()` - Stop IDS
- `ids_add_rule()` - Add detection rule
- `ids_remove_rule()` - Remove rule
- `ids_get_alerts()` - Get security alerts
- `ids_get_stats()` - Get IDS statistics
- `ids_block_threat()` - Block detected threat

### Network Monitoring (8 functions)
- `network_start_monitor()` - Start traffic monitor
- `network_stop_monitor()` - Stop monitor
- `network_get_bandwidth()` - Get bandwidth stats
- `network_get_connections()` - List connections
- `network_get_protocols()` - Protocol distribution
- `network_get_top_talkers()` - Top bandwidth users
- `network_get_flows()` - Get network flows
- `network_export_pcap()` - Export to PCAP

### Packet Capture (5 functions)
- `capture_start()` - Start packet capture
- `capture_stop()` - Stop capture
- `capture_get_packets()` - Get captured packets
- `capture_analyze_packet()` - Analyze packet
- `capture_save_pcap()` - Save to PCAP file

### Port Scanning (5 functions)
- `scan_ports()` - Scan target ports
- `scan_network()` - Discover hosts
- `scan_service_version()` - Identify services
- `scan_os_fingerprint()` - Detect OS
- `scan_vulnerabilities()` - Find vulnerabilities

### Reverse Proxy (5 functions)
- `reverse_proxy_create()` - Create reverse proxy
- `reverse_proxy_add_backend()` - Add backend
- `reverse_proxy_remove_backend()` - Remove backend
- `reverse_proxy_set_load_balancing()` - Set algorithm
- `reverse_proxy_get_health()` - Check health

## Requirements

- Sentra VM with network module enabled
- Network interface access
- Administrator/root privileges for some operations:
  - Packet capture requires elevated privileges
  - Port scanning may require elevated privileges
  - Firewall management requires elevated privileges

## Configuration

Each example can be configured by modifying variables at the top of the file:

### IDS System
```sentra
let check_interval = 5  // Seconds between checks
let auto_block = true   // Automatically block threats
```

### Network Scanner
```sentra
let target_network = "192.168.1.0/24"
let scan_common_ports = true
let check_vulnerabilities = true
```

### Firewall Manager
```sentra
let default_input_policy = "ACCEPT"
let default_output_policy = "ACCEPT"
let default_forward_policy = "DROP"
```

### Network Monitor
```sentra
let update_interval = 6  // Seconds between updates
let show_packet_details = true
```

### Proxy Server
```sentra
let proxy_port = 8080
let enable_filtering = true
let enable_cache = true
```

## Tips and Best Practices

1. **Run with elevated privileges**: Some network operations require administrator/root access

2. **Test in isolated environment**: Test network scanning and IDS in controlled networks

3. **Monitor resource usage**: Network monitoring can be CPU/memory intensive

4. **Configure firewall carefully**: Test rules before deploying in production

5. **Review logs regularly**: Check proxy and IDS logs for security insights

6. **Export data for analysis**: Use PCAP export for detailed packet analysis

7. **Combine tools**: Use multiple tools together for comprehensive security

## Troubleshooting

### "Failed to start monitor"
- Check network interface name (use `ifconfig` or `ipconfig`)
- Ensure elevated privileges
- Verify network module is enabled

### "No hosts found"
- Check network connectivity
- Verify correct CIDR notation
- Ensure firewall allows scanning

### "Permission denied"
- Run with administrator/root privileges
- Check file permissions
- Verify network interface access

## Next Steps

After exploring these examples:

1. Customize for your environment
2. Build automated security workflows
3. Integrate with existing security tools
4. Create custom detection rules
5. Build security dashboards
6. Implement automated responses

## License

MIT License - see main project LICENSE
