---
layout: default
title: How-to Guides
permalink: /guide/
---

# Sentra How-to Guides

Practical guides and recipes for common programming tasks in Sentra. Each guide provides step-by-step instructions with working code examples.

## Security & Compliance

### Security Tools
- [Building a Port Scanner](/guide/port-scanner/) - Network reconnaissance tool
- [Creating a Vulnerability Scanner](/guide/vuln-scanner/) - Automated security assessment
- [Writing Security Auditors](/guide/security-audit/) - Compliance checking
- [Building a Password Manager](/guide/password-manager/) - Secure credential storage
- [Implementing 2FA](/guide/2fa/) - Two-factor authentication

### Compliance & Auditing
- [SOC2 Compliance Checker](/guide/soc2/) - Automated SOC2 validation
- [GDPR Data Scanner](/guide/gdpr/) - Privacy regulation compliance
- [HIPAA Audit Tool](/guide/hipaa/) - Healthcare compliance
- [PCI-DSS Validator](/guide/pci-dss/) - Payment card security

## Web Development

### Web Applications
- [Creating a REST API](/guide/rest-api/) - Building HTTP services
- [WebSocket Server](/guide/websocket/) - Real-time communication
- [Authentication System](/guide/auth/) - User login and sessions
- [Rate Limiting](/guide/rate-limit/) - API protection
- [Web Scraping](/guide/scraping/) - Data extraction

### API Development
- [JSON API Server](/guide/json-api/) - RESTful JSON services
- [GraphQL Server](/guide/graphql/) - Query language implementation
- [API Gateway](/guide/api-gateway/) - Request routing and management
- [Webhook Handler](/guide/webhooks/) - Event-driven integration

## Data Processing

### File Operations
- [Reading CSV Files](/guide/csv/) - Parsing structured data
- [Processing JSON](/guide/json-processing/) - JSON manipulation
- [XML Parsing](/guide/xml/) - Working with XML documents
- [Log Analysis](/guide/logs/) - Processing log files
- [Binary Files](/guide/binary/) - Reading binary formats

### Database Operations
- [Database Connections](/guide/database/) - Connecting to databases
- [SQL Queries](/guide/sql/) - Running database queries
- [Data Migration](/guide/migration/) - Moving data between systems
- [Database Security](/guide/db-security/) - Securing database access

## Network Programming

### Network Tools
- [TCP Server](/guide/tcp-server/) - Building TCP services
- [UDP Communication](/guide/udp/) - Datagram protocols
- [DNS Resolver](/guide/dns/) - Domain name resolution
- [Network Monitor](/guide/network-monitor/) - Traffic analysis
- [Proxy Server](/guide/proxy/) - Request forwarding

### Security Scanning
- [Network Discovery](/guide/network-discovery/) - Finding devices
- [Service Detection](/guide/service-detection/) - Identifying services
- [SSL/TLS Testing](/guide/ssl-test/) - Certificate validation
- [Firewall Testing](/guide/firewall-test/) - Rule validation

## System Administration

### Automation
- [Task Scheduling](/guide/scheduling/) - Cron-like automation
- [System Monitoring](/guide/monitoring/) - Resource tracking
- [Log Rotation](/guide/log-rotation/) - Managing log files
- [Backup Scripts](/guide/backup/) - Automated backups
- [Deployment Tools](/guide/deployment/) - Application deployment

### Process Management
- [Service Management](/guide/services/) - Starting/stopping services
- [Process Monitoring](/guide/processes/) - Tracking processes
- [Resource Limits](/guide/resources/) - Managing resources
- [Health Checks](/guide/health/) - Service availability

## Cryptography & Security

### Encryption
- [File Encryption](/guide/file-encryption/) - Securing files
- [Data Encryption](/guide/data-encryption/) - Protecting data
- [Key Management](/guide/keys/) - Managing encryption keys
- [Digital Signatures](/guide/signatures/) - Signing data
- [Certificate Management](/guide/certificates/) - X.509 certificates

### Hashing & Authentication
- [Password Hashing](/guide/password-hash/) - Secure password storage
- [HMAC Generation](/guide/hmac/) - Message authentication
- [Token Generation](/guide/tokens/) - Creating secure tokens
- [Session Management](/guide/sessions/) - User sessions

## Testing & Quality

### Testing
- [Unit Testing](/guide/unit-tests/) - Writing test cases
- [Integration Testing](/guide/integration-tests/) - System testing
- [Security Testing](/guide/security-tests/) - Vulnerability testing
- [Performance Testing](/guide/performance-tests/) - Load testing
- [Test Coverage](/guide/coverage/) - Measuring test coverage

### Debugging
- [Debugging Techniques](/guide/debugging/) - Finding bugs
- [Profiling](/guide/profiling/) - Performance analysis
- [Memory Debugging](/guide/memory-debug/) - Finding leaks
- [Stack Traces](/guide/stack-traces/) - Error analysis

## Best Practices

### Code Organization
- [Project Structure](/guide/project-structure/) - Organizing code
- [Module Design](/guide/modules/) - Creating modules
- [Error Handling](/guide/errors/) - Managing errors
- [Logging](/guide/logging/) - Effective logging
- [Documentation](/guide/documentation/) - Writing docs

### Security Best Practices
- [Input Validation](/guide/validation/) - Sanitizing input
- [Secure Defaults](/guide/secure-defaults/) - Safe configuration
- [Least Privilege](/guide/least-privilege/) - Access control
- [Defense in Depth](/guide/defense-depth/) - Layered security

## Advanced Topics

### Concurrency
- [Goroutines](/guide/goroutines/) - Concurrent execution
- [Channels](/guide/channels/) - Communication
- [Worker Pools](/guide/workers/) - Task distribution
- [Rate Limiting](/guide/concurrency-limit/) - Resource control

### Performance
- [Optimization Tips](/guide/optimization/) - Faster code
- [Memory Management](/guide/memory/) - Efficient memory use
- [Caching](/guide/caching/) - Performance improvement
- [Benchmarking](/guide/benchmarks/) - Measuring performance

## Quick Recipes

### Common Tasks

```sentra
// Read a file
import io
let content = io.readfile("data.txt")

// Make HTTP request
import http
let response = http.get("https://api.example.com/data")

// Hash a password
import security
let hash = security.hash_password("secret123")

// Parse JSON
import json
let data = json.decode('{"name": "John", "age": 30}')

// Scan ports
import network
let ports = network.scan_ports("192.168.1.1", "1-1000")
```

## Contributing Guides

Want to contribute a guide? See our [contribution guidelines](https://github.com/sentra-language/sentra/blob/main/CONTRIBUTING.md#guides).

---

<div class="guide-nav">
    <a href="/" class="nav-home">← Home</a>
    <a href="/guide/port-scanner/" class="nav-next">Building a Port Scanner →</a>
</div>