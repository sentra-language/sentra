# Sentra - Security Automation Language

A powerful, domain-specific security automation language built for cybersecurity professionals, penetration testers, and security engineers.

## 🚀 VSCode Extension Available!
Install the official VSCode extension for syntax highlighting, IntelliSense, and integrated execution:
```bash
cd vscode-sentra
./install.bat  # Windows
./install.sh   # Linux/Mac
```

## Overview

Sentra is a specialized programming language designed specifically for security automation tasks. It combines the simplicity of scripting languages with powerful security-focused primitives and parallel execution capabilities.

## ✨ Key Features

### Security-First Design
- **70+ Security Functions**: Built-in primitives for common security tasks
- **Network Security**: Port scanning, packet capture, DNS enumeration
- **Web Security**: XSS/SQLi detection, TLS analysis, vulnerability scanning
- **Cryptography**: Hashing, encryption, certificate analysis
- **File Integrity**: Baseline creation, change detection, permission auditing
- **Database Security**: Injection testing, privilege auditing, sensitive data discovery
- **OS Security**: Process monitoring, privilege escalation detection, firewall analysis

### High Performance
- **Concurrent Execution**: Worker pools, rate limiters, parallel scanning
- **Optimized VM**: Stack-based architecture with pre-allocated memory
- **Fast Operations**: 14-40 microseconds per operation
- **Memory Efficient**: Minimal allocations, thread-safe collections

### Developer Experience
- **VSCode Integration**: Full IDE support with syntax highlighting and IntelliSense
- **Package Manager**: GitHub-based package distribution (like Go)
- **REPL**: Interactive console for testing
- **Cross-Platform**: Works on Windows, Linux, macOS

## Quick Start

### Installation
```bash
# Build from source
go build -o sentra.exe ./cmd/sentra

# Or use pre-built binaries (coming soon)
```

### Hello World
```sentra
#!/usr/bin/env sentra

log("Hello, Security World!")

// Quick security check
let os = os_info()
log("Platform: " + os["platform"])
log("Hostname: " + os["hostname"])

if (os_privileges()) {
    log("⚠️ Running with elevated privileges")
}
```

### Port Scanner Example
```sentra
// Scan common web ports
let results = port_scan("scanme.nmap.org", 80, 443, "TCP")

for (let i = 0; i < len(results); i++) {
    let port = results[i]
    if (port["state"] == "open") {
        log("Port " + port["port"] + " is open")
    }
}
```

### Concurrent Security Scanning
```sentra
// Create worker pool for parallel scanning
if (conc_create_worker_pool("scanner", 8, 100)) {
    conc_start_worker_pool("scanner")
    
    // Submit multiple scan jobs
    let targets = ["192.168.1.1", "192.168.1.2", "192.168.1.3"]
    for (let i = 0; i < len(targets); i++) {
        conc_submit_job("scanner", "job_" + str(i), "port_scan", targets[i])
    }
    
    // Get metrics
    let metrics = conc_get_metrics()
    log("Jobs completed: " + str(metrics["tasks_completed"]))
}
```

### Web Vulnerability Scanning
```sentra
// Configure web client
let config = {
    "timeout": 30,
    "user_agent": "Sentra Security Scanner"
}

if (web_create_client("scanner", config)) {
    // Scan for vulnerabilities
    let xss = web_scan_xss("scanner", "https://example.com")
    let sqli = web_scan_sqli("scanner", "https://example.com")
    
    if (xss["vulnerable"]) {
        log("⚠️ XSS vulnerability detected!")
    }
    
    if (sqli["vulnerable"]) {
        log("⚠️ SQL injection vulnerability detected!")
    }
}
```

### File Integrity Monitoring
```sentra
// Create baseline
if (fs_create_baseline("/etc", true)) {
    log("Baseline created for /etc")
    
    // Later, check for changes
    let changes = fs_compare_baseline("/etc")
    if (len(changes) > 0) {
        log("File system changes detected:")
        for (let i = 0; i < len(changes); i++) {
            log("  - " + changes[i])
        }
    }
}
```

## Complete Feature Set

### 🔒 Security Modules

#### Network Security
- Port scanning (TCP/UDP)
- Service detection
- DNS enumeration
- Packet capture and analysis
- Socket operations
- TLS/SSL analysis

#### Web Application Security
- XSS detection
- SQL injection testing
- Directory traversal checks
- Security header analysis
- Web fuzzing
- Spider/crawler
- JWT analysis

#### Cryptography
- Hash functions (MD5, SHA1, SHA256, SHA512)
- HMAC generation
- Bcrypt hashing/verification
- AES encryption/decryption
- RSA operations
- Certificate analysis
- Digital signatures

#### File System Security
- Integrity monitoring
- Baseline creation/comparison
- Permission auditing
- Sensitive data discovery
- Hash calculation
- Change detection

#### Database Security
- Connection management
- SQL injection testing
- Permission auditing
- User enumeration
- Sensitive data discovery
- Authentication testing

#### Operating System Security
- Process monitoring
- Open port detection
- User enumeration
- Privilege detection
- Firewall rule analysis
- Registry operations (Windows)
- Service enumeration

#### Reporting
- Multiple formats (JSON, HTML, XML, Markdown)
- Finding management
- Evidence collection
- CVSS scoring
- Compliance mapping
- Streaming reports

#### Concurrency
- Worker pools
- Rate limiting
- Task queues
- Connection pooling
- Semaphores
- Metrics collection

### 📦 Package Management

Sentra uses a Go-like approach with GitHub as the package repository:

```sentra
// Import packages
import "github.com/sentra-security/network"
import scanner "github.com/user/custom-scanner"

// Use imported functions
let results = network.deep_scan("10.0.0.0/24")
```

Install packages:
```bash
sentra get github.com/sentra-security/network@latest
```

### 🛠️ Build System

```bash
# Compile to bytecode
sentra build main.sn -o app.snc

# Run compiled bytecode
sentra run app.snc

# Build with dependencies
sentra build --with-deps
```

## Language Syntax

### Variables and Types
```sentra
let immutable = "can't change"
var mutable = "can change"
const CONSTANT = 3.14

// Dynamic typing
let number = 42
let string = "hello"
let boolean = true
let array = [1, 2, 3]
let map = {"key": "value"}
```

### Functions
```sentra
fn scan_network(subnet, ports) {
    let results = []
    for (let i = 0; i < len(ports); i++) {
        let scan = port_scan(subnet, ports[i], ports[i], "TCP")
        results = results + scan
    }
    return results
}
```

### Control Flow
```sentra
// If-else
if (condition) {
    // code
} else if (other) {
    // code
} else {
    // code
}

// While loop
while (condition) {
    // code
}

// For loop
for (let i = 0; i < 10; i++) {
    // code
}

// Match (pattern matching)
match value {
    "case1" => { /* code */ }
    "case2" => { /* code */ }
    _ => { /* default */ }
}
```

## Roadmap

### ✅ Completed
- Core VM implementation
- Security function library (70+ functions)
- Concurrency support
- VSCode extension
- Package manager design

### 🚧 In Progress
- Memory forensics module
- SIEM integration
- Threat intelligence APIs
- Container security
- Cloud security (AWS/Azure/GCP)

### 📅 Planned
- Machine learning for security
- Incident response automation
- Compliance frameworks (PCI-DSS, HIPAA)
- Advanced network analysis
- API security testing

## Contributing

Contributions are welcome! Areas of interest:
- Security module implementations
- Package ecosystem
- Documentation
- Testing frameworks
- Performance optimizations

## License

MIT License - See LICENSE file for details

## Community

- GitHub: [github.com/sentra-lang/sentra](https://github.com/sentra-lang/sentra)
- Packages: [github.com/sentra-packages](https://github.com/sentra-packages)
- Discord: Coming soon
- Documentation: Coming soon

## Why Sentra?

Traditional scripting languages require extensive libraries and boilerplate for security tasks. Sentra provides these capabilities out-of-the-box with a syntax designed for security professionals. Whether you're conducting penetration tests, building security tools, or automating compliance checks, Sentra makes it simple and efficient.

**Sentra: Security Automation Made Simple**