---
layout: default
title: Quick Start
nav_order: 2
description: "Get up and running with Sentra in 5 minutes"
---

# Quick Start Guide

Get up and running with Sentra in just 5 minutes!

## Installation

### Prerequisites
- Go 1.20 or higher
- Git

### Build from Source
```bash
# Clone the repository
git clone https://github.com/sentra-language/sentra.git
cd sentra

# Build the executable
make sentra
# or manually: go build -o sentra ./cmd/sentra
```

### Verify Installation
```bash
./sentra --version
```

## Hello World

### Your First Program

Create `hello.sn`:
```sentra
// hello.sn
log("Hello, World!")
log("Welcome to Sentra!")
```

Run it:
```bash
./sentra run hello.sn
```

Output:
```
Hello, World!
Welcome to Sentra!
```

### Interactive REPL

Start the interactive shell:
```bash
./sentra repl
```

Try these commands:
```sentra
>>> let x = 10
>>> let y = 20
>>> x + y
30
>>> fn greet(name) { return "Hello, " + name }
>>> greet("Sentra")
"Hello, Sentra"
```

## Core Concepts

### Variables and Types

```sentra
// Variable declarations
let immutable = "can't change reference"
var mutable = "can change"
const CONSTANT = 42

// Dynamic typing
let number = 42
let string = "hello"
let boolean = true
let array = [1, 2, 3]
let map = {"key": "value"}
let nothing = nil
```

### Functions

```sentra
// Named function
fn add(a, b) {
    return a + b
}

// Lambda function
let multiply = fn(x, y) { return x * y }

// Using functions
let result = add(5, 3)        // 8
let product = multiply(4, 6)  // 24
```

### Collections

```sentra
// Arrays
let fruits = ["apple", "banana", "orange"]
push(fruits, "grape")
log("Fruits: " + str(fruits))

// Maps
let person = {}
person["name"] = "Alice"
person["age"] = 30
log("Name: " + person["name"])
```

### Control Flow

```sentra
// Conditionals
if age >= 18 {
    log("Adult")
} else {
    log("Minor")
}

// Loops
for (let i = 0; i < 5; i = i + 1) {
    log("Count: " + i)
}

// For-in loops
for fruit in fruits {
    log("Fruit: " + fruit)
}
```

### Error Handling

```sentra
try {
    let result = divide(10, 0)
} catch (error) {
    log("Error: " + error)
} finally {
    log("Cleanup code")
}
```

## Security Features

One of Sentra's unique strengths is its built-in security capabilities:

### Network Security

```sentra
// Port scanning
let scan = net_scan("192.168.1.1", "1-100")
log("Open ports: " + str(scan["open_ports"]))

// Security assessment
let risk = security_assess("network", {"ip": "192.168.1.1"})
log("Risk score: " + risk["score"])
```

### Cryptography

```sentra
// Hash functions
let hash = hash("sha256", "sensitive data")
log("SHA256: " + hash)

// Encryption
let encrypted = encrypt("aes256", "secret message", "encryption-key")
let decrypted = decrypt("aes256", encrypted, "encryption-key")
log("Decrypted: " + decrypted)
```

### Security Scanner Example

```sentra
// Complete security scanner
fn scanHost(host) {
    log("🔍 Scanning " + host + "...")
    
    let results = {}
    
    // Port scan
    let ports = net_scan(host, "1-1000")
    results["ports"] = ports["open_ports"]
    
    // Security assessment
    let assessment = security_assess("host", {"ip": host})
    results["risk_score"] = assessment["score"]
    
    // Check for common vulnerabilities
    let vulns = []
    for port in results["ports"] {
        if port == 23 {
            push(vulns, "Telnet (insecure)")
        }
        if port == 21 {
            push(vulns, "FTP (potentially insecure)")
        }
    }
    results["vulnerabilities"] = vulns
    
    // Report findings
    log("📊 Scan Results:")
    log("   Open Ports: " + str(results["ports"]))
    log("   Risk Score: " + results["risk_score"] + "/100")
    
    if len(results["vulnerabilities"]) > 0 {
        log("⚠️  Vulnerabilities:")
        for vuln in results["vulnerabilities"] {
            log("   - " + vuln)
        }
    } else {
        log("✅ No obvious vulnerabilities found")
    }
    
    return results
}

// Scan a target
let target = "192.168.1.1"
try {
    let results = scanHost(target)
    log("Scan completed successfully!")
} catch (e) {
    log("Scan failed: " + e)
}
```

## Common Patterns

### Configuration Management

```sentra
// config.sn
let config = {
    "database": {
        "host": "localhost",
        "port": 5432,
        "name": "security_db"
    },
    "security": {
        "scan_timeout": 5000,
        "max_threads": 10
    }
}

fn getConfig(path) {
    let keys = split(path, ".")
    let result = config
    for key in keys {
        result = result[key]
    }
    return result
}

log("DB Host: " + getConfig("database.host"))
```

### Module Pattern

```sentra
// utils.sn
export fn formatTime(timestamp) {
    return "2024-01-01 12:00:00"  // Simplified
}

export fn isValidIP(ip) {
    return contains(ip, ".")
}

// main.sn
import { formatTime, isValidIP } from "./utils"

if isValidIP("192.168.1.1") {
    log("Valid IP at " + formatTime(time()))
}
```

## Performance Tips

1. **Cache array lengths** in loops:
```sentra
let arr = [1, 2, 3, 4, 5]
let len = len(arr)
for (let i = 0; i < len; i = i + 1) {
    // Process arr[i]
}
```

2. **Use maps for lookups**:
```sentra
// Instead of searching arrays
let lookup = {"key1": "value1", "key2": "value2"}
let value = lookup["key1"]  // O(1) lookup
```

3. **Handle large datasets with chunking**:
```sentra
fn processLargeDataset(data) {
    let chunkSize = 1000
    for (let i = 0; i < len(data); i = i + chunkSize) {
        let end = min(i + chunkSize, len(data))
        processChunk(slice(data, i, end))
    }
}
```

## Next Steps

### 1. Explore Examples
Check out the `examples/` directory:
- **`examples/basics/`** - Fundamental concepts
- **`examples/security/`** - Security tools and scanners  
- **`examples/web/`** - Web applications
- **`examples/advanced/`** - Advanced features

### 2. Read Documentation
- [**Language Reference**](language-reference/) - Complete syntax guide
- [**Standard Library**](stdlib/) - All built-in functions
- [**Security Modules**](security-modules/) - Security capabilities

### 3. Build Something
Try building:
- A simple port scanner
- A file integrity checker
- A log analyzer
- A compliance checker
- An API security scanner

### 4. Join the Community
- **GitHub**: Report issues and contribute
- **Discussions**: Ask questions and share projects
- **Examples**: Submit your own example programs

## Troubleshooting

### Stack Overflow with Large Loops
For operations over 30,000 iterations:
```sentra
// Use chunking instead of one large loop
fn processInChunks(start, end, chunkSize) {
    for (let i = start; i < end; i = i + chunkSize) {
        let chunkEnd = min(i + chunkSize, end)
        processChunk(i, chunkEnd)
    }
}

processInChunks(0, 100000, 10000)  // Process in 10k chunks
```

### Memory Management
```sentra
// Clear references to large objects when done
let bigData = loadLargeFile()
processData(bigData)
bigData = nil  // Help garbage collector
```

### Common Errors
- **Undefined variable**: Check spelling and scope
- **Type errors**: Use `type()` to check value types
- **Stack overflow**: Break large operations into smaller chunks

## Getting Help

- **Documentation**: Check the `docs/` section
- **Examples**: Look at similar programs in `examples/`
- **REPL**: Test code interactively with `./sentra repl`
- **GitHub Issues**: Report bugs or ask for help

---

Congratulations! You now know enough Sentra to build useful security applications. 

**Happy coding with Sentra!** 🚀