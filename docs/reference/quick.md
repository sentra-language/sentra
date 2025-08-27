---
layout: default
title: Quick Reference
parent: Reference
nav_order: 3
---

# Sentra Quick Start Guide

Welcome to Sentra! This guide will get you up and running in 5 minutes.

## Installation

### Prerequisites
- Go 1.20 or higher
- Git

### Building from Source
```bash
# Clone the repository
git clone https://github.com/yourusername/sentra.git
cd sentra

# Build the executable
make sentra
# or
go build -o sentra ./cmd/sentra
```

### Verify Installation
```bash
./sentra --version
```

## Your First Program

### 1. Hello World

Create a file `hello.sn`:
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

### 2. Variables and Math

Create `calculator.sn`:
```sentra
// Basic arithmetic
let a = 10
let b = 20
let sum = a + b

log("Sum of " + a + " and " + b + " is " + sum)

// Functions
fn calculate(x, y, operation) {
    if operation == "add" {
        return x + y
    } else if operation == "multiply" {
        return x * y
    }
    return 0
}

let result = calculate(5, 3, "multiply")
log("5 × 3 = " + result)
```

### 3. Working with Collections

Create `collections.sn`:
```sentra
// Arrays
let fruits = ["apple", "banana", "orange"]
log("Fruits: " + str(fruits))

// Add an item
push(fruits, "grape")
log("After adding grape: " + str(fruits))

// Maps (dictionaries)
let person = {}
person["name"] = "Alice"
person["age"] = 30
person["city"] = "New York"

log("Person: " + str(person))

// Iteration
log("\nIterating through fruits:")
for fruit in fruits {
    log("- " + fruit)
}
```

## Interactive REPL

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
>>> exit
```

## Core Language Features

### Variables
```sentra
let immutable = "can't change reference"
var mutable = "can change"
const CONSTANT = 42
```

### Control Flow
```sentra
// If-else
if age >= 18 {
    log("Adult")
} else {
    log("Minor")
}

// Loops
for (let i = 0; i < 5; i = i + 1) {
    log(i)
}

// While
while condition {
    // do something
}

// For-in
for item in collection {
    log(item)
}
```

### Functions
```sentra
// Named function
fn add(a, b) {
    return a + b
}

// Anonymous function
let multiply = fn(x, y) { return x * y }

// Higher-order function
fn map(arr, func) {
    let result = []
    for item in arr {
        push(result, func(item))
    }
    return result
}

let numbers = [1, 2, 3, 4]
let doubled = map(numbers, fn(x) { return x * 2 })
log(doubled)  // [2, 4, 6, 8]
```

### Error Handling
```sentra
try {
    let result = divide(10, 0)
} catch (error) {
    log("Error: " + error)
} finally {
    log("Cleanup")
}
```

## Security Features Example

Sentra includes powerful security capabilities:

```sentra
// Network security scan
let scan = net_scan("192.168.1.1", "1-1000")
log("Open ports: " + str(scan["open_ports"]))

// Security assessment
let risk = security_assess("network", {"ip": "192.168.1.1"})
log("Risk score: " + risk["score"])

// Hash functions
let hash = hash("sha256", "secret data")
log("SHA256: " + hash)

// Encryption
let encrypted = encrypt("aes256", "sensitive", "key")
let decrypted = decrypt("aes256", encrypted, "key")
```

## Project Structure

Recommended project layout:
```
my-project/
├── main.sn           # Entry point
├── lib/              # Your libraries
│   ├── utils.sn
│   └── helpers.sn
├── modules/          # Modules
│   └── database.sn
└── tests/           # Test files
    └── test_utils.sn
```

## Common Patterns

### 1. Module Pattern
```sentra
// math_utils.sn
export fn factorial(n) {
    if n <= 1 { return 1 }
    return n * factorial(n - 1)
}

// main.sn
import { factorial } from "./math_utils"
log(factorial(5))  // 120
```

### 2. Configuration Object
```sentra
let config = {
    "host": "localhost",
    "port": 8080,
    "debug": true
}

fn startServer(cfg) {
    log("Starting server on " + cfg["host"] + ":" + cfg["port"])
}

startServer(config)
```

### 3. Error-First Callbacks
```sentra
fn readFile(path, callback) {
    try {
        let content = file_read(path)
        callback(nil, content)
    } catch (err) {
        callback(err, nil)
    }
}

readFile("data.txt", fn(err, data) {
    if err != nil {
        log("Error: " + err)
        return
    }
    log("File content: " + data)
})
```

## Command-Line Usage

### Run a Script
```bash
./sentra run script.sn
```

### Start REPL
```bash
./sentra repl
```

### Run with Arguments
```bash
./sentra run script.sn arg1 arg2
```

### Debug Mode
```bash
./sentra run --debug script.sn
```

## Performance Tips

1. **Use local variables** - They're faster than globals
2. **Cache array lengths** in loops
3. **Use maps for lookups** instead of array searches
4. **Avoid deep nesting** - Refactor into functions
5. **String concatenation** - Use string builder for many concatenations

## Troubleshooting

### Stack Overflow
If you get a stack overflow with large loops:
```sentra
// Instead of this (may overflow at 50k+)
for (let i = 0; i < 100000; i = i + 1) {
    // heavy processing
}

// Use chunking
fn processChunk(start, end) {
    for (let i = start; i < end; i = i + 1) {
        // process
    }
}

processChunk(0, 50000)
processChunk(50000, 100000)
```

### Memory Issues
Clear references to large objects when done:
```sentra
let bigData = loadLargeFile()
processData(bigData)
bigData = nil  // Help garbage collector
```

## Next Steps

1. **Explore Examples**: Check the `examples/` directory
   - `basics/` - Fundamental concepts
   - `advanced/` - Advanced features
   - `security/` - Security capabilities
   - `web/` - Web-related examples

2. **Read Documentation**:
   - [Language Reference](LANGUAGE_REFERENCE.md) - Complete syntax guide
   - [Standard Library](STDLIB_REFERENCE.md) - All built-in functions
   - [Security Modules](SECURITY_MODULES.md) - Security capabilities

3. **Build Something**:
   - Security scanner
   - Compliance checker
   - API client
   - Data processor
   - Automation tool

## Getting Help

- **Documentation**: `docs/` directory
- **Examples**: `examples/` directory
- **Issues**: GitHub Issues
- **Community**: Discord/Forums

## Example: Complete Security Scanner

Here's a simple security scanner in Sentra:

```sentra
// scanner.sn - Simple security scanner
fn scanTarget(target) {
    log("Scanning " + target + "...")
    
    let results = {}
    
    // Port scan
    let ports = net_scan(target, "1-1000")
    results["open_ports"] = ports["open_ports"]
    
    // Security assessment
    let assessment = security_assess("host", {"ip": target})
    results["risk_score"] = assessment["score"]
    
    // Check for common vulnerabilities
    let vulns = []
    for port in results["open_ports"] {
        if port == 23 {
            push(vulns, "Telnet (insecure)")
        }
        if port == 21 {
            push(vulns, "FTP (insecure)")
        }
    }
    results["vulnerabilities"] = vulns
    
    return results
}

// Main program
let target = "192.168.1.1"
try {
    let scan = scanTarget(target)
    
    log("\n=== Scan Results ===")
    log("Target: " + target)
    log("Open Ports: " + str(scan["open_ports"]))
    log("Risk Score: " + scan["risk_score"])
    
    if len(scan["vulnerabilities"]) > 0 {
        log("\nVulnerabilities Found:")
        for vuln in scan["vulnerabilities"] {
            log("  - " + vuln)
        }
    }
} catch (e) {
    log("Scan failed: " + e)
}
```

## Congratulations!

You now know enough Sentra to build useful applications. Start with the examples, experiment with the REPL, and build something awesome!

---

{: .fs-6 .fw-300 }
This completes the reference documentation. Ready to start building? Check out the examples and tutorials.

[← Previous: Standard Library](../stdlib/){: .btn .btn-outline .mr-2 }
[Browse Examples on GitHub →](https://github.com/sentra-language/sentra/tree/main/examples){: .btn .btn-primary }

---

## Related Documentation

- [Tutorial Overview](../../tutorial/) - Complete learning path
- [Language Reference](../language/) - Full syntax documentation
- [Standard Library](../stdlib/) - All built-in functions
- [Back to Reference Overview](../) - All reference materials

Happy coding with Sentra! 🚀