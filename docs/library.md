---
layout: default
title: Library Reference
permalink: /library/
---

# Sentra Standard Library Reference

The Sentra standard library provides a comprehensive set of modules and functions for common programming tasks, with a special focus on security operations.

## Core Modules

### Built-in Functions
Essential functions available without imports:

- [**Global Functions**](/library/builtin/) - `log()`, `str()`, `int()`, `float()`, `bool()`, `type()`, `len()`
- [**Type Conversions**](/library/conversions/) - Converting between data types
- [**Collections**](/library/collections/) - Array and map operations

### General Purpose

- [**math**](/library/math/) - Mathematical functions and constants
- [**string**](/library/string/) - String manipulation and formatting
- [**array**](/library/array/) - Array operations and transformations
- [**io**](/library/io/) - File and directory operations
- [**json**](/library/json/) - JSON encoding and decoding
- [**time**](/library/time/) - Date and time operations
- [**regex**](/library/regex/) - Regular expression matching
- [**http**](/library/http/) - HTTP client and server

### Security Modules

- [**security**](/library/security/) - Core security operations
- [**crypto**](/library/crypto/) - Cryptographic functions
- [**network**](/library/network/) - Network scanning and analysis
- [**database**](/library/database/) - Database security operations
- [**siem**](/library/siem/) - Security event management
- [**cloud**](/library/cloud/) - Cloud security operations
- [**compliance**](/library/compliance/) - Compliance checking frameworks

### Specialized Security

- [**mobile**](/library/mobile/) - Mobile security scanning
- [**blockchain**](/library/blockchain/) - Blockchain security analysis
- [**iot**](/library/iot/) - IoT device security
- [**ml**](/library/ml/) - Machine learning for security
- [**forensics**](/library/forensics/) - Digital forensics tools
- [**incident**](/library/incident/) - Incident response automation

## Module Categories

### Data Processing
Modules for working with data:
- `json` - JSON serialization
- `csv` - CSV file handling
- `xml` - XML parsing
- `yaml` - YAML support

### Networking
Network-related functionality:
- `http` - HTTP client/server
- `websocket` - WebSocket support
- `tcp` - TCP connections
- `udp` - UDP datagrams

### System Operations
System-level operations:
- `os` - Operating system interface
- `process` - Process management
- `shell` - Shell command execution
- `env` - Environment variables

### Security Operations
Security-specific modules:
- `vulnerability` - Vulnerability scanning
- `pentest` - Penetration testing tools
- `threat_intel` - Threat intelligence
- `audit` - Security auditing

## Quick Reference

### Most Used Functions

```sentra
// Logging and output
log(message)           // Print to console
debug(message)         // Debug output
error(message)         // Error output

// Type conversion
str(value)            // Convert to string
int(value)            // Convert to integer
float(value)          // Convert to float
bool(value)           // Convert to boolean

// Collections
len(collection)       // Get length
push(array, item)     // Add to array
pop(array)           // Remove last item
keys(map)            // Get map keys
values(map)          // Get map values

// Security basics
sha256(data)         // SHA-256 hash
encrypt(data, key)   // AES encryption
scan_ports(host)     // Port scanning
check_vuln(target)   // Vulnerability check
```

## Import Syntax

```sentra
// Import entire module
import math
let pi = math.PI

// Import with alias
import security as sec
let hash = sec.sha256("data")

// Import specific functions
from array import sort, reverse
let sorted = sort([3, 1, 2])

// Import all (use sparingly)
from string import *
let upper = upper("hello")
```

## Module Documentation Format

Each module page includes:

1. **Overview** - Module purpose and use cases
2. **Constants** - Module-level constants
3. **Functions** - Complete function reference
4. **Classes** - Object types (if applicable)
5. **Examples** - Practical usage examples
6. **See Also** - Related modules and topics

## Finding Functions

### By Category

- **Text Processing**: `string`, `regex`, `unicode`
- **Math & Numbers**: `math`, `random`, `statistics`
- **File Operations**: `io`, `path`, `csv`
- **Network**: `http`, `socket`, `url`
- **Security**: `crypto`, `hash`, `secure`
- **Data Formats**: `json`, `xml`, `yaml`
- **System**: `os`, `sys`, `process`
- **Time**: `time`, `datetime`, `calendar`

### By Task

**"I want to..."**
- Hash a password → [`security.hash_password()`](/library/security/#hash_password)
- Read a file → [`io.readfile()`](/library/io/#readfile)
- Make HTTP request → [`http.get()`](/library/http/#get)
- Parse JSON → [`json.decode()`](/library/json/#decode)
- Scan ports → [`network.scan_ports()`](/library/network/#scan_ports)
- Check compliance → [`compliance.check()`](/library/compliance/#check)

## Version Information

This documentation covers Sentra version **1.0.0**.

For version-specific documentation:
- [v1.0.0](/library/v1.0.0/) - Current stable
- [v0.9.0](/library/v0.9.0/) - Previous version
- [dev](/library/dev/) - Development version

## Contributing

Found an issue or want to improve the documentation?

- [Report Documentation Issues](https://github.com/sentra-language/sentra/issues/new?labels=documentation)
- [Contribute to Docs](https://github.com/sentra-language/sentra/blob/main/CONTRIBUTING.md#documentation)

---

<div class="library-nav">
    <a href="/" class="nav-home">← Home</a>
    <a href="/library/builtin/" class="nav-next">Built-in Functions →</a>
</div>