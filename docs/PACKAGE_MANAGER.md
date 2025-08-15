# Sentra Package Manager Design

## Overview
Sentra's package management system follows Go's philosophy of using version control systems (primarily GitHub) as the package repository, making it decentralized and simple.

## Package Structure

### Module Definition (sentra.mod)
```
module github.com/user/project

sentra 1.0

require (
    github.com/sentra-lang/stdlib v1.2.0
    github.com/sentra-security/network v2.0.1
    github.com/sentra-security/forensics v1.0.0
)

replace github.com/old/package => github.com/new/package v1.0.0
```

### Package Layout
```
my-sentra-package/
├── sentra.mod           # Module definition
├── sentra.sum           # Checksum file
├── README.md
├── LICENSE
├── src/
│   ├── main.sn         # Main entry point
│   ├── scanner.sn      # Package modules
│   └── utils.sn
├── tests/
│   └── scanner_test.sn
├── examples/
│   └── example.sn
└── docs/
    └── API.md
```

## Import System

### Import Syntax
```sentra
// Import entire package
import "github.com/sentra-security/network"

// Import with alias
import net "github.com/sentra-security/network"

// Import specific functions
import { port_scan, dns_lookup } from "github.com/sentra-security/network"

// Import local modules
import "./lib/utils"
import "../shared/config"
```

### Standard Library
```sentra
// Core modules (no prefix needed)
import "io"
import "fmt"
import "strings"
import "crypto"
import "net"
import "os"
```

## Package Commands

### Initialize New Module
```bash
sentra mod init github.com/user/project
```

### Add Dependencies
```bash
sentra get github.com/sentra-security/network@v2.0.0
sentra get github.com/sentra-security/network@latest
sentra get ./local/package
```

### Update Dependencies
```bash
sentra get -u                    # Update all
sentra get -u github.com/...     # Update specific
```

### Download Dependencies
```bash
sentra mod download
```

### Verify Dependencies
```bash
sentra mod verify
```

### Vendor Dependencies
```bash
sentra mod vendor
```

### Tidy Dependencies
```bash
sentra mod tidy
```

## Package Resolution

### Search Order
1. Standard library
2. Vendor directory (if exists)
3. Module cache (~/.sentra/pkg/mod/)
4. Download from source

### Version Selection
- Minimal version selection (like Go)
- Semantic versioning (v1.2.3)
- Pseudo-versions for commits (v0.0.0-20210101000000-abcdef123456)

## Package Registry

### Official Packages
Hosted under `github.com/sentra-lang/` organization:
- `github.com/sentra-lang/stdlib` - Standard library
- `github.com/sentra-lang/security` - Security tools
- `github.com/sentra-lang/network` - Network utilities
- `github.com/sentra-lang/forensics` - Forensics tools
- `github.com/sentra-lang/cloud` - Cloud security

### Community Packages
- `github.com/sentra-community/` - Community packages
- Any GitHub repository with sentra.mod

### Private Packages
```bash
# Configure private repository access
export SENTRA_PRIVATE=github.com/company/*
git config --global url."https://user:token@github.com/".insteadOf "https://github.com/"
```

## Package Publishing

### Publish to GitHub
```bash
# Tag version
git tag v1.0.0
git push origin v1.0.0

# Package is now available at:
# github.com/user/package@v1.0.0
```

### Package Metadata
Create `.sentra-package.json`:
```json
{
  "name": "network-scanner",
  "version": "1.0.0",
  "description": "Advanced network security scanner",
  "author": "Security Team",
  "license": "MIT",
  "keywords": ["security", "network", "scanner"],
  "homepage": "https://github.com/user/network-scanner",
  "dependencies": {
    "github.com/sentra-lang/network": "^2.0.0"
  },
  "scripts": {
    "test": "sentra test ./tests",
    "build": "sentra build -o scanner"
  }
}
```

## Build System Integration

### Build Configuration (sentra.build)
```yaml
name: my-app
version: 1.0.0
entry: src/main.sn

targets:
  - name: default
    output: bin/app
    flags: ["-optimize", "-strip"]
  
  - name: debug
    output: bin/app-debug
    flags: ["-debug", "-verbose"]

  - name: wasm
    output: dist/app.wasm
    target: wasm32

dependencies:
  pre-build:
    - sentra mod download
    - sentra test ./tests
  
  post-build:
    - cp README.md bin/
```

### Build Commands
```bash
# Build default target
sentra build

# Build specific target
sentra build --target=wasm

# Build with configuration
sentra build -c sentra.build

# Clean build
sentra clean

# Install globally
sentra install
```

## Dependency Management

### Lock File (sentra.sum)
```
github.com/sentra-security/network v2.0.0 h1:SHA256HASH...
github.com/sentra-security/network/go.mod v2.0.0 h1:SHA256HASH...
```

### Vendoring
```bash
# Vendor all dependencies
sentra mod vendor

# Build using vendor
sentra build -mod=vendor
```

### Module Proxy
```bash
# Configure module proxy
export SENTRA_PROXY=https://proxy.sentra-lang.org

# Direct connection for private repos
export SENTRA_NOPROXY=github.com/company/*
```

## Testing Framework

### Test Files
Test files end with `_test.sn`:
```sentra
// scanner_test.sn
import testing
import "../src/scanner"

fn test_port_scan() {
    let result = scanner.scan("127.0.0.1", 80, 80)
    testing.assert_equal(len(result), 1)
    testing.assert_equal(result[0]["port"], 80)
}

fn test_invalid_host() {
    testing.assert_panics(fn() {
        scanner.scan("invalid..host", 80, 80)
    })
}
```

### Running Tests
```bash
# Run all tests
sentra test

# Run specific directory
sentra test ./tests

# Run with coverage
sentra test -cover

# Run with verbose output
sentra test -v
```

## Package Documentation

### Documentation Generation
```bash
# Generate documentation
sentra doc

# Serve documentation
sentra doc -http=:6060

# Generate markdown
sentra doc -format=markdown > API.md
```

### Documentation Comments
```sentra
// Package scanner provides network scanning utilities
// for security assessment and vulnerability detection.
package scanner

// ScanPorts performs a TCP port scan on the target host.
// It returns an array of open ports with service information.
//
// Example:
//   let results = scanner.ScanPorts("192.168.1.1", 1, 1000)
//   for port in results {
//       log("Open port: " + port.number)
//   }
fn ScanPorts(host: string, start: int, end: int) -> array {
    // Implementation
}
```

## Migration from Other Languages

### From Python
```bash
sentra migrate python script.py -o script.sn
```

### From Go
```bash
sentra migrate go main.go -o main.sn
```

## Implementation Timeline

1. **Phase 1**: Basic import/export system
2. **Phase 2**: GitHub-based package fetching
3. **Phase 3**: Version management
4. **Phase 4**: Build system
5. **Phase 5**: Testing framework
6. **Phase 6**: Documentation generation

This design provides a robust, Go-like package management system that leverages GitHub for distribution while maintaining simplicity and security.