---
layout: tutorial
title: Introduction to Sentra
permalink: /tutorial/introduction/
order: 1
---

# Introduction to Sentra

Welcome to the Sentra programming language tutorial! This tutorial will guide you through the fundamentals of Sentra, a security-focused programming language designed for defensive security operations, compliance automation, and security tool development.

## What is Sentra?

Sentra is a modern, high-performance programming language that combines:

- **Security-first design**: Built-in functions for cryptography, network scanning, vulnerability assessment, and compliance checking
- **Simple syntax**: Python-like syntax that's easy to learn and read
- **Fast execution**: Optimized stack-based VM with ~450μs per operation
- **Memory safety**: Automatic memory management with garbage collection
- **Rich standard library**: 70+ built-in functions for security operations

## Who Should Use Sentra?

Sentra is perfect for:

- **Security Engineers** building defensive security tools
- **DevSecOps Teams** automating security workflows
- **Compliance Officers** implementing compliance checks
- **Security Researchers** developing proof-of-concepts
- **System Administrators** creating security automation scripts

## What You'll Learn

This tutorial covers:

1. **Getting Started**: Installation and your first program
2. **Basic Syntax**: Variables, functions, and control flow
3. **Data Types**: Working with numbers, strings, arrays, and maps
4. **Functions**: Creating and using functions
5. **Modules**: Organizing code with modules
6. **Error Handling**: Managing errors gracefully
7. **Security Features**: Using built-in security capabilities
8. **Best Practices**: Writing clean, secure Sentra code

## Prerequisites

You should have:

- Basic programming knowledge (any language)
- A computer running Windows, macOS, or Linux
- Command line familiarity

## A Quick Example

Here's a simple Sentra program that demonstrates key features:

```sentra
// Security scanner example
import security
import network

fn scan_host(ip) {
    log("Scanning " + ip + "...")
    
    // Port scan
    let ports = network.scan_ports(ip, "1-1000")
    log("Open ports: " + str(ports.open_ports))
    
    // Security assessment
    let risk = security.assess_risk({
        "host": ip,
        "ports": ports.open_ports
    })
    
    if risk.score > 70 {
        log("⚠️ HIGH RISK: " + risk.description)
    } else {
        log("✅ Risk level acceptable")
    }
    
    return risk
}

// Main execution
let targets = ["192.168.1.1", "192.168.1.100"]
for target in targets {
    try {
        let result = scan_host(target)
        log("Scan complete for " + target)
    } catch (error) {
        log("Error scanning " + target + ": " + error)
    }
}
```

## Let's Get Started!

Ready to learn Sentra? Continue to the [Installation](/tutorial/installation/) guide to set up your development environment.

---

<div class="tutorial-nav">
    <a href="/tutorial/" class="nav-prev">← Tutorial Home</a>
    <a href="/tutorial/installation/" class="nav-next">Installation →</a>
</div>