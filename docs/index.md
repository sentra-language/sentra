---
layout: default
title: "Sentra Programming Language"
description: "A security-focused programming language with built-in defensive security capabilities"
hero:
  title: "Sentra Programming Language"
  subtitle: "Security-first programming with built-in defensive capabilities. Build security tools, compliance checkers, and automation scripts with ease."
  buttons:
    - text: "Get Started"
      url: "/quick-start/"
      class: "btn-primary"
    - text: "View Examples"
      url: "/examples/"
      class: "btn-secondary"
---

<div class="feature-grid">
  <div class="feature-card">
    <div class="feature-icon">🔒</div>
    <h3>Security-First Design</h3>
    <p>Built-in cryptography, network scanning, vulnerability assessment, and compliance checking. 70+ security functions out of the box.</p>
  </div>

  <div class="feature-card">
    <div class="feature-icon">⚡</div>
    <h3>Fast Execution</h3>
    <p>Optimized stack-based VM with ~450μs per operation. Handles 50,000+ loop iterations efficiently for real-world workloads.</p>
  </div>

  <div class="feature-card">
    <div class="feature-icon">🎯</div>
    <h3>Simple Syntax</h3>
    <p>Clean, Python-like syntax that's easy to learn. Focus on solving security problems, not wrestling with complex language features.</p>
  </div>

  <div class="feature-card">
    <div class="feature-icon">🛡️</div>
    <h3>Memory Safe</h3>
    <p>Automatic memory management with garbage collection. No manual allocation or buffer overflows to worry about.</p>
  </div>

  <div class="feature-card">
    <div class="feature-icon">🌐</div>
    <h3>Production Ready</h3>
    <p>Used for web frameworks, batch processing, and enterprise security applications. Comprehensive standard library included.</p>
  </div>

  <div class="feature-card">
    <div class="feature-icon">📦</div>
    <h3>Rich Ecosystem</h3>
    <p>Module system, concurrency support, comprehensive testing framework, and extensive documentation with examples.</p>
  </div>
</div>

## Quick Example

```sentra
// Security scanner in Sentra
fn scanTarget(host) {
    log("Scanning " + host + "...")
    
    // Port scan
    let ports = net_scan(host, "1-1000")
    log("Open ports: " + str(ports["open_ports"]))
    
    // Security assessment
    let risk = security_assess("network", {"ip": host})
    log("Risk score: " + risk["score"] + "/100")
    
    // Check for vulnerabilities
    if risk["score"] > 70 {
        log("⚠️  HIGH RISK detected!")
    } else {
        log("✅ Acceptable risk level")
    }
    
    return risk
}

// Scan multiple targets
let targets = ["192.168.1.1", "192.168.1.100"]
for target in targets {
    try {
        scanTarget(target)
    } catch (error) {
        log("Error scanning " + target + ": " + error)
    }
}
```

## Core Features

### 🔧 Language Features
- **Variables**: `let`, `var`, `const` with proper scoping
- **Functions**: First-class functions, closures, lambdas
- **Collections**: Arrays and maps with rich operations
- **Control Flow**: if/else, for, while, match statements
- **Error Handling**: try/catch/finally with stack traces
- **Modules**: Import/export system for code organization
- **Concurrency**: Goroutines and channels (Go-style)

### 🔐 Security Capabilities
- **Cryptography**: Hash functions, HMAC, encryption/decryption
- **Network Security**: Port scanning, vulnerability assessment
- **Database Security**: SQL injection testing, security scanning
- **Mobile Security**: Device scanning, app security analysis
- **Blockchain Security**: Smart contract auditing
- **Compliance**: SOC2, GDPR, HIPAA, PCI-DSS assessments
- **Threat Detection**: Pattern matching, anomaly detection

### 📊 Performance Characteristics

| Operation | Time | Memory | Suitable For |
|-----------|------|--------|--------------|
| Arithmetic | ~442μs | 1.2MB | ✅ High-frequency calculations |
| Function Calls | ~651μs | 1.2MB | ✅ Complex business logic |
| Array Operations | ~480μs | 1.2MB | ✅ Data processing |
| Network Operations | ~500ms | 2MB | ✅ Security scanning |
| Large Loops (50k+) | ~2-3s | 1.2MB | ✅ Batch processing |

## Use Cases

Sentra is perfect for:

<div class="feature-grid">
  <div class="card">
    <h3>🔍 Security Automation</h3>
    <p>Automated vulnerability scanning, threat detection, and incident response workflows.</p>
  </div>

  <div class="card">
    <h3>✅ Compliance Checking</h3>
    <p>SOC2, GDPR, HIPAA compliance validation and reporting automation.</p>
  </div>

  <div class="card">
    <h3>🌐 Web Security</h3>
    <p>Security-focused web applications, APIs, and middleware with built-in protections.</p>
  </div>

  <div class="card">
    <h3>📊 Security Orchestration</h3>
    <p>Coordinating multiple security tools and creating comprehensive security workflows.</p>
  </div>
</div>

## Language Comparison

| Feature | Sentra | Python | JavaScript | Go |
|---------|--------|--------|------------|---|
| **Security Functions** | ✅ 70+ built-in | ❌ External libs | ❌ External libs | ❌ External libs |
| **Learning Curve** | ✅ Easy | ✅ Easy | ✅ Easy | ⚠️ Moderate |
| **Performance** | ✅ Good | ⚠️ Slower | ✅ Fast | ✅ Very Fast |
| **Memory Safety** | ✅ Yes | ✅ Yes | ✅ Yes | ⚠️ Manual |
| **Concurrency** | ✅ Goroutines | ⚠️ Limited | ⚠️ Event loop | ✅ Goroutines |
| **Security Focus** | ✅ Core feature | ❌ Third-party | ❌ Third-party | ❌ Third-party |

## Getting Started

<div class="code-example">
  <div class="example-header">Installation</div>
  <pre><code class="language-bash"># Clone and build Sentra
git clone https://github.com/yourusername/sentra.git
cd sentra
make sentra

# Start the interactive REPL
./sentra repl

# Run your first program
echo 'log("Hello, Sentra!")' > hello.sn
./sentra run hello.sn</code></pre>
</div>

## Community & Resources

- **📚 Documentation**: Comprehensive guides and API reference
- **🎯 Examples**: Real-world security tools and applications  
- **🐛 Issues**: Report bugs and request features on GitHub
- **💬 Discussions**: Join our community discussions
- **📈 Benchmarks**: Performance analysis and optimization guides

---

<div class="text-center" style="margin: 3rem 0;">
  <h2>Ready to Build Secure Applications?</h2>
  <p style="font-size: 1.125rem; color: #6b7280; margin-bottom: 2rem;">
    Start with our quick start guide and build your first security tool in minutes.
  </p>
  <a href="/quick-start/" class="btn btn-primary" style="margin-right: 1rem;">Get Started</a>
  <a href="https://github.com/yourusername/sentra" class="btn btn-secondary">View on GitHub</a>
</div>