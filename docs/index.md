---
layout: default
title: Home
nav_order: 1
description: "Sentra is a security-focused programming language with built-in network capabilities and cybersecurity tools"
permalink: /
---

# Sentra Programming Language
{: .fs-9 }

A modern, security-focused programming language designed for cybersecurity professionals, network engineers, and developers building security tools.
{: .fs-6 .fw-300 }

[Quick Start Guide]({{ site.baseurl }}/quick-start/){: .btn .btn-primary .fs-5 .mb-4 .mb-md-0 .mr-2 }
[View on GitHub](https://github.com/sentra-language/sentra){: .btn .fs-5 .mb-4 .mb-md-0 }

---

{: .highlight }
Sentra combines the simplicity of modern scripting languages with powerful built-in networking capabilities and security-focused tools, making it ideal for cybersecurity professionals and network engineers.

## Why Sentra?

**Built for Security**
{: .text-green-300 }
Native support for network security operations, vulnerability scanning, traffic analysis, and penetration testing tools.

**Network-First Design**
{: .text-blue-300 }
TCP/UDP sockets, HTTP client/server, WebSockets, and SSL/TLS analysis built directly into the language.

**High Performance**
{: .text-purple-300 }
Stack-based virtual machine with optimized bytecode execution for production workloads.

**Easy to Learn**
{: .text-yellow-300 }
Clean, modern syntax that's familiar to developers coming from Python, JavaScript, or Go.

---

## Quick Example

Create a simple network scanner in just a few lines:

```sentra
// Port scanner example
let target = "192.168.1.1"
let results = port_scan(target, 1, 1000, "TCP")

for (let port in results) {
    if (port["state"] == "open") {
        log("Open: " + str(port["port"]) + " (" + port["service"] + ")")
    }
}

// HTTP API example  
let server = http_server_create("127.0.0.1", 8080)
http_server_route(server["id"], "GET", "/status", fn(req) {
    return http_response(200, "{\"status\":\"online\"}", {
        "Content-Type": "application/json"
    })
})
http_server_start(server["id"])
```

---

## Learning Path

### 1. Get Started
{: .text-delta }

New to Sentra? Start here for a quick introduction and setup.

[Quick Start Guide]({{ site.baseurl }}/quick-start/){: .btn .btn-outline .mr-2 }
[Installation]({{ site.baseurl }}/tutorial/installation/){: .btn .btn-outline }

### 2. Learn the Basics  
{: .text-delta }

Master the fundamentals with step-by-step tutorials.

[Your First Program]({{ site.baseurl }}/tutorial/first-program/){: .btn .btn-outline .mr-2 }
[Language Basics]({{ site.baseurl }}/tutorial/language-basics/){: .btn .btn-outline }

### 3. Build Real Applications
{: .text-delta }

Learn network programming and security tool development.

[Network Programming]({{ site.baseurl }}/tutorial/network-programming/){: .btn .btn-outline .mr-2 }
[Security Tools]({{ site.baseurl }}/tutorial/security-tools/){: .btn .btn-outline }

### 4. Reference Materials
{: .text-delta }

Complete documentation for advanced usage.

[Language Reference]({{ site.baseurl }}/reference/language/){: .btn .btn-outline .mr-2 }
[Standard Library]({{ site.baseurl }}/reference/stdlib/){: .btn .btn-outline }

---

## Use Cases

<div class="code-example" markdown="1">
**Security Operations Centers (SOCs)**

Automate threat detection, incident response, and security monitoring workflows.

**Penetration Testing**

Build custom scanners, exploit tools, and security assessment scripts.

**Network Engineering** 

Create network monitoring tools, traffic analyzers, and infrastructure automation.

**DevSecOps**

Integrate security testing into CI/CD pipelines and development workflows.

**Research & Education**

Teach network security concepts with hands-on, practical examples.
</div>

---

## Key Features

| Feature | Description |
|:--------|:------------|
| **Network Programming** | TCP/UDP sockets, HTTP client/server, WebSockets with built-in functions |
| **Security Tools** | Port scanning, SSL/TLS analysis, vulnerability detection, traffic monitoring |
| **Modern Language** | Functions, closures, arrays, maps, error handling, module system |
| **High Performance** | Optimized virtual machine with minimal overhead |
| **Cross Platform** | Runs on Windows, macOS, and Linux |
| **Easy Deployment** | Single binary with no external dependencies |

---

## Community

[GitHub Repository](https://github.com/sentra-language/sentra){: .btn .btn-outline .mr-2 }
[Issue Tracker](https://github.com/sentra-language/sentra/issues){: .btn .btn-outline .mr-2 }
[Examples](https://github.com/sentra-language/sentra/tree/main/examples){: .btn .btn-outline }