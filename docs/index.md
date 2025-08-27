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

[Get Started Now]({{ site.baseurl }}/installation){: .btn .btn-primary .fs-5 .mb-4 .mb-md-0 .mr-2 }
[View on GitHub](https://github.com/sentra-language/sentra){: .btn .fs-5 .mb-4 .mb-md-0 }

---

## What is Sentra?

Sentra is a high-performance programming language built specifically for security operations, network programming, and cybersecurity tool development. It combines the ease of use of modern scripting languages with powerful built-in networking capabilities and security-focused libraries.

### Key Features

- **Built-in Network Programming**: TCP/UDP sockets, HTTP client/server, WebSockets
- **Security Tools**: Port scanning, traffic analysis, SSL/TLS inspection, vulnerability assessment
- **High Performance**: Stack-based virtual machine with optimized bytecode execution
- **Modern Language Features**: Functions, closures, arrays, maps, error handling, modules
- **Easy to Learn**: Clean syntax inspired by modern languages
- **Cross-Platform**: Runs on Windows, macOS, and Linux

## Getting Started

### Quick Installation

**Download Binary** (Recommended)
```bash
# Download for your platform from GitHub releases
curl -L https://github.com/sentra-language/sentra/releases/latest/download/sentra-linux-amd64 -o sentra
chmod +x sentra
sudo mv sentra /usr/local/bin/
```

**Build from Source**
```bash
git clone https://github.com/sentra-language/sentra.git
cd sentra
make sentra
```

### Your First Program

Create `hello.sn`:
```sentra
log("Hello, Sentra!")

// Network example
let response = http_get("https://httpbin.org/json")
log("Status: " + str(response["status_code"]))
```

Run it:
```bash
sentra run hello.sn
```

## Language Highlights

### Network Programming Made Easy

```sentra
// TCP Server
let server = socket_listen("TCP", "127.0.0.1", 8080)
let client = socket_accept(server)
let message = socket_receive(client, 1024)
socket_send(client, "Hello from server!")

// HTTP Server
let server = http_server_create("127.0.0.1", 8080)
http_server_route(server["id"], "GET", "/", fn(req) {
    return http_response(200, "Hello World!", {})
})
http_server_start(server["id"])

// WebSocket Client
let conn = ws_connect("wss://echo.websocket.org")
ws_send(conn["id"], "Hello WebSocket!")
let response = ws_receive(conn["id"], 5)
```

### Security Tools

```sentra
// Port Scanning
let results = port_scan("192.168.1.1", 1, 1000, "TCP")
for (let port in results) {
    if (port["state"] == "open") {
        log("Open port: " + str(port["port"]))
    }
}

// SSL Analysis
let ssl = analyze_ssl("example.com", 443)
log("SSL Grade: " + ssl["grade"])
log("Issues: " + str(ssl["security_issues"]))
```

### Modern Language Features

```sentra
// Functions and Closures
fn create_counter() {
    let count = 0
    return fn() {
        count = count + 1
        return count
    }
}

let counter = create_counter()
log(counter())  // 1
log(counter())  // 2

// Arrays and Maps
let users = [
    {"name": "Alice", "role": "admin"},
    {"name": "Bob", "role": "user"}
]

for (let user in users) {
    log("User: " + user["name"] + " (" + user["role"] + ")")
}

// Error Handling
try {
    let data = file_read("config.json")
    let config = json_parse(data)
} catch (error) {
    log("Error loading config: " + error)
}
```

## Documentation

### Tutorial
{: .text-delta }

Start here if you're new to Sentra. A hands-on introduction to the language fundamentals.

- [Installation]({{ site.baseurl }}/installation) - Get Sentra up and running
- [Your First Program]({{ site.baseurl }}/first-program) - Write your first Sentra program
- [Data Types]({{ site.baseurl }}/data-types) - Learn about variables and data types
- [Network Programming]({{ site.baseurl }}/network-programming) - Explore networking capabilities
- [Project Management]({{ site.baseurl }}/project-management) - Create and manage projects

### Reference
{: .text-delta }

Complete documentation of Sentra's language features and standard library.

- [Language Reference]({{ site.baseurl }}/LANGUAGE_REFERENCE) - Syntax and language elements
- [Standard Library]({{ site.baseurl }}/STDLIB_REFERENCE) - Built-in functions and modules
- [Quick Start]({{ site.baseurl }}/QUICK_START) - Quick reference guide

## Use Cases

- **Security Operations**: Build custom security tools and scripts
- **Network Monitoring**: Create network monitoring and analysis tools
- **API Development**: Build REST APIs and web services
- **Automation**: Automate security tasks and workflows
- **Penetration Testing**: Develop custom penetration testing tools
- **Incident Response**: Create incident response and forensics tools

## Community and Support

- [GitHub Repository](https://github.com/sentra-language/sentra) - Source code, issues, and contributions
- [Examples](https://github.com/sentra-language/sentra/tree/main/examples) - Sample programs and use cases

---

Ready to start building security tools with Sentra? [Get Started Now]({{ site.baseurl }}/installation)!