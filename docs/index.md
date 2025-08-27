---
layout: default
title: Home
nav_order: 1
description: "Sentra is a security-focused programming language with built-in network capabilities and cybersecurity tools"
permalink: /
last_modified_date: 2025-08-27
---

# Sentra Programming Language
{: .fs-9 }

A security-focused programming language with built-in networking and cybersecurity capabilities. Write security tools, network scanners, and automation scripts with minimal code.
{: .fs-6 .fw-300 }

[Start Tutorial](tutorial/){: .btn .btn-primary .fs-5 .mb-4 .mb-md-0 .mr-2 }
[View on GitHub](https://github.com/sentra-language/sentra){: .btn .fs-5 .mb-4 .mb-md-0 }

---

## Why Sentra?

Sentra eliminates the complexity of building security tools by providing networking and security capabilities directly in the language. No external libraries, no complicated setup—just write code and run it.

### Network Security Made Simple

```javascript
// Port scanner in 6 lines
let target = "192.168.1.1"
let results = port_scan(target, 1, 1000, "TCP")

for (let port in results) {
    if (port["state"] == "open") {
        log("Open: " + str(port["port"]) + " (" + port["service"] + ")")
    }
}
```

### HTTP APIs Without Frameworks

```javascript
// Complete web API server
let server = http_server_create("127.0.0.1", 8080)

http_server_route(server["id"], "GET", "/scan", fn(req) {
    let results = port_scan("127.0.0.1", 1, 100, "TCP") 
    return http_response(200, "{\"open_ports\": 5}", {
        "Content-Type": "application/json"
    })
})

http_server_start(server["id"])
log("Security API running at http://127.0.0.1:8080")
```

---

## What You Can Build

{: .note }
**Security Operations Centers (SOCs)**: Automate threat detection, incident response workflows, and security monitoring

{: .note }
**Penetration Testing**: Create custom scanners, vulnerability assessments, and security validation tools  

{: .note }
**Network Engineering**: Build traffic analyzers, network monitoring tools, and infrastructure automation

{: .note }
**DevSecOps**: Integrate security testing into CI/CD pipelines with lightweight, fast-running tools

---

## Language Features

| Feature | Description |
|:--------|:------------|
| **Built-in Networking** | TCP/UDP sockets, HTTP client/server, WebSockets |
| **Security Functions** | Port scanning, SSL analysis, vulnerability detection |
| **Modern Syntax** | Clean, readable syntax familiar to JavaScript/Python developers |
| **Single Binary** | No dependencies, runs anywhere |
| **High Performance** | Optimized virtual machine with fast execution |

---

## Quick Installation

**Download and run immediately:**

```bash
# Linux/macOS
curl -L https://github.com/sentra-language/sentra/releases/latest/download/sentra-linux-amd64 -o sentra
chmod +x sentra && sudo mv sentra /usr/local/bin/

# Test installation
sentra run -e 'log("Sentra is ready!")'
```

**Windows:**
```powershell
# Download sentra.exe and add to PATH
curl.exe -L https://github.com/sentra-language/sentra/releases/latest/download/sentra-windows-amd64.exe -o sentra.exe
```

---

## Next Steps

Ready to start building security tools with Sentra?

**[Quick Start Guide](quick-start/)**{: .btn .btn-primary .mr-2 }
**[Complete Tutorial](tutorial/)**{: .btn .btn-green .mr-2 }
**[Language Reference](reference/)**{: .btn .btn-outline }

---

## About the Project

Sentra is open source and actively developed. We welcome contributions from the security community.

### License

Sentra is distributed by an [MIT license](https://github.com/sentra-language/sentra/blob/main/LICENSE).

### Contributing

When contributing to this repository, please first discuss the change you wish to make via issue, email, or any other method with the owners of this repository before making a change. Read more about becoming a contributor in [our GitHub repo](https://github.com/sentra-language/sentra#contributing).

#### Thank you to the contributors of Sentra!

<ul class="list-style-none">
{% for contributor in site.github.contributors %}
  <li class="d-inline-block mr-1">
     <a href="{{ contributor.html_url }}"><img src="{{ contributor.avatar_url }}" width="32" height="32" alt="{{ contributor.login }}"/></a>
  </li>
{% endfor %}
</ul>

### Code of Conduct

Sentra is committed to fostering a welcoming community.

[View our Code of Conduct](https://github.com/sentra-language/sentra/blob/main/CODE_OF_CONDUCT.md) on our GitHub repository.