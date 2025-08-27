---
layout: default
title: Getting Started
nav_order: 1
parent: Tutorial
permalink: /tutorial/getting-started
---

# Getting Started with Sentra

## Installation

### Binary Installation

Download the latest release for your platform:
- [Windows](https://github.com/sentra-language/sentra/releases)
- [macOS](https://github.com/sentra-language/sentra/releases)
- [Linux](https://github.com/sentra-language/sentra/releases)

### Building from Source

```bash
git clone https://github.com/sentra-language/sentra
cd sentra
make sentra
```

## Your First Program

Create a file called `hello.sn`:

```sentra
// hello.sn
log("Hello, Sentra!")

// Variables
let name = "World"
log("Hello, " + name + "!")

// Functions
fn greet(person) {
    return "Welcome, " + person
}

log(greet("Developer"))
```

Run it:
```bash
./sentra run hello.sn
```

## Network Programming Example

Sentra has powerful networking capabilities built-in:

```sentra
// Create an HTTP server
let server = http_server_create("127.0.0.1", 8080)

// Add a route
http_server_route(server["id"], "GET", "/", fn(req) {
    return http_response(200, "Hello from Sentra!", {
        "Content-Type": "text/plain"
    })
})

// Start server
http_server_start(server["id"])
log("Server running on http://127.0.0.1:8080")
```

## What's Next?

- Learn about [Data Types]({{ site.baseurl }}/tutorial/data-types)
- Explore [Functions]({{ site.baseurl }}/tutorial/functions)
- Master [Network Programming]({{ site.baseurl }}/tutorial/networking)