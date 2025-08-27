---
layout: default
title: Network Module
parent: Tutorial
nav_order: 5
---

# Network Module
{: .fs-9 }

Master Sentra's built-in network programming capabilities for TCP/UDP, HTTP, and WebSocket communication.
{: .fs-6 .fw-300 }

---

## TCP/UDP Sockets

### TCP Server

```sentra
// Create a simple TCP echo server
fn start_tcp_server() {
    let server = socket_listen("TCP", "127.0.0.1", 8080)
    log("TCP server listening on port 8080")
    
    while (true) {
        let client = socket_accept(server)
        log("Client connected: " + client)
        
        // Handle client in a simple way
        let message = socket_receive(client, 1024)
        if (message) {
            log("Received: " + message)
            socket_send(client, "Echo: " + message)
        }
        
        socket_close(client)
    }
}

// start_tcp_server()  // Uncomment to run
```

### TCP Client

```sentra
// Connect to TCP server
fn tcp_client_example() {
    let client = socket_create("TCP", "127.0.0.1", 8080)
    
    // Send message
    socket_send(client, "Hello, Server!")
    
    // Receive response
    let response = socket_receive(client, 1024)
    log("Server responded: " + response)
    
    // Clean up
    socket_close(client)
}

tcp_client_example()
```

### UDP Communication

```sentra
// UDP server
fn udp_server() {
    let server = socket_listen("UDP", "127.0.0.1", 9999)
    log("UDP server listening on port 9999")
    
    while (true) {
        let data = socket_receive(server, 1024)
        if (data) {
            log("Received UDP: " + data)
            socket_send(server, "UDP Echo: " + data)
        }
    }
}

// UDP client
fn udp_client() {
    let client = socket_create("UDP", "127.0.0.1", 9999)
    
    socket_send(client, "Hello UDP!")
    let response = socket_receive(client, 1024)
    log("UDP response: " + response)
    
    socket_close(client)
}

udp_client()
```

---

## HTTP Client

### Basic HTTP Requests

```sentra
// GET request
let response = http_get("https://httpbin.org/json")
log("Status: " + str(response["status_code"]))
log("Headers: " + str(response["headers"]))
log("Body: " + response["body"])

// POST request with data
let headers = {
    "Content-Type": "application/json",
    "User-Agent": "Sentra/1.0"
}

let data = '{"username": "test", "action": "login"}'
let post_response = http_post("https://httpbin.org/post", data, headers)
log("POST response: " + str(post_response["status_code"]))

// Other HTTP methods
let put_response = http_put("https://httpbin.org/put", data, headers)
let delete_response = http_delete("https://httpbin.org/delete")
```

### Advanced HTTP Operations

```sentra
// Custom request with full control
fn advanced_http_request() {
    let custom_response = http_request("PATCH", "https://httpbin.org/patch", {
        "Authorization": "Bearer token123",
        "Accept": "application/json"
    }, '{"field": "updated"}')
    
    return custom_response
}

// Download file
fn download_file(url, filename) {
    log("Downloading " + url + "...")
    let content = http_download(url)
    file_write(filename, content)
    log("Downloaded to " + filename)
}

// download_file("https://httpbin.org/json", "sample.json")
```

---

## HTTP Server

### Creating Web APIs

```sentra
// Complete HTTP API server
fn start_web_api() {
    let server = http_server_create("127.0.0.1", 8080)
    
    // Health check endpoint
    http_server_route(server["id"], "GET", "/health", fn(req) {
        return http_response(200, '{"status": "healthy", "timestamp": ' + str(time()) + '}', {
            "Content-Type": "application/json"
        })
    })
    
    // Echo endpoint
    http_server_route(server["id"], "POST", "/echo", fn(req) {
        return http_response(200, req["body"], {
            "Content-Type": "application/json"
        })
    })
    
    // Network scan endpoint
    http_server_route(server["id"], "POST", "/scan", fn(req) {
        // Simple scan (would parse JSON body in real implementation)
        let target = "127.0.0.1"
        let results = port_scan(target, 1, 100, "TCP")
        
        let open_count = 0
        for (let port in results) {
            if (port["state"] == "open") {
                open_count = open_count + 1
            }
        }
        
        let response_data = '{"target": "' + target + '", "open_ports": ' + str(open_count) + '}'
        return http_response(200, response_data, {
            "Content-Type": "application/json"
        })
    })
    
    // Serve static files
    http_server_static(server["id"], "/static/", "./public")
    
    // Start the server
    http_server_start(server["id"])
    log("Web API running at http://127.0.0.1:8080")
    
    // Keep running
    while (true) {
        sleep(1000)
    }
}

// start_web_api()  // Uncomment to run
```

---

## WebSocket Communication

### WebSocket Client

```sentra
// Connect to WebSocket server
fn websocket_client_example() {
    let conn = ws_connect("wss://echo.websocket.org")
    
    if (conn) {
        log("Connected to WebSocket server")
        
        // Send messages
        ws_send(conn["id"], "Hello WebSocket!")
        ws_send(conn["id"], "This is a test message")
        
        // Receive messages
        for (let i = 0; i < 2; i = i + 1) {
            let message = ws_receive(conn["id"], 5)  // 5 second timeout
            if (message) {
                log("Received: " + message)
            }
        }
        
        // Close connection
        ws_close(conn["id"])
        log("WebSocket connection closed")
    }
}

websocket_client_example()
```

### WebSocket Server

```sentra
// WebSocket chat server
fn websocket_chat_server() {
    let server = ws_listen("127.0.0.1", 8765)
    log("WebSocket server running on ws://127.0.0.1:8765")
    
    let users = {}
    
    while (true) {
        // Accept new connections
        let new_client = ws_server_accept(server["id"], 1)  // 1 second timeout
        if (new_client) {
            log("New client connected: " + new_client["id"])
            
            // Send welcome message
            ws_server_send_to(server["id"], new_client["id"], "Welcome to Sentra Chat!")
            
            // Ask for username
            ws_server_send_to(server["id"], new_client["id"], "Please enter your username:")
            let username = ws_server_receive_from(server["id"], new_client["id"])
            
            if (username) {
                users[new_client["id"]] = username
                ws_server_broadcast(server["id"], username + " joined the chat")
            }
        }
        
        // Handle messages from all clients
        let clients = ws_server_get_clients(server["id"])
        for (let i = 0; i < len(clients); i = i + 1) {
            let client_id = clients[i]
            let message = ws_server_receive_from(server["id"], client_id)
            
            if (message) {
                let username = users[client_id] || "Unknown"
                let formatted = "[" + username + "]: " + message
                log("Broadcasting: " + formatted)
                ws_server_broadcast(server["id"], formatted)
            }
        }
        
        sleep(100)  // Small delay to prevent busy waiting
    }
}

// websocket_chat_server()  // Uncomment to run
```

---

## Practical Example: Network Monitor

```sentra
// Network monitoring tool
fn network_monitor() {
    log("Starting network monitor...")
    
    // Hosts to monitor
    let hosts = ["google.com", "github.com", "stackoverflow.com"]
    let results = {}
    
    // Check each host
    for (let host in hosts) {
        log("Checking " + host + "...")
        
        // HTTP health check
        try {
            let start_time = time()
            let response = http_get("https://" + host)
            let end_time = time()
            let response_time = end_time - start_time
            
            results[host] = {
                "status": "up",
                "http_status": response["status_code"],
                "response_time": response_time,
                "server": response["headers"]["Server"] || "Unknown"
            }
            
            log(host + " is UP (HTTP " + str(response["status_code"]) + 
                ", " + str(response_time) + "ms)")
                
        } catch (error) {
            results[host] = {
                "status": "down",
                "error": error
            }
            log(host + " is DOWN: " + error)
        }
        
        sleep(1000)  // Wait 1 second between checks
    }
    
    // Generate report
    log("\n=== Network Monitor Report ===")
    for (let host in results) {
        let result = results[host]
        if (result["status"] == "up") {
            log(host + ": UP - " + str(result["response_time"]) + "ms")
        } else {
            log(host + ": DOWN - " + result["error"])
        }
    }
    
    return results
}

network_monitor()
```

---

## Network Utilities

### DNS Operations

```sentra
// DNS lookup functions
fn dns_operations() {
    let domain = "example.com"
    
    // Different record types
    let a_records = dns_lookup(domain, "A")        // IPv4 addresses
    let aaaa_records = dns_lookup(domain, "AAAA")  // IPv6 addresses  
    let mx_records = dns_lookup(domain, "MX")      // Mail servers
    let txt_records = dns_lookup(domain, "TXT")    // TXT records
    let ns_records = dns_lookup(domain, "NS")      // Name servers
    
    log("A records: " + str(a_records))
    log("MX records: " + str(mx_records))
    log("TXT records: " + str(txt_records))
}

dns_operations()
```

### Network Analysis

```sentra
// Analyze network traffic (simulated)
fn analyze_network() {
    log("Analyzing network traffic...")
    
    // This would analyze real network interface in production
    let analysis = analyze_traffic("eth0", 10)  // 10 seconds
    
    log("Traffic Analysis Results:")
    log("Total packets: " + str(analysis["total_packets"]))
    log("Total bytes: " + str(analysis["total_bytes"]))
    log("Top sources: " + str(analysis["top_sources"]))
    log("Suspicious IPs: " + str(analysis["suspicious_ips"]))
}
```

---

## Next Steps

Now that you understand network programming:

- [Security Module](../security-module/) - Security tools and vulnerability scanning
- [Project Management](../project-management/) - Managing larger projects
- [Network Functions Reference](../../reference/language/) - Complete API documentation
- [Examples on GitHub](https://github.com/sentra-language/sentra/tree/main/examples) - Sample network applications

---

{: .fs-6 .fw-300 }
With network programming mastered, let's explore Sentra's built-in security tools and vulnerability scanning capabilities.

[← Previous: Standard Library](../standard-library/){: .btn .btn-outline .mr-2 }
[Next: Security Module →](../security-module/){: .btn .btn-primary }

---

## Network Function Reference

### Socket Functions
- `socket_listen(protocol, host, port)` - Create server socket
- `socket_accept(server)` - Accept client connection
- `socket_create(protocol, host, port)` - Create client socket
- `socket_send(socket, data)` - Send data
- `socket_receive(socket, size)` - Receive data
- `socket_close(socket)` - Close connection

### HTTP Client Functions  
- `http_get(url)` - GET request
- `http_post(url, body, headers)` - POST request
- `http_put(url, body, headers)` - PUT request
- `http_delete(url)` - DELETE request
- `http_request(method, url, headers, body)` - Custom request
- `http_download(url)` - Download file

### HTTP Server Functions
- `http_server_create(host, port)` - Create server
- `http_server_route(id, method, path, handler)` - Add route
- `http_server_static(id, path, directory)` - Serve static files
- `http_server_start(id)` - Start server
- `http_server_stop(id)` - Stop server
- `http_response(status, body, headers)` - Create response

### WebSocket Functions
- `ws_connect(url)` - Connect to server
- `ws_send(id, message)` - Send message
- `ws_receive(id, timeout)` - Receive message  
- `ws_close(id)` - Close connection
- `ws_listen(host, port)` - Create server
- `ws_server_accept(id, timeout)` - Accept client
- `ws_server_broadcast(id, message)` - Broadcast to all
- `ws_server_send_to(id, client_id, message)` - Send to specific client

### Network Utilities
- `dns_lookup(domain, type)` - DNS resolution
- `analyze_traffic(interface, duration)` - Traffic analysis