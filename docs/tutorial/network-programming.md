---
layout: default
title: Network Programming
parent: Tutorial
nav_order: 4
---

# Network Programming in Sentra

Sentra provides comprehensive networking capabilities built into the language, making it ideal for security operations, network tools, and distributed applications.

## TCP/UDP Sockets

### TCP Server
```sentra
// Create TCP server
let server = socket_listen("TCP", "127.0.0.1", 8080)
log("Server listening on: " + server)

// Accept client connection
let client = socket_accept(server)
log("Client connected: " + client)

// Receive data
let message = socket_receive(client, 1024)
log("Received: " + message)

// Send response
socket_send(client, "Hello from server!")

// Clean up
socket_close(client)
socket_close(server)
```

### TCP Client
```sentra
// Connect to server
let client = socket_create("TCP", "127.0.0.1", 8080)

// Send data
socket_send(client, "Hello from client!")

// Receive response
let response = socket_receive(client, 1024)
log("Server says: " + response)

// Close connection
socket_close(client)
```

### UDP Socket
```sentra
// Create UDP socket
let socket = socket_create("UDP", "127.0.0.1", 9999)

// Send datagram
socket_send(socket, "UDP message")

// Receive datagram
let data = socket_receive(socket, 1024)

socket_close(socket)
```

## HTTP Client

### Basic Requests
```sentra
// GET request
let response = http_get("https://api.example.com/data")
log("Status: " + str(response["status_code"]))
log("Body: " + response["body"])

// POST request
let headers = {
    "Content-Type": "application/json",
    "Authorization": "Bearer token123"
}
let body = "{\"name\":\"test\",\"value\":123}"
let result = http_post("https://api.example.com/data", body, headers)

// PUT request
http_put(url, body, headers)

// DELETE request
http_delete(url)
```

### Advanced HTTP
```sentra
// Custom request
let response = http_request("PATCH", url, headers, body)

// JSON API request
let data = {
    "user": "admin",
    "action": "update",
    "values": [1, 2, 3]
}
let result = http_json("POST", "https://api.example.com/json", data)

// Download file
let content = http_download("https://example.com/file.zip")
file_write("downloaded.zip", content)
```

## HTTP Server

### Creating a Server
```sentra
// Create HTTP server
let server = http_server_create("127.0.0.1", 8080)

// Add routes
http_server_route(server["id"], "GET", "/", fn(req) {
    return http_response(200, "Welcome!", {
        "Content-Type": "text/plain"
    })
})

// API endpoint
http_server_route(server["id"], "GET", "/api/status", fn(req) {
    return http_response(200, "{\"status\":\"ok\"}", {
        "Content-Type": "application/json"
    })
})

// Handle POST data
http_server_route(server["id"], "POST", "/data", fn(req) {
    log("Received: " + req["body"])
    return http_response(201, "Created", {})
})

// Serve static files
http_server_static(server["id"], "/static/", "./public")

// Start server
http_server_start(server["id"])
log("Server running on http://127.0.0.1:8080")

// Later: stop server
http_server_stop(server["id"])
```

## WebSocket Client

### Basic WebSocket Usage
```sentra
// Connect to WebSocket server
let conn = ws_connect("wss://echo.websocket.org")

// Send text message
ws_send(conn["id"], "Hello WebSocket!")

// Receive message (with timeout in seconds)
let message = ws_receive(conn["id"], 5)
log("Received: " + message)

// Send binary data
ws_send_binary(conn["id"], "Binary data here")

// Send ping
ws_ping(conn["id"])

// Close connection
ws_close(conn["id"])
```

## WebSocket Server

### Complete WebSocket Server
```sentra
// Create WebSocket server
let server = ws_listen("127.0.0.1", 8765)
log("WebSocket server on ws://127.0.0.1:8765")

// Accept new connections
let client = ws_server_accept(server["id"], 5)  // 5 second timeout
if (client) {
    log("New client: " + client["id"])
    
    // Send welcome message
    ws_server_send_to(server["id"], client["id"], "Welcome!")
}

// Get all connected clients
let clients = ws_server_get_clients(server["id"])
log("Connected clients: " + str(len(clients)))

// Broadcast to all clients
ws_server_broadcast(server["id"], "Server message to all")

// Receive from specific client
let msg = ws_server_receive_from(server["id"], client_id)

// Disconnect a client
ws_server_disconnect(server["id"], client_id)

// Stop server
ws_server_stop(server["id"])
```

### WebSocket Chat Room Example
```sentra
// Simple chat server
let server = ws_listen("127.0.0.1", 8888)
let users = {}  // Map of client_id to username

while (true) {
    // Check for new connections
    let new_client = ws_server_wait_connection(server["id"], 1)
    if (new_client) {
        ws_server_send_to(server["id"], new_client["id"], 
            "Enter your username:")
        
        let username = ws_server_receive_from(server["id"], 
            new_client["id"])
        users[new_client["id"]] = username
        
        ws_server_broadcast(server["id"], 
            username + " joined the chat")
    }
    
    // Check for messages from all clients
    let all_clients = ws_server_get_clients(server["id"])
    for (let i = 0; i < len(all_clients); i = i + 1) {
        let client_id = all_clients[i]
        let message = ws_server_receive_from(server["id"], client_id)
        
        if (message) {
            let formatted = "[" + users[client_id] + "]: " + message
            ws_server_broadcast(server["id"], formatted)
        }
    }
}
```

## Network Security Tools

### Port Scanning
```sentra
// Scan ports
let results = port_scan("192.168.1.1", 1, 1000, "TCP")
for (let i = 0; i < len(results); i = i + 1) {
    let port = results[i]
    if (port["state"] == "open") {
        log("Port " + str(port["port"]) + " is open")
        log("  Service: " + port["service"])
        log("  Banner: " + port["banner"])
    }
}
```

### Network Discovery
```sentra
// Scan network
let hosts = network_scan("192.168.1.0/24")
for (let i = 0; i < len(hosts); i = i + 1) {
    let host = hosts[i]
    log("Found: " + host["ip"])
    log("  Hostname: " + host["hostname"])
    log("  MAC: " + host["mac"])
    log("  OS: " + host["os"])
}
```

### DNS Operations
```sentra
// DNS lookups
let ips = dns_lookup("example.com", "A")        // IPv4
let ipv6 = dns_lookup("example.com", "AAAA")    // IPv6
let mx = dns_lookup("example.com", "MX")        // Mail servers
let txt = dns_lookup("example.com", "TXT")      // TXT records
let ns = dns_lookup("example.com", "NS")        // Name servers
let cname = dns_lookup("example.com", "CNAME")  // Canonical name
```

### Traffic Analysis
```sentra
// Analyze network traffic
let analysis = analyze_traffic("eth0", 10)  // 10 seconds
log("Total packets: " + str(analysis["total_packets"]))
log("Total bytes: " + str(analysis["total_bytes"]))
log("Top sources: " + str(analysis["top_sources"]))
log("Suspicious IPs: " + str(analysis["suspicious_ips"]))
```

### SSL/TLS Analysis
```sentra
// Analyze SSL certificate and configuration
let ssl = analyze_ssl("example.com", 443)
log("SSL Version: " + ssl["ssl_version"])
log("Cipher Suite: " + ssl["cipher_suite"])
log("Certificate: " + str(ssl["certificate_info"]))
log("Security Grade: " + ssl["grade"])
log("Issues: " + str(ssl["security_issues"]))
```

## Security Operations Examples

### Network Monitor
```sentra
// Continuous network monitoring
while (true) {
    // Check for intrusions
    let intrusions = detect_intrusions("eth0", 5)
    for (let i = 0; i < len(intrusions); i = i + 1) {
        let alert = intrusions[i]
        log("ALERT: " + alert["alert_type"])
        log("  Severity: " + alert["severity"])
        log("  Source: " + alert["source_ip"])
        log("  Description: " + alert["description"])
    }
    
    sleep(5000)  // Check every 5 seconds
}
```

### Security Scanner
```sentra
// Comprehensive security scan
fn security_scan(target) {
    log("Scanning " + target + "...")
    
    // Port scan
    let ports = port_scan(target, 1, 65535, "TCP")
    let open_ports = []
    for (let i = 0; i < len(ports); i = i + 1) {
        if (ports[i]["state"] == "open") {
            push(open_ports, ports[i])
        }
    }
    
    // Check for vulnerabilities
    for (let i = 0; i < len(open_ports); i = i + 1) {
        let port = open_ports[i]
        
        // Check SSL if HTTPS
        if (port["port"] == 443) {
            let ssl = analyze_ssl(target, 443)
            if (len(ssl["security_issues"]) > 0) {
                log("SSL vulnerabilities found!")
            }
        }
        
        // Check for weak services
        if (port["service"] == "telnet") {
            log("WARNING: Insecure telnet service found!")
        }
    }
    
    return open_ports
}
```

### API Gateway
```sentra
// Simple API gateway with rate limiting
let server = http_server_create("0.0.0.0", 8080)
let rate_limits = {}  // Track requests per IP

http_server_route(server["id"], "ANY", "/api/*", fn(req) {
    let client_ip = req["headers"]["X-Forwarded-For"]
    
    // Rate limiting
    if (!rate_limits[client_ip]) {
        rate_limits[client_ip] = 0
    }
    rate_limits[client_ip] = rate_limits[client_ip] + 1
    
    if (rate_limits[client_ip] > 100) {
        return http_response(429, "Too Many Requests", {})
    }
    
    // Forward to backend
    let backend_url = "http://backend:3000" + req["path"]
    let response = http_request(req["method"], backend_url, 
                                req["headers"], req["body"])
    
    return http_response(response["status_code"], 
                         response["body"], 
                         response["headers"])
})

http_server_start(server["id"])
```

## Best Practices

1. **Always close connections** - Use `socket_close()`, `ws_close()` to prevent resource leaks
2. **Handle timeouts** - Set appropriate timeouts for network operations
3. **Error handling** - Check return values and handle network failures gracefully
4. **Security** - Validate input, use HTTPS/WSS, implement authentication
5. **Rate limiting** - Implement rate limiting for servers to prevent abuse
6. **Logging** - Log network events for debugging and security monitoring

## Performance Tips

- Use connection pooling for HTTP requests to the same server
- Implement caching for frequently accessed data
- Use WebSockets for real-time communication instead of polling
- Batch network operations when possible
- Monitor network usage and optimize data transfer

## Next Steps

- Build a [Security Scanner](/examples/security-scanner)
- Create a [REST API](/examples/rest-api)
- Implement a [Chat Application](/examples/chat-app)
- Develop a [Network Monitor](/examples/network-monitor)