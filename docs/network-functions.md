---
layout: default
title: Network Functions
nav_order: 6
parent: Standard Library
permalink: /library/network
---

# Network Functions Reference

Complete reference for all network-related functions in Sentra.

## TCP/UDP Socket Functions

### socket_create
Creates a client socket connection.
```sentra
socket_create(type: string, address: string, port: number) -> string
```
- **type**: "TCP" or "UDP"
- **address**: IP address or hostname
- **port**: Port number
- **Returns**: Socket ID string or nil on failure

### socket_listen
Creates a server listener socket.
```sentra
socket_listen(type: string, address: string, port: number) -> string
```
- **type**: "TCP" or "UDP"
- **address**: IP address to bind to
- **port**: Port number to listen on
- **Returns**: Listener ID string or nil on failure

### socket_accept
Accepts a client connection on a TCP listener.
```sentra
socket_accept(listener_id: string) -> string
```
- **listener_id**: ID of the listener socket
- **Returns**: Client socket ID or nil on failure

### socket_send
Sends data through a socket.
```sentra
socket_send(socket_id: string, data: string) -> number
```
- **socket_id**: Socket ID
- **data**: Data to send
- **Returns**: Number of bytes sent or 0 on failure

### socket_receive
Receives data from a socket.
```sentra
socket_receive(socket_id: string, max_bytes: number) -> string
```
- **socket_id**: Socket ID
- **max_bytes**: Maximum bytes to receive
- **Returns**: Received data or nil on failure

### socket_close
Closes a socket or listener.
```sentra
socket_close(socket_id: string) -> boolean
```
- **socket_id**: Socket or listener ID
- **Returns**: true on success, false on failure

## HTTP Client Functions

### http_get
Performs an HTTP GET request.
```sentra
http_get(url: string) -> map
```
- **url**: URL to request
- **Returns**: Response map with status_code, status, body, headers

### http_post
Performs an HTTP POST request.
```sentra
http_post(url: string, body: string, headers: map) -> map
```
- **url**: URL to request
- **body**: Request body
- **headers**: Request headers map
- **Returns**: Response map

### http_put
Performs an HTTP PUT request.
```sentra
http_put(url: string, body: string, headers: map) -> map
```
- **url**: URL to request
- **body**: Request body
- **headers**: Request headers map
- **Returns**: Response map

### http_delete
Performs an HTTP DELETE request.
```sentra
http_delete(url: string) -> map
```
- **url**: URL to request
- **Returns**: Response map

### http_request
Performs a custom HTTP request.
```sentra
http_request(method: string, url: string, headers: map, body: string) -> map
```
- **method**: HTTP method (GET, POST, PUT, DELETE, etc.)
- **url**: URL to request
- **headers**: Request headers
- **body**: Request body
- **Returns**: Response map

### http_json
Performs an HTTP request with JSON body.
```sentra
http_json(method: string, url: string, data: any) -> map
```
- **method**: HTTP method
- **url**: URL to request
- **data**: Data to encode as JSON
- **Returns**: Response map

### http_download
Downloads content from a URL.
```sentra
http_download(url: string) -> string
```
- **url**: URL to download from
- **Returns**: Downloaded content as string

## HTTP Server Functions

### http_server_create
Creates an HTTP server.
```sentra
http_server_create(address: string, port: number) -> map
```
- **address**: IP address to bind to
- **port**: Port number
- **Returns**: Server map with id, address, port

### http_server_route
Adds a route to the HTTP server.
```sentra
http_server_route(server_id: string, method: string, path: string, handler: function) -> boolean
```
- **server_id**: Server ID
- **method**: HTTP method or "ANY"
- **path**: URL path pattern
- **handler**: Handler function(req) -> response
- **Returns**: true on success

### http_server_static
Serves static files from a directory.
```sentra
http_server_static(server_id: string, url_path: string, directory: string) -> boolean
```
- **server_id**: Server ID
- **url_path**: URL prefix
- **directory**: Directory to serve files from
- **Returns**: true on success

### http_server_start
Starts the HTTP server.
```sentra
http_server_start(server_id: string) -> boolean
```
- **server_id**: Server ID
- **Returns**: true on success

### http_server_stop
Stops the HTTP server.
```sentra
http_server_stop(server_id: string) -> boolean
```
- **server_id**: Server ID
- **Returns**: true on success

### http_response
Creates an HTTP response.
```sentra
http_response(status_code: number, body: string, headers: map) -> map
```
- **status_code**: HTTP status code
- **body**: Response body
- **headers**: Response headers
- **Returns**: Response map

## WebSocket Client Functions

### ws_connect
Connects to a WebSocket server.
```sentra
ws_connect(url: string) -> map
```
- **url**: WebSocket URL (ws:// or wss://)
- **Returns**: Connection map with id, url, connected

### ws_send
Sends a text message over WebSocket.
```sentra
ws_send(conn_id: string, message: string) -> boolean
```
- **conn_id**: Connection ID
- **message**: Text message
- **Returns**: true on success

### ws_send_binary
Sends binary data over WebSocket.
```sentra
ws_send_binary(conn_id: string, data: string) -> boolean
```
- **conn_id**: Connection ID
- **data**: Binary data
- **Returns**: true on success

### ws_receive
Receives a message from WebSocket.
```sentra
ws_receive(conn_id: string, timeout_seconds: number) -> string
```
- **conn_id**: Connection ID
- **timeout_seconds**: Timeout in seconds
- **Returns**: Received message or nil

### ws_close
Closes a WebSocket connection.
```sentra
ws_close(conn_id: string) -> boolean
```
- **conn_id**: Connection ID
- **Returns**: true on success

### ws_ping
Sends a ping message.
```sentra
ws_ping(conn_id: string) -> boolean
```
- **conn_id**: Connection ID
- **Returns**: true on success

## WebSocket Server Functions

### ws_listen
Creates a WebSocket server.
```sentra
ws_listen(address: string, port: number) -> map
```
- **address**: IP address to bind to
- **port**: Port number
- **Returns**: Server map with id, address, port

### ws_server_accept
Accepts a new WebSocket client connection.
```sentra
ws_server_accept(server_id: string, timeout: number) -> map
```
- **server_id**: Server ID
- **timeout**: Timeout in seconds
- **Returns**: Client connection map or nil

### ws_server_wait_connection
Waits for a new connection with timeout.
```sentra
ws_server_wait_connection(server_id: string, timeout_seconds: number) -> map
```
- **server_id**: Server ID
- **timeout_seconds**: Timeout in seconds
- **Returns**: Client map with id, connected

### ws_server_broadcast
Sends a message to all connected clients.
```sentra
ws_server_broadcast(server_id: string, message: string) -> boolean
```
- **server_id**: Server ID
- **message**: Message to broadcast
- **Returns**: true on success

### ws_server_get_clients
Gets list of connected client IDs.
```sentra
ws_server_get_clients(server_id: string) -> array
```
- **server_id**: Server ID
- **Returns**: Array of client ID strings

### ws_server_send_to
Sends a message to a specific client.
```sentra
ws_server_send_to(server_id: string, client_id: string, message: string) -> boolean
```
- **server_id**: Server ID
- **client_id**: Client ID
- **message**: Message to send
- **Returns**: true on success

### ws_server_receive_from
Receives a message from a specific client.
```sentra
ws_server_receive_from(server_id: string, client_id: string) -> string
```
- **server_id**: Server ID
- **client_id**: Client ID
- **Returns**: Received message or nil

### ws_server_disconnect
Disconnects a specific client.
```sentra
ws_server_disconnect(server_id: string, client_id: string) -> boolean
```
- **server_id**: Server ID
- **client_id**: Client ID
- **Returns**: true on success

### ws_server_stop
Stops the WebSocket server.
```sentra
ws_server_stop(server_id: string) -> boolean
```
- **server_id**: Server ID
- **Returns**: true on success

## Network Security Functions

### port_scan
Scans ports on a target host.
```sentra
port_scan(host: string, start_port: number, end_port: number, scan_type: string) -> array
```
- **host**: Target hostname or IP
- **start_port**: Starting port number
- **end_port**: Ending port number
- **scan_type**: "TCP", "UDP", or "SYN"
- **Returns**: Array of scan results

### network_scan
Discovers hosts on a network.
```sentra
network_scan(subnet: string) -> array
```
- **subnet**: CIDR notation (e.g., "192.168.1.0/24")
- **Returns**: Array of discovered hosts

### dns_lookup
Performs DNS lookups.
```sentra
dns_lookup(hostname: string, record_type: string) -> array
```
- **hostname**: Domain name
- **record_type**: "A", "AAAA", "MX", "TXT", "NS", "CNAME"
- **Returns**: Array of DNS records

### analyze_traffic
Analyzes network traffic.
```sentra
analyze_traffic(interface: string, duration: number) -> map
```
- **interface**: Network interface name
- **duration**: Analysis duration in seconds
- **Returns**: Traffic analysis results

### detect_intrusions
Detects network intrusions.
```sentra
detect_intrusions(interface: string, duration: number) -> array
```
- **interface**: Network interface
- **duration**: Detection duration
- **Returns**: Array of intrusion alerts

### analyze_ssl
Analyzes SSL/TLS configuration.
```sentra
analyze_ssl(host: string, port: number) -> map
```
- **host**: Target hostname
- **port**: Port number (usually 443)
- **Returns**: SSL analysis results

### packet_capture
Captures network packets (simulated).
```sentra
packet_capture(interface: string, filter: string, count: number) -> array
```
- **interface**: Network interface
- **filter**: Packet filter
- **count**: Number of packets to capture
- **Returns**: Array of captured packets