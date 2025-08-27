// Package network - WebSocket server enhancements
package network

import (
	"fmt"
	"sync"
	"github.com/gorilla/websocket"
)

// WebSocketAccept waits for and accepts a new client connection
func (n *NetworkModule) WebSocketAccept(serverID string, timeout int) (*WebSocketConn, error) {
	n.mu.RLock()
	server, exists := n.WSServers[serverID]
	n.mu.RUnlock()
	
	if !exists {
		return nil, fmt.Errorf("websocket server %s not found", serverID)
	}
	
	// Check for new clients (this is a simplified approach)
	// In a real implementation, we'd use channels or callbacks
	server.mu.RLock()
	defer server.mu.RUnlock()
	
	for _, client := range server.Clients {
		if client != nil && !client.closed {
			return client, nil
		}
	}
	
	return nil, fmt.Errorf("no new connections available")
}

// WebSocketBroadcast sends a message to all connected clients
func (n *NetworkModule) WebSocketBroadcast(serverID string, message string) error {
	n.mu.RLock()
	server, exists := n.WSServers[serverID]
	n.mu.RUnlock()
	
	if !exists {
		return fmt.Errorf("websocket server %s not found", serverID)
	}
	
	server.mu.RLock()
	clients := make([]*WebSocketConn, 0, len(server.Clients))
	for _, client := range server.Clients {
		clients = append(clients, client)
	}
	server.mu.RUnlock()
	
	var lastErr error
	for _, client := range clients {
		client.mu.Lock()
		if !client.closed {
			err := client.Conn.WriteMessage(websocket.TextMessage, []byte(message))
			if err != nil {
				lastErr = err
				client.closed = true
			}
		}
		client.mu.Unlock()
	}
	
	return lastErr
}

// WebSocketGetClients returns list of connected client IDs
func (n *NetworkModule) WebSocketGetClients(serverID string) ([]string, error) {
	n.mu.RLock()
	server, exists := n.WSServers[serverID]
	n.mu.RUnlock()
	
	if !exists {
		return nil, fmt.Errorf("websocket server %s not found", serverID)
	}
	
	server.mu.RLock()
	defer server.mu.RUnlock()
	
	clientIDs := make([]string, 0, len(server.Clients))
	for id, client := range server.Clients {
		if !client.closed {
			clientIDs = append(clientIDs, id)
		}
	}
	
	return clientIDs, nil
}

// WebSocketSendToClient sends a message to a specific client
func (n *NetworkModule) WebSocketSendToClient(serverID, clientID, message string) error {
	n.mu.RLock()
	server, exists := n.WSServers[serverID]
	n.mu.RUnlock()
	
	if !exists {
		return fmt.Errorf("websocket server %s not found", serverID)
	}
	
	server.mu.RLock()
	client, exists := server.Clients[clientID]
	server.mu.RUnlock()
	
	if !exists {
		return fmt.Errorf("client %s not found", clientID)
	}
	
	client.mu.Lock()
	defer client.mu.Unlock()
	
	if client.closed {
		return fmt.Errorf("client connection is closed")
	}
	
	return client.Conn.WriteMessage(websocket.TextMessage, []byte(message))
}

// WebSocketReceiveFromClient receives a message from a specific client
func (n *NetworkModule) WebSocketReceiveFromClient(serverID, clientID string) (string, error) {
	n.mu.RLock()
	server, exists := n.WSServers[serverID]
	n.mu.RUnlock()
	
	if !exists {
		return "", fmt.Errorf("websocket server %s not found", serverID)
	}
	
	server.mu.RLock()
	client, exists := server.Clients[clientID]
	server.mu.RUnlock()
	
	if !exists {
		return "", fmt.Errorf("client %s not found", clientID)
	}
	
	select {
	case msg := <-client.messagesCh:
		return string(msg), nil
	default:
		return "", fmt.Errorf("no messages available")
	}
}

// WebSocketDisconnectClient disconnects a specific client
func (n *NetworkModule) WebSocketDisconnectClient(serverID, clientID string) error {
	n.mu.RLock()
	server, exists := n.WSServers[serverID]
	n.mu.RUnlock()
	
	if !exists {
		return fmt.Errorf("websocket server %s not found", serverID)
	}
	
	server.mu.Lock()
	client, exists := server.Clients[clientID]
	if exists {
		delete(server.Clients, clientID)
	}
	server.mu.Unlock()
	
	if !exists {
		return fmt.Errorf("client %s not found", clientID)
	}
	
	client.mu.Lock()
	client.closed = true
	client.mu.Unlock()
	
	client.Conn.WriteMessage(websocket.CloseMessage, 
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	
	return client.Conn.Close()
}

// WebSocketStopServer stops a WebSocket server
func (n *NetworkModule) WebSocketStopServer(serverID string) error {
	n.mu.Lock()
	server, exists := n.WSServers[serverID]
	if exists {
		delete(n.WSServers, serverID)
	}
	n.mu.Unlock()
	
	if !exists {
		return fmt.Errorf("websocket server %s not found", serverID)
	}
	
	// Close all client connections
	server.mu.Lock()
	for _, client := range server.Clients {
		client.mu.Lock()
		client.closed = true
		client.Conn.Close()
		client.mu.Unlock()
	}
	server.mu.Unlock()
	
	// Stop the HTTP server
	if server.Server != nil {
		return server.Server.Close()
	}
	
	return nil
}

// Enhanced connection handling with callbacks
type ConnectionHandler struct {
	OnConnect    func(clientID string)
	OnMessage    func(clientID string, message []byte)
	OnDisconnect func(clientID string)
	mu           sync.RWMutex
}

// WebSocketSetHandlers sets connection event handlers for a server
func (n *NetworkModule) WebSocketSetHandlers(serverID string, handlers *ConnectionHandler) error {
	n.mu.RLock()
	server, exists := n.WSServers[serverID]
	n.mu.RUnlock()
	
	if !exists {
		return fmt.Errorf("websocket server %s not found", serverID)
	}
	
	// Store handlers in server (would need to add handlers field to WebSocketServer)
	// For now, this is a placeholder for the enhanced implementation
	_ = server
	_ = handlers
	
	return nil
}