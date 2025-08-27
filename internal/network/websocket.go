// Package network - WebSocket implementation
package network

import (
	"fmt"
	"net/http"
	"sync"
	"time"
	
	"github.com/gorilla/websocket"
)

// WebSocketConn represents a WebSocket connection
type WebSocketConn struct {
	ID         string
	URL        string
	Conn       *websocket.Conn
	IsServer   bool
	mu         sync.Mutex
	closed     bool
	messagesCh chan []byte
}

// WebSocketServer represents a WebSocket server
type WebSocketServer struct {
	ID           string
	Address      string
	Port         int
	Upgrader     websocket.Upgrader
	Handler      http.HandlerFunc
	Server       *http.Server
	Clients      map[string]*WebSocketConn
	NewClients   chan *WebSocketConn  // Channel for new connections
	mu           sync.RWMutex
}

// WebSocketMessage represents a WebSocket message
type WebSocketMessage struct {
	Type int    // 1 for text, 2 for binary
	Data []byte
}

// WebSocketConnect connects to a WebSocket server
func (n *NetworkModule) WebSocketConnect(url string) (*WebSocketConn, error) {
	dialer := websocket.DefaultDialer
	dialer.HandshakeTimeout = 10 * time.Second
	
	conn, _, err := dialer.Dial(url, nil)
	if err != nil {
		return nil, fmt.Errorf("websocket dial failed: %v", err)
	}
	
	wsConn := &WebSocketConn{
		ID:         fmt.Sprintf("ws_%d", time.Now().UnixNano()),
		URL:        url,
		Conn:       conn,
		IsServer:   false,
		messagesCh: make(chan []byte, 100),
	}
	
	// Start message reader goroutine
	go wsConn.readMessages()
	
	n.mu.Lock()
	if n.WebSockets == nil {
		n.WebSockets = make(map[string]*WebSocketConn)
	}
	n.WebSockets[wsConn.ID] = wsConn
	n.mu.Unlock()
	
	return wsConn, nil
}

// WebSocketSend sends a message over WebSocket
func (n *NetworkModule) WebSocketSend(connID string, message string) error {
	n.mu.RLock()
	conn, exists := n.WebSockets[connID]
	n.mu.RUnlock()
	
	if !exists {
		return fmt.Errorf("websocket connection %s not found", connID)
	}
	
	conn.mu.Lock()
	defer conn.mu.Unlock()
	
	if conn.closed {
		return fmt.Errorf("websocket connection is closed")
	}
	
	return conn.Conn.WriteMessage(websocket.TextMessage, []byte(message))
}

// WebSocketSendBinary sends binary data over WebSocket
func (n *NetworkModule) WebSocketSendBinary(connID string, data []byte) error {
	n.mu.RLock()
	conn, exists := n.WebSockets[connID]
	n.mu.RUnlock()
	
	if !exists {
		return fmt.Errorf("websocket connection %s not found", connID)
	}
	
	conn.mu.Lock()
	defer conn.mu.Unlock()
	
	if conn.closed {
		return fmt.Errorf("websocket connection is closed")
	}
	
	return conn.Conn.WriteMessage(websocket.BinaryMessage, data)
}

// WebSocketReceive receives a message from WebSocket
func (n *NetworkModule) WebSocketReceive(connID string, timeout time.Duration) (string, error) {
	n.mu.RLock()
	conn, exists := n.WebSockets[connID]
	n.mu.RUnlock()
	
	if !exists {
		return "", fmt.Errorf("websocket connection %s not found", connID)
	}
	
	select {
	case msg := <-conn.messagesCh:
		return string(msg), nil
	case <-time.After(timeout):
		return "", fmt.Errorf("receive timeout")
	}
}

// WebSocketClose closes a WebSocket connection
func (n *NetworkModule) WebSocketClose(connID string) error {
	n.mu.Lock()
	conn, exists := n.WebSockets[connID]
	if exists {
		delete(n.WebSockets, connID)
	}
	n.mu.Unlock()
	
	if !exists {
		return fmt.Errorf("websocket connection %s not found", connID)
	}
	
	conn.mu.Lock()
	conn.closed = true
	conn.mu.Unlock()
	
	// Send close message
	conn.Conn.WriteMessage(websocket.CloseMessage, 
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	
	return conn.Conn.Close()
}

// WebSocketPing sends a ping message
func (n *NetworkModule) WebSocketPing(connID string) error {
	n.mu.RLock()
	conn, exists := n.WebSockets[connID]
	n.mu.RUnlock()
	
	if !exists {
		return fmt.Errorf("websocket connection %s not found", connID)
	}
	
	conn.mu.Lock()
	defer conn.mu.Unlock()
	
	if conn.closed {
		return fmt.Errorf("websocket connection is closed")
	}
	
	return conn.Conn.WriteMessage(websocket.PingMessage, []byte{})
}

// readMessages continuously reads messages from the WebSocket
func (ws *WebSocketConn) readMessages() {
	defer close(ws.messagesCh)
	
	for {
		ws.mu.Lock()
		if ws.closed {
			ws.mu.Unlock()
			return
		}
		ws.mu.Unlock()
		
		messageType, message, err := ws.Conn.ReadMessage()
		if err != nil {
			ws.mu.Lock()
			ws.closed = true
			ws.mu.Unlock()
			return
		}
		
		// Only handle text and binary messages
		if messageType == websocket.TextMessage || messageType == websocket.BinaryMessage {
			select {
			case ws.messagesCh <- message:
			default:
				// Channel full, drop oldest message
				<-ws.messagesCh
				ws.messagesCh <- message
			}
		}
	}
}

// WebSocketListen creates a WebSocket server
func (n *NetworkModule) WebSocketListen(address string, port int) (*WebSocketServer, error) {
	server := &WebSocketServer{
		ID:         fmt.Sprintf("ws_server_%d", time.Now().UnixNano()),
		Address:    address,
		Port:       port,
		Clients:    make(map[string]*WebSocketConn),
		NewClients: make(chan *WebSocketConn, 100),
		Upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins for now
			},
		},
	}
	
	// Create HTTP handler for WebSocket upgrade
	server.Handler = func(w http.ResponseWriter, r *http.Request) {
		conn, err := server.Upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		
		wsConn := &WebSocketConn{
			ID:         fmt.Sprintf("ws_client_%d", time.Now().UnixNano()),
			Conn:       conn,
			IsServer:   true,
			messagesCh: make(chan []byte, 100),
		}
		
		server.mu.Lock()
		server.Clients[wsConn.ID] = wsConn
		server.mu.Unlock()
		
		// Send to new clients channel
		select {
		case server.NewClients <- wsConn:
		default:
			// Channel full, skip
		}
		
		go wsConn.readMessages()
	}
	
	// Start HTTP server in background
	server.Server = &http.Server{
		Addr:    fmt.Sprintf("%s:%d", address, port),
		Handler: server.Handler,
	}
	
	go server.Server.ListenAndServe()
	
	n.mu.Lock()
	if n.WSServers == nil {
		n.WSServers = make(map[string]*WebSocketServer)
	}
	n.WSServers[server.ID] = server
	n.mu.Unlock()
	
	return server, nil
}